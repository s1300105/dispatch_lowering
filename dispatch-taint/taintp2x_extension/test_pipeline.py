"""Self-contained tests for pipeline.py (review items C1 / C4 / M2 / M3).

Run from any directory: ``python3 test_pipeline.py``. Fixtures are generated
into a temp dir at runtime — no external files, no Pysa.

  (a) K1  wall-file identity is the src_root-relative path: a ``links.manual.json``
          entry for ``pkg/prompts/base.py`` is never adopted by ``pkg/chains/base.py``
  (a2) C1 two walls on one line are told apart by ``(line, col)``: a link carrying
          ``col`` joins that wall only; a col-less link on such a line is refused
          as ambiguous (phantom) instead of landing on the last-detected wall
  (b) K2  ``WallRecord.lowered_line`` = the wall call's line in the rewritten file
  (c) C4  a wall file that DEFINES the registry it reads (langchain prompts/base.py
          defines DEFAULT_FORMATTER_MAPPING) keeps its narrowing when cand_dir is
          a byte-identical copy of the wall tree; both de-dup layers are pinned
          on their own (pipeline._extra_registry_roots twin check and
          links.index_registries content de-dup) — a fixture whose wall file only
          imports the registry cannot detect the double count; a later group on
          the same, already rewritten wall file keeps the narrowing as well.
          Caveat (review C4): a twin at the same relative path whose bytes
          DIFFER is a second definition — through a directory root as much as
          through a file root — so the registry is untrusted, never silently
          resolved to the first tree's literal
  (d) M2  ``run_plan`` statistics do not depend on the group order
  (e) M3  multi-stage / multi-group pins name cond_A lines and are translated
          through earlier insertions; a pin that is not an original line is
          refused (``unmatched_position``) instead of falling back to a call
          inside a generated block
  (e2) M3 a pin-less detect stage after a pinned stage re-detects the stage-1
          wall (bench ``stages_idempotent`` lowers it again) and still records
          every wall / link / header tag in cond_A coordinates, with
          ``lowered_line`` the wall's real line in the final text — both emit
          modes (the doc caveat in SCALE_OUT_DESIGN.md / README.md states this)
"""
import ast
import inspect
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import links as L          # noqa: E402
import pipeline            # noqa: E402

TOOLS = '''\
def tool(fn):
    return fn


@tool
def run_shell(cmd):
    return cmd


@tool
def echo(msg):
    return msg


@tool
def other(x):
    return x


REGISTRY = {"shell": run_shell, "echo": echo}
'''

# one wall: ``result = REGISTRY[name](args)`` at 10:13 (Assign -> block inserted after)
APP_ASSIGN = '''\
from {mod} import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    result = REGISTRY[name](args)
    return result
'''

# two walls in ``return`` statements (block inserted BEFORE the wall, so the
# wall itself moves): first() at 4:11, second() at 8:11
APP_TWO = '''\
from tools import REGISTRY

def first(name, args):
    return REGISTRY[name](args)


def second(name, args):
    return REGISTRY[name](args)
'''

# two walls on ONE line (review C1: litellm weights_biases.py:72 col 24/79,
# vanna base.py:1685): 5:11 and 5:28
APP_TWO_ONE_LINE = '''\
from tools import REGISTRY


def both(a, b, x, y):
    return REGISTRY[a](x) + REGISTRY[b](y)
'''

# review C4: the registry is defined IN the wall file (tools.py holds only the
# decorated defs). Scanning this file through two roots — cand_dir and the wall
# file itself — is the double binding that untrusted DEFAULT_FORMATTER_MAPPING
# in the real cond_B runs. One wall: ``result = REGISTRY[name](args)`` at 13:13
TOOLS_NO_REG = TOOLS.split("\n\nREGISTRY")[0] + "\n"
APP_SELF_REG = '''\
from tools import run_shell, echo


def llm_decide(prompt):
    return prompt, prompt


REGISTRY = {"shell": run_shell, "echo": echo}


def agent(prompt):
    name, args = llm_decide(prompt)
    result = REGISTRY[name](args)
    return result
'''

SPEC = {"tool_decorators": ["tool"], "registry_vars": ["REGISTRY"],
        "detect_subscript": False, "detect_getattr": False, "detect_higher_order": False}
GUARD = "if __ctaudit_unreachable__:"

passed = total = 0


def check(label, cond, detail=""):
    global passed, total
    total += 1
    passed += bool(cond)
    print(("PASS" if cond else "FAIL"), "-", label, ("" if cond else f"  [{detail}]"))


def write_tree(base, files):
    for rel, txt in files.items():
        p = os.path.join(base, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(txt)
    return base


def pin(at, accept=True, origin="engine", callee="REGISTRY[name]"):
    return {"at": at, "callee": callee, "accept": accept, "origin": origin}


def group(gid, files, positions, accepted=1, stages=None):
    g = {"id": gid, "wall_files": files, "accepted": accepted,
         "spec": dict(SPEC, wall_positions=positions), "walls": []}
    if stages:
        g["stages"] = [dict(SPEC, wall_positions=s) for s in stages]
    return g


def headers_between(text, start_marker, end_marker=None):
    body = text.split(start_marker, 1)[1]
    if end_marker and end_marker in body:
        body = body.split(end_marker, 1)[0]
    return body.count(GUARD)


root = tempfile.mkdtemp(prefix="pipeline_test_")
try:
    # ------------------------------------------------------------------ (a) K1
    app = APP_ASSIGN.format(mod="pkg.tools")
    src = write_tree(os.path.join(root, "a", "src"), {
        "pkg/__init__.py": "", "pkg/tools.py": TOOLS,
        "pkg/prompts/__init__.py": "", "pkg/prompts/base.py": app,
        "pkg/chains/__init__.py": "", "pkg/chains/base.py": app,
    })
    manual = {"links": [{"file": "pkg/prompts/base.py", "line": 10,
                         "target": {"cls": None, "name": "run_shell", "params": ["cmd"], "module": "pkg.tools"}}]}
    lp = os.path.join(root, "a", "links.manual.json")
    json.dump(manual, open(lp, "w"))
    walls = [os.path.join(src, "pkg/prompts/base.py"), os.path.join(src, "pkg/chains/base.py")]
    det = {"detect_subscript": True, "detect_getattr": False, "detect_higher_order": False}
    res = pipeline.run_spec(src, det, walls, links_in=lp, emit="inline", write=True)
    check("K1: wall records carry the src_root-relative POSIX path",
          sorted(w.file for w in res.walls) == ["pkg/chains/base.py", "pkg/prompts/base.py"],
          str([w.file for w in res.walls]))
    lowered = [l for l in res.links if l.status == "lowered"]
    check("K1: the manual link is adopted once, by pkg/prompts/base.py only",
          res.stats.links_lowered == 1 and len(lowered) == 1 and lowered[0].file == "pkg/prompts/base.py",
          f"lowered={res.stats.links_lowered} files={[l.file for l in lowered]}")
    prompts_txt = open(walls[0]).read()
    chains_txt = open(walls[1]).read()
    check("K1: prompts/base.py lowered, chains/base.py (same basename) untouched",
          "run_shell(args)" in prompts_txt and chains_txt == app)
    if "src_root" in inspect.signature(L.build_links).parameters:
        check("K1: the guard header names the wall by its relative path and cond_A line",
              "| wall=pkg/prompts/base.py:10" in prompts_txt,
              [t for t in prompts_txt.splitlines() if GUARD in t])
    else:
        print("SKIP - K1 header: links.build_links has no 'src_root' yet (agent A); the header keeps the basename until then")
    chains_wall = next(w for w in res.walls if w.file == "pkg/chains/base.py")
    check("K1: the same-basename wall stays unresolved (no link supplied)",
          chains_wall.status == "unresolved", chains_wall.status)
    out_json = os.path.join(root, "a", "links.json")
    pipeline.write_links(out_json, res)
    data = json.load(open(out_json))
    check("K1: links.json 'file' keys are relative paths",
          data["links"][0]["file"] == "pkg/prompts/base.py"
          and sorted(w["file"] for w in data["walls"]) == ["pkg/chains/base.py", "pkg/prompts/base.py"])
    if "extra" in inspect.signature(L.dump_links).parameters:
        check("K4: links.json carries tool_version", isinstance(data.get("tool_version"), dict)
              and data["tool_version"].get("combined"))
    else:
        print("SKIP - K4: links.dump_links has no 'extra' yet (agent A); write_links drops it until then")
    # a bare basename matches NOTHING (it would name both files)
    src2 = write_tree(os.path.join(root, "a2", "src"), {
        "pkg/__init__.py": "", "pkg/tools.py": TOOLS,
        "pkg/prompts/__init__.py": "", "pkg/prompts/base.py": app,
        "pkg/chains/__init__.py": "", "pkg/chains/base.py": app,
    })
    lp2 = os.path.join(root, "a2", "links.manual.json")
    json.dump({"links": [dict(manual["links"][0], file="base.py")]}, open(lp2, "w"))
    walls2 = [os.path.join(src2, "pkg/prompts/base.py"), os.path.join(src2, "pkg/chains/base.py")]
    res2 = pipeline.run_spec(src2, det, walls2, links_in=lp2, emit="inline", write=True)
    check("K1: a bare-basename entry ('base.py') is adopted by neither file",
          res2.stats.links_lowered == 0 and all(open(p).read() == app for p in walls2),
          f"lowered={res2.stats.links_lowered}")
    # ``file`` omitted = every wall file
    lp3 = os.path.join(root, "a2", "links.any.json")
    json.dump({"links": [{k: v for k, v in manual["links"][0].items() if k != "file"}]}, open(lp3, "w"))
    res3 = pipeline.run_spec(src2, det, walls2, links_in=lp3, emit="inline", write=True)
    check("K1: an entry without 'file' applies to every wall file",
          res3.stats.links_lowered == 2 and sorted(l.file for l in res3.links if l.status == "lowered")
          == ["pkg/chains/base.py", "pkg/prompts/base.py"], f"lowered={res3.stats.links_lowered}")

    # ------------------------------------------------------------ (a2) C1 col
    src4 = write_tree(os.path.join(root, "a4", "src"), {"tools.py": TOOLS, "app.py": APP_TWO_ONE_LINE})
    det4 = {"detect_subscript": True, "detect_getattr": False, "detect_higher_order": False}
    wall4 = os.path.join(src4, "app.py")
    res4 = pipeline.run_spec(src4, det4, [wall4], emit="inline", write=False)
    cols = sorted(w.col for w in res4.walls)
    check("C1 col: two walls detected on one line with distinct columns",
          [w.line for w in res4.walls] == [5, 5] and len(set(cols)) == 2, str([(w.line, w.col) for w in res4.walls]))
    lp4 = os.path.join(root, "a4", "links.manual.json")
    json.dump({"links": [
        {"file": "app.py", "line": 5, "col": cols[1],
         "target": {"cls": None, "name": "run_shell", "params": ["cmd"], "module": "tools"}},
        {"file": "app.py", "line": 5,
         "target": {"cls": None, "name": "echo", "params": ["msg"], "module": "tools"}}]}, open(lp4, "w"))
    res4 = pipeline.run_spec(src4, det4, [wall4], links_in=lp4, emit="inline", write=True)
    low4 = [l for l in res4.links if l.status == "lowered"]
    ph4 = [l for l in res4.links if l.status == "phantom"]
    check("C1 col: the link carrying col is adopted by the wall at that column only",
          len(low4) == 1 and low4[0].col == cols[1]
          and next(w for w in res4.walls if w.col == cols[1]).status == "resolved"
          and next(w for w in res4.walls if w.col == cols[0]).status == "unresolved",
          str([(l.status, l.col, l.wall_id) for l in res4.links]))
    check("C1 col: a col-less link on a two-wall line is refused as ambiguous (phantom), not joined to the last wall",
          len(ph4) == 1 and "ambiguous wall line app.py:5" in ph4[0].reason and res4.stats.links_phantom == 1
          and res4.stats.links_lowered == 1, str([(l.status, l.reason) for l in ph4]))
    out4 = os.path.join(root, "a4", "links.json")
    pipeline.write_links(out4, res4)
    check("C1 col: links.json round-trips the link's col",
          [l.col for l in L.load_links(out4)[1] if l.status == "lowered"] == [cols[1]])

    # ------------------------------------------------------------------ (b) K2
    src = write_tree(os.path.join(root, "b", "src"), {"tools.py": TOOLS, "app.py": APP_TWO})
    plan = {"groups": [group("G0", ["app.py"], [pin("app.py:4:11")])]}
    res = pipeline.run_plan(src, plan, cand_dir=src, emit="inline", write=True)
    txt = open(os.path.join(src, "app.py")).read()
    w = res.walls[0]
    check("K2: block before a `return` wall moves it: line 4 -> lowered_line 8",
          (w.line, getattr(w, "lowered_line", 0)) == (4, 8) and "REGISTRY[name](args)" in txt.splitlines()[7],
          f"line={w.line} lowered_line={getattr(w, 'lowered_line', 0)}")
    check("K2: link lowered_line points at the inserted call",
          all(l.target.name in txt.splitlines()[l.lowered_line - 1] for l in res.links if l.status == "lowered"))
    src = write_tree(os.path.join(root, "b2", "src"), {"tools.py": TOOLS, "app.py": APP_ASSIGN.format(mod="tools")})
    res = pipeline.run_plan(src, {"groups": [group("G0", ["app.py"], [pin("app.py:10:13")])]},
                            cand_dir=src, emit="inline", write=True)
    w = res.walls[0]
    check("K2: block after an Assign wall leaves it in place: lowered_line == line == 10",
          (w.line, getattr(w, "lowered_line", 0)) == (10, 10), f"{w.line}/{getattr(w, 'lowered_line', 0)}")
    check("K2: a wall without a lowered link keeps lowered_line 0",
          getattr(pipeline.run_plan(
              write_tree(os.path.join(root, "b3", "src"), {"tools.py": TOOLS, "app.py": APP_ASSIGN.format(mod="tools")}),
              {"groups": [group("G0", ["app.py"], [pin("app.py:10:13", accept=False)], accepted=0)]},
              cand_dir=None or os.path.join(root, "b3", "src"), emit="inline", write=True).walls[0], "lowered_line", 0) == 0)

    # ------------------------------------------------------------------ (c) C4
    # The wall file defines REGISTRY itself. Before the fix, the lowering stage
    # scanned cand_dir (TARGET_SRC) plus the wall file (cond_B/src/...): the one
    # dict literal was seen through two realpaths -> bindings == 2 -> untrusted
    # -> no narrowing (langchain-0.0.131 prompts/base.py: dry run 1 lowered / 90
    # filtered_registry, real cond_B 91 lowered). Expected with narrowing:
    # run_shell + echo lowered, ``other`` filtered_registry.
    files = {"tools.py": TOOLS_NO_REG, "app.py": APP_SELF_REG}
    plan = {"groups": [group("G0", ["app.py"], [pin("app.py:13:13")])]}
    REG_MEMBERS = frozenset({"shell", "echo", "run_shell"})
    src = write_tree(os.path.join(root, "c1", "src"), files)
    res = pipeline.run_plan(src, plan, cand_dir=src, emit="inline", write=True)
    base_counts = (res.stats.links_lowered, res.stats.links_filtered_registry)
    check("C4: cand_dir == wall tree: REGISTRY (defined in the wall file) trusted, 2 lowered / 1 filtered_registry",
          base_counts == (2, 1), str(base_counts))
    src = write_tree(os.path.join(root, "c2", "src"), files)
    cand = shutil.copytree(src, os.path.join(root, "c2", "cand"))       # byte-identical copy (TARGET_SRC vs cond_B/src)
    wall = os.path.join(src, "app.py")
    # layer 1 (pipeline): an identical twin under cand_dir means the wall file is NOT an extra root
    check("C4 [pipeline]: a wall file with a byte-identical twin under cand_dir is not an extra registry root",
          pipeline._extra_registry_roots(cand, [wall], src) == (),
          str(pipeline._extra_registry_roots(cand, [wall], src)))
    # layer 2 (links): even when it IS passed as a second root, the copy counts once
    check("C4 [links]: index_registries([cand, copy-of-wall-file]) == index_registries([cand]) (content de-dup)",
          L.index_registries([cand, wall]) == L.index_registries([cand])
          and L.index_registries([cand, wall]).get("REGISTRY") == REG_MEMBERS,
          f"{dict(L.index_registries([cand, wall]))} vs {dict(L.index_registries([cand]))}")
    check("C4 [links]: index_registries([cand, copy-of-tree]) keeps REGISTRY trusted (content de-dup of the identical twin)",
          L.index_registries([cand, src]).get("REGISTRY") == REG_MEMBERS, str(dict(L.index_registries([cand, src]))))
    # end to end: cand_dir = the copy, wall tree = src
    prov = pipeline.AutoLinksProvider(cand, SPEC, [wall], src_root=src)
    check("C4: AutoLinksProvider(cand_dir=copy) trusts the wall file's registry",
          prov.registry_index().get("REGISTRY") == REG_MEMBERS
          and prov.describe()["trusted_registries"].get("REGISTRY") == sorted(REG_MEMBERS),
          str(prov.registry_index()))
    res = pipeline.run_plan(src, plan, cand_dir=cand, emit="inline", write=True)
    txt = open(wall).read()
    check("C4: cand_dir = a copy of the wall tree keeps the narrowing: same 2 lowered / 1 filtered_registry",
          (res.stats.links_lowered, res.stats.links_filtered_registry) == base_counts,
          f"{(res.stats.links_lowered, res.stats.links_filtered_registry)}; a failure here means the same dict "
          "literal was indexed through two roots (bindings == 2 -> untrusted -> no narrowing)")
    check("C4: the non-member 'other' is filtered_registry, not lowered into the wall file",
          "run_shell(args)" in txt and "echo(args)" in txt and "other(args)" not in txt
          and [l.target.name for l in res.links if l.status == "filtered_registry"] == ["other"],
          str([(l.status, l.target.name) for l in res.links]))
    # a wall file whose twin DIFFERS (or is missing) is still indexed on its own,
    # and a genuinely different registry revision through two roots still untrusts
    open(wall, "w").write(APP_SELF_REG.replace('"echo": echo}', '"echo": echo, "other": other}'))
    check("C4 [pipeline]: a wall file that differs from its twin is indexed as an extra root",
          pipeline._extra_registry_roots(cand, [wall], src) == (os.path.realpath(wall),)
          and pipeline._extra_registry_roots(cand, [os.path.join(cand, "app.py")], src) == ())
    check("C4 [links]: a different definition of the registry through two roots is untrusted (no narrowing)",
          "REGISTRY" not in L.index_registries([cand, wall]) and "REGISTRY" in L.index_registries([cand]))
    # review C4 caveat: the same must hold when the differing twin is reached
    # through a DIRECTORY root (src/app.py vs cand/app.py: same relative path,
    # other bytes). De-duplicating on the relative path alone silently kept the
    # FIRST tree's literal and trusted it ({shell, echo} or {shell, echo, other}
    # depending on root order); both definitions have to be indexed so the name
    # gets two bindings. A byte-identical twin still counts once.
    check("C4 [links]: a differing twin at the same relative path under two DIRECTORY roots is untrusted (either order)",
          "REGISTRY" not in L.index_registries([cand, src]) and "REGISTRY" not in L.index_registries([src, cand]),
          f"[cand, src] -> {dict(L.index_registries([cand, src]))}; [src, cand] -> {dict(L.index_registries([src, cand]))}")
    cand_same = shutil.copytree(src, os.path.join(root, "c2", "cand_same"))   # identical to the MUTATED src
    check("C4 [links]: an identical twin at the same relative path still counts once (trusted, members of the new literal)",
          L.index_registries([cand_same, src]).get("REGISTRY") == REG_MEMBERS | {"other"}
          and L.index_registries([src, cand_same]) == L.index_registries([src]),
          f"{dict(L.index_registries([cand_same, src]))}")
    # a second group / stage on the SAME wall file sees it already rewritten by
    # the first one: it no longer byte-matches its twin, but its registry is
    # still the one literal — the twin is compared against the pre-rewrite
    # snapshot (``originals``), so later groups keep the narrowing too
    files2 = {"tools.py": TOOLS_NO_REG, "app.py": APP_SELF_REG + "\n\ndef agent2(prompt):\n"
              "    name, args = llm_decide(prompt)\n    return REGISTRY[name](args)\n"}
    plan2 = {"groups": [group("G0", ["app.py"], [pin("app.py:13:13")]),
                        group("G1", ["app.py"], [pin("app.py:19:11", origin="review")])]}
    src = write_tree(os.path.join(root, "c3", "src"), files2)
    cand = shutil.copytree(src, os.path.join(root, "c3", "cand"))
    res = pipeline.run_plan(src, plan2, cand_dir=cand, emit="inline", write=True)
    check("C4: a later group on an already rewritten wall file (cand_dir = copy) keeps the narrowing: 4 lowered / 2 filtered_registry",
          (res.stats.links_lowered, res.stats.links_filtered_registry) == (4, 2)
          and [w.registry for w in res.walls] == ["REGISTRY", "REGISTRY"]
          and sorted(l.wall_id for l in res.links if l.status == "filtered_registry") == ["G0W0", "G1W0"],
          f"{(res.stats.links_lowered, res.stats.links_filtered_registry)} {[(l.wall_id, l.status, l.target.name) for l in res.links]}")
    wall = os.path.join(src, "app.py")
    check("C4 [pipeline]: the twin check compares against the pre-rewrite snapshot, not the rewritten file",
          pipeline._extra_registry_roots(cand, [wall], src) == (os.path.realpath(wall),)      # on disk: rewritten != twin
          and pipeline._extra_registry_roots(cand, [wall], src, {os.path.abspath(wall): files2["app.py"]}) == ())

    # ------------------------------------------------------------------ (d) M2
    files = {"tools.py": TOOLS, "a.py": APP_ASSIGN.format(mod="tools"), "b.py": APP_ASSIGN.format(mod="tools")}
    g_unmatched = group("GA", ["a.py"], [pin("a.py:99:4", origin="review")])             # no call at line 99
    g_rejected = group("GB", ["b.py"], [pin("b.py:10:13", accept=False)], accepted=0)    # rejected_by_review
    for label, groups in (("unmatched first", [g_unmatched, g_rejected]), ("rejected first", [g_rejected, g_unmatched])):
        src = write_tree(os.path.join(root, "d_" + label.replace(" ", "_"), "src"), files)
        res = pipeline.run_plan(src, {"groups": groups}, cand_dir=src, emit="inline", write=True)
        s = res.stats
        check(f"M2 ({label}): walls_unmatched 1, walls_rejected 1, by_origin engine 1 / review 1",
              (s.walls_unmatched, s.walls_rejected, s.walls_by_origin, s.walls_detected, s.links_lowered)
              == (1, 1, {"engine": 1, "review": 1}, 1, 0),
              f"unmatched={s.walls_unmatched} rejected={s.walls_rejected} by_origin={s.walls_by_origin}")
    check("M2: LoweringStats().merge(x) == x",
          L.LoweringStats().merge(L.LoweringStats(walls_unmatched=1, walls_by_origin={"review": 1}))
          == L.LoweringStats(walls_unmatched=1, walls_by_origin={"review": 1}))

    # ------------------------------------------------------------------ (e) M3
    files = {"tools.py": TOOLS, "app.py": APP_TWO}
    src = write_tree(os.path.join(root, "e1", "src"), files)
    plan = {"groups": [group("G0", ["app.py"], [pin("app.py:4:11")],
                             stages=[[pin("app.py:8:11", origin="review")]])]}
    res = pipeline.run_plan(src, plan, cand_dir=src, emit="inline", write=True)
    txt = open(os.path.join(src, "app.py")).read()
    ast.parse(txt)
    check("M3 (stages): first() lowered once, second() lowered once",
          txt.count(GUARD) == 2 and headers_between(txt, "def first", "def second") == 1
          and headers_between(txt, "def second") == 1, f"headers={txt.count(GUARD)}")
    check("M3 (stages): records stay in cond_A coordinates (lines 4 and 8), no unmatched pin",
          sorted((w.id, w.line) for w in res.walls) == [("G0S0W0", 4), ("G0S1W0", 8)]
          and res.stats.walls_unmatched == 0 and res.stats.links_lowered == 4,
          f"{[(w.id, w.line, w.status) for w in res.walls]} unmatched={res.stats.walls_unmatched}")
    check("M3 (stages): header tags carry the cond_A line of each wall",
          "| wall=app.py:4" in txt and "| wall=app.py:8" in txt and "| wall=app.py:12" not in txt)
    ll = {w.id: getattr(w, "lowered_line", 0) for w in res.walls}
    # stage 1's block is 4 lines (header, import, 2 calls) so first() moves 4 -> 8;
    # stage 2's block needs no import (the names are bound by stage 1's block)
    wall_lines = [i + 1 for i, t in enumerate(txt.splitlines()) if "return REGISTRY[name](args)" in t]
    check("M3 (stages): lowered_line is each wall's line in the final text",
          ll == {"G0S0W0": wall_lines[0], "G0S1W0": wall_lines[1]} and wall_lines[0] == 8 and wall_lines[1] > 12,
          f"{ll} vs text {wall_lines}")
    check("M3 (stages): every link's lowered_line points at its inserted call",
          all(l.target.name in txt.splitlines()[l.lowered_line - 1] for l in res.links if l.status == "lowered"))
    check("M3 (stages): link lines are cond_A lines too",
          sorted({l.line for l in res.links}) == [4, 8], str(sorted({l.line for l in res.links})))
    # the same two hops as two GROUPS on one file (run_plan's own snapshot)
    src = write_tree(os.path.join(root, "e2", "src"), files)
    plan = {"groups": [group("G0", ["app.py"], [pin("app.py:4:11")]),
                       group("G1", ["app.py"], [pin("app.py:8:11", origin="review")])]}
    res = pipeline.run_plan(src, plan, cand_dir=src, emit="inline", write=True)
    txt = open(os.path.join(src, "app.py")).read()
    check("M3 (groups): a second group on an already rewritten file is remapped the same way",
          txt.count(GUARD) == 2 and headers_between(txt, "def first", "def second") == 1
          and sorted((w.id, w.line) for w in res.walls) == [("G0W0", 4), ("G1W0", 8)]
          and res.stats.links_lowered == 4, f"{[(w.id, w.line) for w in res.walls]} headers={txt.count(GUARD)}")
    # a pin that is not an original line (12 = second()'s line AFTER stage 1)
    # is refused rather than matched against the rewritten text
    src = write_tree(os.path.join(root, "e3", "src"), files)
    plan = {"groups": [group("G0", ["app.py"], [pin("app.py:4:11")],
                             stages=[[pin("app.py:12:11", origin="review")]])]}
    res = pipeline.run_plan(src, plan, cand_dir=src, emit="inline", write=True)
    txt = open(os.path.join(src, "app.py")).read()
    um = [w for w in res.walls if w.status == "unmatched_position"]
    check("M3 (stale pin): a line that is not an original line becomes unmatched_position",
          res.stats.walls_unmatched == 1 and len(um) == 1 and um[0].origin == "review"
          and "app.py:12:11" in um[0].reason and txt.count(GUARD) == 1 and headers_between(txt, "def second") == 0,
          f"unmatched={res.stats.walls_unmatched} headers={txt.count(GUARD)}")
    # reject_walls pins are translated the same way
    src = write_tree(os.path.join(root, "e4", "src"), files)
    plan = {"groups": [{"id": "G0", "wall_files": ["app.py"], "accepted": 1, "walls": [],
                        "spec": dict(SPEC, wall_positions=[pin("app.py:4:11")]),
                        "stages": [dict(SPEC, detect_subscript=True, reject_walls=["app.py:8:11"])]}]}
    res = pipeline.run_plan(src, plan, cand_dir=src, emit="inline", write=True)
    txt = open(os.path.join(src, "app.py")).read()
    rej = [w for w in res.walls if w.status == "rejected_by_review"]
    check("M3 (reject_walls): a rejected cond_A position is honoured after the file moved",
          len(rej) == 1 and rej[0].line == 8 and headers_between(txt, "def second") == 0,
          f"rejected={[(w.id, w.line) for w in rej]} headers={txt.count(GUARD)}")
    # (e2) a pin-less detect stage after the pinned stage: it re-detects first()'s
    # wall (now at post-stage line 8) and second()'s (post-stage 12) — both are
    # recorded at their cond_A lines 4 / 8, the header tags too, and the wall's
    # lowered_line is its real line in the final text (before the fix the
    # re-detected wall was recorded at line 8 with lowered_line = second()'s)
    for emit in ("inline", "redirector"):
        src = write_tree(os.path.join(root, f"e5_{emit}", "src"), files)
        plan = {"groups": [{"id": "G0", "wall_files": ["app.py"], "accepted": 1, "walls": [],
                            "spec": dict(SPEC, wall_positions=[pin("app.py:4:11")]),
                            "stages": [dict(SPEC, detect_subscript=True)]}]}
        res = pipeline.run_plan(src, plan, cand_dir=src, emit=emit, write=True)
        txt = open(os.path.join(src, "app.py")).read()
        ast.parse(txt)
        wall_lines = [i + 1 for i, t in enumerate(txt.splitlines()) if "return REGISTRY[name](args)" in t]
        recs = sorted((w.id, w.line, getattr(w, "lowered_line", 0)) for w in res.walls)
        check(f"M3 (detect stage, {emit}): stage 2 re-lowers first() and lowers second(), no unmatched pin",
              txt.count(GUARD) == 3 and headers_between(txt, "def first", "def second") == 2
              and headers_between(txt, "def second") == 1 and res.stats.walls_unmatched == 0
              and res.stats.links_lowered == 6, f"headers={txt.count(GUARD)} stats={res.stats}")
        check(f"M3 (detect stage, {emit}): re-detected walls are recorded at cond_A lines with the real lowered_line",
              recs == [("G0S0W0", 4, wall_lines[0]), ("G0S1W0", 4, wall_lines[0]), ("G0S1W1", 8, wall_lines[1])],
              f"{recs} vs text {wall_lines}")
        check(f"M3 (detect stage, {emit}): header tags of the detect stage carry cond_A lines",
              txt.count("| wall=app.py:4") == 2 and txt.count("| wall=app.py:8") == 1
              and "| wall=app.py:12" not in txt, str([t for t in txt.splitlines() if GUARD in t]))
        check(f"M3 (detect stage, {emit}): link lines are cond_A lines, lowered_line points at the inserted call",
              sorted({l.line for l in res.links}) == [4, 8]
              and all(l.target.name in txt.splitlines()[l.lowered_line - 1] for l in res.links if l.status == "lowered"),
              str([(l.id, l.line, l.lowered_line) for l in res.links]))
    # unit: the line map around an insertion
    lm = pipeline._line_map("a\nb\nc\nd\n", "a\nb\nX1\n    X2\nc\nd\n")
    check("M3: _line_map skips inserted lines", lm == {1: 1, 2: 2, 3: 5, 4: 6}, str(lm))
    check("M3: _line_map of an unchanged file is the identity",
          pipeline._line_map("a\nb\n", "a\nb\n") == {1: 1, 2: 2})
finally:
    shutil.rmtree(root, ignore_errors=True)

print(f"\n{passed}/{total} passed")
sys.exit(0 if passed == total else 1)
