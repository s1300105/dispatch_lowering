"""Run the wall-idiom micro-benchmark (see fixtures.py).

    python3 run_bench.py                # AST-level checks, both emit modes (fast)
    python3 run_bench.py --pyre         # additionally run Pysa on each cond_B (slow)
    python3 run_bench.py --engine       # --pyre + check what engine_walls.py reads off cond_A
                                        #   against the fixture's ``engine`` expectation
    python3 run_bench.py --only subscript boolop
    python3 run_bench.py --keep         # keep the temp trees for inspection

--pyre needs the TaintP2X taint defs/stubs and a typeshed; set TP2X and TYPESHED
(defaults follow run_ablation.sh) and activate the venv that provides ``pyre``.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXT = os.path.dirname(HERE)
if EXT not in sys.path:
    sys.path.insert(0, EXT)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import pipeline                      # noqa: E402
import engine_walls                  # noqa: E402
from fixtures import FIXTURES, MODELS  # noqa: E402

ROOT = os.path.abspath(os.path.join(EXT, "..", ".."))
RECORD = False
TP2X = os.environ.get("TP2X", os.path.join(ROOT, "TaintP2X", "Taint_Propagation"))
TYPESHED = os.environ.get("TYPESHED", os.path.join(ROOT, ".venv", "lib", "pyre_check", "typeshed"))


def materialise(name: str, fx: dict, base: str) -> str:
    d = os.path.join(base, name, "src")
    os.makedirs(d, exist_ok=True)
    for rel, txt in fx["files"].items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(txt)
    return d


def run_pyre(cond_dir: str) -> int:
    """Issue count Pysa reports for the tree at ``cond_dir/src``. Raises
    RuntimeError when pyre is not on PATH, so a missing venv is a clear failure
    rather than a silent zero."""
    cfg = {
        "source_directories": [os.path.join(cond_dir, "src")],
        "taint_models_path": [os.path.join(TP2X, "taint"), os.path.join(cond_dir, "models")],
        "search_path": [os.path.join(TP2X, "stubs")],
        "typeshed": TYPESHED,
        "strict": False,
    }
    json.dump(cfg, open(os.path.join(cond_dir, ".pyre_configuration"), "w"), indent=2)
    os.makedirs(os.path.join(cond_dir, "models"), exist_ok=True)
    open(os.path.join(cond_dir, "models", "bench.pysa"), "w").write(MODELS)
    try:
        subprocess.run(["pyre", "analyze", "--no-verify", "--save-results-to", "./r"],
                       cwd=cond_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        raise RuntimeError("pyre not found on PATH — activate the venv for --pyre")
    n, reached = 0, set()
    out = os.path.join(cond_dir, "r", "taint-output.json")
    if os.path.exists(out):
        for line in open(out):
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            if o.get("kind") != "issue":
                continue
            n += 1
            # the sink callee = first hop of the backward trace (what the wall
            # resolution made reachable), independent of how many rule kinds fire
            for tr in o.get("data", {}).get("traces", []):
                if tr.get("name") != "backward":
                    continue
                for r in tr.get("roots", []):
                    for callee in (r.get("call") or {}).get("resolves_to") or []:
                        reached.add(callee)
    return n, reached


def _rel(path: str, src: str) -> str:
    """Wall-file key relative to the fixture's ``src`` root (review C1 / K1:
    ``WallRecord.file`` is relative to the source root). An absolute path — a
    pipeline that does not hand ``src_root`` to ``build_links`` — is
    normalised the same way, so the comparison never depends on it."""
    if os.path.isabs(path):
        try:
            return os.path.relpath(path, src).replace(os.sep, "/")
        except ValueError:
            return path
    return path.replace(os.sep, "/")


def check_engine(fx: dict, cond_a: str, walls, src: str) -> list:
    """The engine-side view of the fixture's AST walls (gate 0 of the scale-out
    design): ``engine.status`` is what ``engine_walls.scan`` must report at
    every AST-detected wall line, ``engine.accept`` the pre-set review flag.
    ``status == "resolved"`` means the engine sees no wall there at all — the
    draft must not list it. ``engine`` is one dict for every wall, or a dict
    keyed by line (``"15": {...}``) when the walls differ — a detected wall
    line missing from the per-line dict FAILS the fixture (review minor: it
    used to fall back to the outer dict and die with a KeyError)."""
    exp_all = fx.get("engine")
    if not exp_all:
        return []
    fails = []
    res = engine_walls.scan(cond_a)
    per_line = "status" not in exp_all
    for w in walls:
        rel = _rel(w.file, src)
        if per_line:
            exp = exp_all.get(str(w.line))
            if exp is None:
                fails.append(f"engine: {rel}:{w.line} is a detected wall but the per-line 'engine' dict "
                             f"has no entry for line {w.line} (keys {sorted(exp_all)})")
                continue
        else:
            exp = exp_all
        st = res.status_at(rel, w.line)
        got = st["status"] if st else None
        if got != exp["status"]:
            fails.append(f"engine: {rel}:{w.line} expected {exp['status']!r}, engine says {got!r}")
            continue
        rows = [e for e in res.walls if e.file == rel and e.line == w.line]
        want = exp.get("accept", True)
        if exp["status"] == "resolved" or want is None:
            # the engine resolves it, or it is an environment gap: the draft must not list it
            if rows:
                fails.append(f"engine: {rel}:{w.line} not a wall for the engine but drafted as {rows[0].engine_status}")
        elif not rows:
            fails.append(f"engine: {rel}:{w.line} has no engine wall row")
        elif rows[0].accept != want:
            fails.append(f"engine: {rel}:{w.line} accept={rows[0].accept}, expected {want} ({rows[0].note})")
    return fails


def dump_evidence(res, src: str) -> None:
    """``links.json`` / ``stats.json`` next to the cond_B tree (the pipeline's
    own artifacts, wall files keyed relative to ``src``) — what
    ``engine_walls.py extract`` copies into an ``r_min`` excerpt."""
    import copy
    import links as L
    walls, links = [], []
    for w in res.walls:
        w = copy.copy(w)
        w.file = _rel(w.file, src)
        walls.append(w)
    for l in res.links:
        l = copy.copy(l)
        l.file = _rel(l.file, src)
        links.append(l)
    cond_b = os.path.dirname(src)
    L.dump_links(os.path.join(cond_b, "links.json"), walls, links, res.stats)
    json.dump(res.stats.to_dict(), open(os.path.join(cond_b, "stats.json"), "w"), indent=2)


def check(name: str, fx: dict, base: str, emit: str, with_pyre: bool, with_engine: bool = False) -> list:
    fails = []
    src = materialise(name, fx, os.path.join(base, emit))
    walls = [os.path.join(src, w) for w in fx["walls"]]
    links_in = os.path.join(src, fx["links_in"]) if fx.get("links_in") else ""
    res = pipeline.run_spec(src, fx["spec"], walls, cand_dir=src, links_in=links_in, emit=emit, write=True)
    dump_evidence(res, src)
    s = res.stats
    e = dict(fx["expect"])
    e.update((fx.get("expect_per_emit") or {}).get(emit, {}))
    for key, attr in (("walls", "walls_detected"), ("lowered", "links_lowered"),
                      ("filtered_registry", "links_filtered_registry"),
                      ("filtered_level", "links_filtered_level"),
                      ("phantom", "links_phantom"),
                      ("rejected", "walls_rejected"),
                      ("unreasonable", "links_unreasonable")):
        if key in e and getattr(s, attr) != e[key]:
            fails.append(f"{key}: expected {e[key]}, got {getattr(s, attr)}")
    lowered = open(walls[0]).read()
    try:
        ast.parse(lowered)
    except SyntaxError as ex:
        fails.append(f"lowered file does not parse: {ex}")
    # substrings are matched against text whose wall-file paths are relative to
    # ``src`` (``wall=app.py:10``, K1); an absolute ``src`` prefix left by a
    # pipeline that does not pass ``src_root`` is stripped, never asserted on
    lowered = lowered.replace(src + os.sep, "")
    if emit == "inline":
        for sub in e.get("contains", []):
            if sub not in lowered:
                fails.append(f"missing {sub!r}")
        for sub in e.get("not_contains", []):
            if sub in lowered:
                fails.append(f"unexpected {sub!r}")
    else:
        rm = os.path.join(src, "__ctaudit_redirect.py")
        if s.links_lowered and not os.path.exists(rm):
            fails.append("redirect module not written")
        rtext = open(rm).read() if os.path.exists(rm) else ""
        if rtext:
            try:
                ast.parse(rtext)
            except SyntaxError as ex:
                fails.append(f"redirect module does not parse: {ex}")
        for sub in e.get("redirect_contains", []):
            if sub not in rtext:
                fails.append(f"redirect module missing {sub!r}")
        for sub in e.get("not_contains", []):
            if sub in rtext:
                fails.append(f"redirect module unexpectedly contains {sub!r}")
    if e.get("before_wall"):
        lines = lowered.splitlines()
        i_block = next((i for i, l in enumerate(lines) if "__ctaudit_unreachable__" in l), -1)
        i_wall = next((i for i, l in enumerate(lines) if e["before_wall"] in l), -1)
        if not (0 <= i_block < i_wall):
            fails.append(f"block not placed before {e['before_wall']!r}")
    if e.get("before_return"):
        lines = lowered.splitlines()
        i_block = next((i for i, l in enumerate(lines) if "__ctaudit_unreachable__" in l), -1)
        i_ret = next((i for i, l in enumerate(lines) if l.strip().startswith("return REGISTRY")), -1)
        if not (0 <= i_block < i_ret):
            fails.append("block not placed before the return statement")
    if e.get("chain_intact"):
        # the original if/elif/else chain must still be one statement
        tree = ast.parse(lowered)
        chains = [n for n in ast.walk(tree)
                  if isinstance(n, ast.If) and not (isinstance(n.test, ast.Name)
                                                    and n.test.id == "__ctaudit_unreachable__")]
        if not any(c.orelse for c in chains):
            fails.append("if/elif/else chain was re-parented to the inserted guard")
    if "block_count" in e:
        n = lowered.count("if __ctaudit_unreachable__:")
        if n != e["block_count"]:
            fails.append(f"block_count: expected {e['block_count']}, got {n}")
    # every lowered link must point at a real line containing its call
    for l in res.links:
        if l.status == "lowered" and l.lowered_line:
            line = lowered.splitlines()[l.lowered_line - 1]
            probe = l.redirector or l.target.name
            if probe not in line:
                fails.append(f"{l.id}: lowered_line {l.lowered_line} does not contain {probe!r}: {line.strip()!r}")
    if with_pyre and "reaches" in e:
        cond_b = os.path.dirname(src)
        # cond_A: the same tree WITHOUT lowering. It must report 0, or the
        # fixture's wall does not actually block Pysa and proves nothing.
        base_a = os.path.join(os.path.dirname(os.path.dirname(cond_b)),
                              os.path.basename(os.path.dirname(cond_b)) + "_A")
        materialise(name, fx, base_a)
        cond_a = os.path.join(base_a, name)
        try:
            a, _ = run_pyre(cond_a)
            b, reached = run_pyre(cond_b)
        except RuntimeError as ex:
            fails.append(str(ex))
            return fails
        if e.get("cond_a_nonzero"):
            if a == 0:
                fails.append("pyre cond_A: expected > 0 (the engine resolves this AST wall by itself), got 0")
        elif a != 0:
            fails.append(f"pyre cond_A: expected 0 (the wall must block Pysa), got {a}")
        if b == 0:
            fails.append("pyre cond_B: 0 issues — the lowering did not connect the wall")
        if with_engine:
            fails += check_engine(fx, cond_a, res.walls, src)
        if RECORD:
            er = engine_walls.scan(cond_a)
            for w in res.walls:
                rel = _rel(w.file, src)
                st = er.status_at(rel, w.line)
                rows = [x for x in er.walls if x.file == rel and x.line == w.line]
                print(f"RECORD {name} {rel}:{w.line} status={st['status'] if st else None} "
                      f"accept={rows[0].accept if rows else None} idiom={rows[0].idiom if rows else '-'} "
                      f"note={rows[0].note if rows else ''}")
            # every other engine site of the wall files (a second, undetected
            # wall such as a stub call below the lowered one)
            for f, sites in sorted(er.sites_by_file.items()):
                for st in sites:
                    if st["status"] != "resolved":
                        rows = [x for x in er.walls if x.file == f and x.line == st["line"] and x.col == st["col"]]
                        print(f"RECORD {name} site {f}:{st['line']}:{st['col']} status={st['status']} "
                              f"recv={st.get('receiver_class', '')} form={st.get('target_form', '')} "
                              f"s2={st.get('s2_reason', '')} wall={rows[0].idiom + '/' + rows[0].confidence if rows else '-'}")
        # in redirector mode the first backward hop is the generated redirector;
        # map it to the link's target so both emission modes are judged alike
        by_redirector = {f"__ctaudit_redirect.{l.redirector}": f"{l.target.module}.{l.target.qualname}"
                         for l in res.links if l.redirector}
        reached = {by_redirector.get(c, c) for c in reached}
        missing = [c for c in e["reaches"] if c not in reached]
        if missing:
            fails.append(f"pyre cond_B did not reach {missing}; reached {sorted(reached)}")
        for c in e.get("not_reaches", []):
            if c in reached:
                fails.append(f"pyre cond_B reached {c!r}, which the fixture forbids")
    return fails


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pyre", action="store_true")
    ap.add_argument("--engine", action="store_true", help="with --pyre: check engine_walls.scan(cond_A) against fixture 'engine'")
    ap.add_argument("--record", action="store_true", help="with --pyre: print the engine status/accept observed at each AST wall (to fill fixture 'engine' keys)")
    ap.add_argument("--only", nargs="*", default=[])
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--emit", nargs="*", default=["inline", "redirector"])
    a = ap.parse_args()
    global RECORD
    RECORD = a.record
    if a.engine or a.record:
        a.pyre = True
    ok = True
    kept = []
    for name, fx in FIXTURES.items():
        if a.only and name not in a.only:
            continue
        # one temp tree per fixture, removed in a finally (review minor: a
        # crash used to leak the whole batch directory)
        base = tempfile.mkdtemp(prefix=f"ctaudit_bench_{name}_")
        try:
            for emit in a.emit:
                try:
                    fails = check(name, fx, base, emit, a.pyre, a.engine)
                except Exception as ex:          # a crash is a failure of that fixture, not of the batch
                    fails = [f"{type(ex).__name__}: {ex}"]
                status = "PASS" if not fails else "FAIL"
                ok = ok and not fails
                print(f"{status} {name:20s} [{emit}]" + ("" if not fails else "\n      - " + "\n      - ".join(fails)))
        finally:
            if a.keep:
                kept.append(base)
            else:
                shutil.rmtree(base, ignore_errors=True)
    for base in kept:
        print("trees kept in", base)
    print("\nALL PASS" if ok else "\nSOME FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
