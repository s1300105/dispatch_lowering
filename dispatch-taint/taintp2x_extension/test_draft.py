"""Tests for draft.py + catalog.py + pipeline.run_plan — no pyre needed.

Uses ``r_min/autogpt`` (in-repo excerpt of AutoGPT's cond_A results plus the
five source files): the draft must pin exactly the one engine wall, derive the
``@command`` recovery key from the in-repo decorator counts, dry-run to the
four ``CodeExecutorComponent`` targets, and ``run_plan`` must lower a copy of
the tree to the same block the legacy AutoGPT spec produced (ids aside).

Self-contained fixtures (temp trees, no Pysa artifacts) cover the review
items that r_min cannot: the FANOUT_MAX demotion, the "a function cannot
override a stub method" rule, two walls on one line (review C1), the impl-map
vocabulary (review M10) and catalogue detection / staleness (review M4).

    python3 test_draft.py
    DRAFT_FULL_TREE=1 python3 test_draft.py     # also probe pysa/projects/sk_real/cond_A (untracked)
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import catalog as CAT      # noqa: E402
import dispatch_lowering as dl   # noqa: E402
import draft as D          # noqa: E402
import engine_walls as EW  # noqa: E402
import pipeline            # noqa: E402
import links as L          # noqa: E402
import toolver             # noqa: E402

R = os.path.join(HERE, "r_min")
FAILS: list = []
N = 0


def check(label, cond, detail=""):
    global N
    N += 1
    print(("PASS " if cond else "FAIL ") + label + ("" if cond or not detail else f": {detail}"))
    if not cond:
        FAILS.append(label)


def test_autogpt_draft_and_plan():
    plan = D.build_plan(os.path.join(R, "autogpt"))
    check("draft: outcome ok", plan["outcome"] == "ok")
    check("draft: plan version 2 with tool_version", plan["version"] == 2 and D.PLAN_VERSION == 2
          and toolver.same_version(plan.get("tool_version"), toolver.tool_version()), str(plan.get("tool_version")))
    check("draft: one group (agent.py)", [g["wall_files"] for g in plan["groups"]] == [["agent.py"]],
          str([g["wall_files"] for g in plan["groups"]]))
    g = plan["groups"][0]
    check("draft: one accepted wall", g["accepted"] == 1 and len(g["walls"]) == 1)
    sp = g["spec"]
    check("draft: detect_* all false", not any(sp[k] for k in ("detect_subscript", "detect_getattr",
                                                                 "detect_higher_order", "detect_boolop")))
    check("draft: @command from decorator counts", sp.get("tool_decorators") == ["command"], str(sp.get("tool_decorators")))
    check("draft: provenance recorded", "forge.command.command" in sp["_provenance"].get("tool_decorators", ""))
    # review M10 / K7: a plan-derived spec always carries the key; no
    # framework with catalogue rows is active here, so it is empty
    check("draft: dispatch_impl_map written empty (no active framework rows)",
          sp.get("dispatch_impl_map") == {} and "empty" in sp["_provenance"].get("dispatch_impl_map", ""),
          str((sp.get("dispatch_impl_map"), sp["_provenance"].get("dispatch_impl_map"))))
    # review M7 / draft minors: counts are recomputed from the groups, the
    # engine's own values are kept beside them, accepted walls by tier
    c = plan["counts"]
    check("draft: counts recomputed from groups + engine values + accepted_by_tier",
          c["walls"] == 1 and c["accepted"] == 1 and c["engine_walls"] == 1 and c["engine_accepted"] == 1
          and c["accepted_by_tier"] == {"T1": 1} and c["by_origin"] == {"engine": 1}, str(c))
    e = sp["wall_positions"][0]
    check("draft: pinned position with metadata",
          (e["at"], e["end"], e["callee"], e["accept"], e["origin"], e["engine_tier"])
          == ("agent.py:277:21", "277:51", "command", True, "engine", "T1"), str(e))
    check("draft: K3 receiver fields carried on entry and row (empty unless the engine fills them)",
          all(k in e for k in ("receiver_class", "target_form", "s2_reason"))
          and all(k in g["walls"][0] for k in ("receiver_class", "target_form", "s2_reason")))
    row = g["walls"][0]
    dr = row.get("dry_run") or {}
    check("draft: dry run lowers 4/4", (dr.get("links"), dr.get("lowered")) == (4, 4), str(dr))
    check("draft: dry-run row names its wall record (join by file:line:col, group-prefixed id)",
          dr.get("wall_id") == "G0W0", str(dr.get("wall_id")))
    names = sorted(t["target"].rsplit(".", 1)[-1] for t in dr.get("targets", []))
    check("draft: the four @command targets",
          names == ["execute_python_code", "execute_python_file", "execute_shell", "execute_shell_popen"], str(names))
    check("draft: splat delivered per parameter",
          any("filename=tool_call.arguments" in t["args"] and "args=tool_call.arguments" in t["args"] for t in dr["targets"]))
    check("draft: candidates summary", plan["candidates"].get("total") == 4)
    check("draft: dry-run stats not multiplied by groups",
          plan["dry_run"]["stats"]["candidates_total"] == 4 and plan["dry_run"]["stats"]["links_lowered"] == 4,
          str(plan["dry_run"]["stats"]))
    md = D.render_walls_md(plan)
    check("draft: walls.md row with fan-out", "`agent.py:277:21`" in md and "4/0/0/0" in md)
    rep = D.render_report_md(plan)
    check("draft: report mentions PLAN_JSON and tool_version", "PLAN_JSON=" in rep and "tool_version" in rep
          and plan["tool_version"]["combined"][:12] in rep)

    # bundle round trip
    out = tempfile.mkdtemp(prefix="draft_")
    try:
        D.write_bundle(plan, out)
        for f in ("plan.json", "plan.draft.json", "walls.md", "report.md", "spec.draft.json", "wall_files.txt",
                  "candidates.draft.json", "links.draft.json", "env_report.json"):
            check(f"bundle: {f}", os.path.exists(os.path.join(out, f)))
        check("bundle: wall_files.txt", open(os.path.join(out, "wall_files.txt")).read().strip() == "agent.py")
        plan2 = json.load(open(os.path.join(out, "plan.json")))
        # review C7: the read-only original is byte-identical to plan.json at
        # draft time and stays so when plan.json is edited in place
        pd = os.path.join(out, "plan.draft.json")
        check("bundle: plan.draft.json is read-only", stat.S_IMODE(os.stat(pd).st_mode) == 0o444, oct(os.stat(pd).st_mode))
        check("bundle: plan.draft.json == plan.json at draft time",
              open(pd).read() == open(os.path.join(out, "plan.json")).read())
        plan2["groups"][0]["walls"][0]["accept"] = False
        json.dump(plan2, open(os.path.join(out, "plan.json"), "w"), indent=2, ensure_ascii=False)
        check("bundle: a review edit of plan.json leaves plan.draft.json untouched (accept flip visible)",
              json.load(open(pd))["groups"][0]["walls"][0]["accept"] is True
              and json.load(open(os.path.join(out, "plan.json")))["groups"][0]["walls"][0]["accept"] is False)
        D.write_bundle(plan, out)       # a re-draft replaces the read-only copy instead of failing
        check("bundle: re-draft replaces plan.draft.json", stat.S_IMODE(os.stat(pd).st_mode) == 0o444
              and json.load(open(pd))["groups"][0]["walls"][0]["accept"] is True)
        plan2 = json.load(open(os.path.join(out, "plan.json")))
        check("bundle: load_plan reads version 2", D.load_plan(os.path.join(out, "plan.json"))["version"] == 2)
        # a version-1 plan (no tool_version, engine counts only) is still readable
        v1 = json.loads(json.dumps(plan2))
        v1["version"] = 1
        del v1["tool_version"]
        v1["counts"] = {"walls": 1, "accepted": 1}
        json.dump(v1, open(os.path.join(out, "plan_v1.json"), "w"))
        lp = D.load_plan(os.path.join(out, "plan_v1.json"))
        check("bundle: load_plan upgrades a version-1 plan",
              lp["version_read"] == 1 and lp["tool_version"] is None and lp["counts"]["engine_walls"] == 1
              and lp["counts"]["accepted_by_tier"] == {"T1": 1}, str(lp["counts"]))
        ld = json.load(open(os.path.join(out, "links.draft.json")))
        check("bundle: links.draft.json has the 4 links", len(ld["links"]) == 4)

        # run_plan on a copy of the tree
        src = os.path.join(out, "src")
        shutil.copytree(os.path.join(R, "autogpt", "src"), src)
        res = pipeline.run_plan(src, plan2, cand_dir=src, emit="inline", write=True)
        check("run_plan: 1 wall, 4 lowered", (res.stats.walls_detected, res.stats.links_lowered) == (1, 4))
        w = res.walls[0]
        check("run_plan: ids are group-prefixed", w.id == "G0W0" and res.links[0].id == "G0L0", w.id)
        check("run_plan: wall carries the engine metadata",
              (w.origin, w.engine_status, w.engine_tier, w.col) == ("engine", "unresolved:UnknownIdentifierCallee", "T1", 21))
        check("run_plan: stats by origin / engine status",
              res.stats.walls_by_origin == {"engine": 1} and res.stats.walls_by_engine_status == {"unresolved": 1})
        lowered = open(os.path.join(src, "agent.py")).read()
        ast.parse(lowered)
        check("run_plan: block inserted after the wall", "if __ctaudit_unreachable__:" in lowered
              and "execute_python_file(filename=tool_call.arguments, args=tool_call.arguments)  # G0L1" in lowered)
        check("run_plan: lowered lines recorded", all(l.lowered_line for l in res.links if l.status == "lowered"))
        # rejected: flip the flag and re-run on a fresh copy
        plan2["groups"][0]["spec"]["wall_positions"][0]["accept"] = False
        src2 = os.path.join(out, "src2")
        shutil.copytree(os.path.join(R, "autogpt", "src"), src2)
        res2 = pipeline.run_plan(src2, plan2, cand_dir=src2, emit="inline", write=True)
        check("run_plan: rejected wall recorded, nothing lowered",
              res2.stats.walls_rejected == 1 and res2.stats.links_lowered == 0
              and res2.walls[0].status == "rejected_by_review")
        check("run_plan: rejected leaves the file untouched",
              open(os.path.join(src2, "agent.py")).read() == open(os.path.join(R, "autogpt", "src", "agent.py")).read())
        # links.json round trip keeps the new fields
        lp = os.path.join(out, "links.json")
        L.dump_links(lp, res.walls, res.links, res.stats)
        ws, ls = L.load_links(lp)
        check("links.json: engine fields survive a round trip",
              ws[0].engine_status == "unresolved:UnknownIdentifierCallee" and ws[0].origin == "engine" and ws[0].col == 21)
    finally:
        shutil.rmtree(out, ignore_errors=True)


def test_preset_priority():
    """Review (draft minors): an explicit --preset supplies its keys —
    ``registry_vars`` included — and beats the detected preset; the
    provenance names the supplier per key.

    Repair: the ORDER is pinned on keys both presets define. ``r_min/lc_0_0_131``
    detects langchain; ``--preset register_runtime`` and langchain both carry
    ``register_methods`` (different values) and ``tool_wrappers`` (the same
    value — the provenance is the discriminator), so the explicit preset must
    win both while langchain still supplies ``tool_list_names``, which only it
    defines. The earlier openmanus / langchain pair could not pin the order:
    openmanus defines only tool_base_classes / tool_impl_methods, so
    langchain's register_methods won whatever the tuple order."""
    cat = os.path.join(HERE, "spec.presets.json")
    rr = D.load_preset(cat, "register_runtime")
    lc = D.load_preset(cat, "langchain")
    check("preset: premise — register_runtime and langchain both define register_methods (differently) and tool_wrappers "
          "(identically); registry_vars is register_runtime-only, tool_list_names langchain-only",
          rr["register_methods"] != lc["register_methods"] and rr["tool_wrappers"] == lc["tool_wrappers"]
          and "registry_vars" in rr and "registry_vars" not in lc and "tool_list_names" in lc and "tool_list_names" not in rr,
          str((rr, lc)))
    plan = D.build_plan(os.path.join(R, "autogpt"), preset=rr)
    sp = plan["groups"][0]["spec"]
    check("preset: --preset register_runtime delivers registry_vars",
          sp.get("registry_vars") == ["TOOLS", "REGISTRY", "FUNCTIONS"], str(sp.get("registry_vars")))
    check("preset: provenance names the explicit preset",
          "register_runtime" in sp["_provenance"].get("registry_vars", "") and "--preset" in sp["_provenance"]["registry_vars"],
          str(sp["_provenance"].get("registry_vars")))
    check("preset: tool_decorators still from the tree's decorator counts", sp.get("tool_decorators") == ["command"])
    # explicit vs detected on a tree that DETECTS langchain: swapping the
    # supplier order in derive_spec makes register_methods / tool_wrappers
    # come from "preset langchain (detected by catalog.detect)" instead
    plan = D.build_plan(os.path.join(R, "lc_0_0_131"), preset=rr, dry_run=False)
    check("preset: lc_0_0_131 detects langchain (the detected preset of this check)",
          plan["catalog"].get("top") == "langchain" and plan["groups"], str(plan["catalog"].get("top")))
    specs = [g["spec"] for g in plan["groups"]]
    prov = specs[0]["_provenance"] if specs else {}
    check("preset: explicit register_runtime beats detected langchain for register_methods (both define it, different values)",
          specs and all(s.get("register_methods") == rr["register_methods"] for s in specs)
          and prov.get("register_methods") == "preset register_runtime (--preset)",
          str((specs[0].get("register_methods") if specs else None, prov.get("register_methods"))))
    check("preset: ... and for tool_wrappers (same value in both — the provenance tells the supplier)",
          specs and all(s.get("tool_wrappers") == rr["tool_wrappers"] for s in specs)
          and prov.get("tool_wrappers") == "preset register_runtime (--preset)", str(prov.get("tool_wrappers")))
    check("preset: a key only the detected preset defines still comes from it (tool_list_names <- langchain, detected)",
          specs and all(s.get("tool_list_names") == lc["tool_list_names"] for s in specs)
          and prov.get("tool_list_names") == "preset langchain (detected by catalog.detect)", str(prov.get("tool_list_names")))
    check("preset: a key only the explicit preset defines comes from it (registry_vars <- register_runtime)",
          specs and all(s.get("registry_vars") == rr["registry_vars"] for s in specs)
          and prov.get("registry_vars") == "preset register_runtime (--preset)", str(prov.get("registry_vars")))
    # the general form of the rule, over every key a preset supplied: the
    # supplier is register_runtime iff register_runtime defines the key,
    # langchain otherwise (tool_decorators / tool_base_classes /
    # tool_impl_methods come from the tree's own evidence and are not judged)
    pres = {k: v for k, v in prov.items() if k in D._PRESET_KEYS and v.startswith("preset ")}
    check("preset: every preset-supplied key comes from register_runtime iff it defines the key, from langchain (detected) otherwise",
          len(pres) >= 4 and all((v == "preset register_runtime (--preset)") == (k in rr) for k, v in pres.items())
          and all(v == "preset langchain (detected by catalog.detect)" for k, v in pres.items() if k not in rr),
          str(pres))
    # the openmanus / langchain pair (kept for what it CAN pin): the tree's
    # own catalogue hits beat both presets, and the impl map covers the
    # explicit preset's framework. register_methods here comes from langchain
    # because openmanus has none — not because of the order.
    plan = D.build_plan(os.path.join(R, "openmanus"), preset=lc)
    sp = next(g["spec"] for g in plan["groups"] if g["wall_files"] == ["app/tool/tool_collection.py"])
    check("preset: a key the detected preset (openmanus) lacks is supplied by the explicit one (register_methods <- langchain)",
          sp.get("register_methods") == ["add_tool", "register"] and "--preset" in sp["_provenance"].get("register_methods", ""),
          str((sp.get("register_methods"), sp["_provenance"].get("register_methods"))))
    check("preset: the tree's own catalogue hits still come first",
          sp.get("tool_base_classes") == ["BaseTool"] and sp.get("tool_impl_methods") == ["execute"]
          and "catalogue rows hit" in sp["_provenance"].get("tool_base_classes", ""))
    check("preset: impl map covers the explicit preset's framework too",
          "run" in sp.get("dispatch_impl_map", {}) and "__call__" in sp.get("dispatch_impl_map", {}),
          str(sp.get("dispatch_impl_map")))


def test_sk_draft_boolop_member():
    plan = D.build_plan(os.path.join(R, "sk_real"))
    g = next((g for g in plan["groups"] if g["wall_files"] == ["semantic_kernel/data/vector.py"]), None)
    check("sk draft: vector.py group", g is not None)
    if not g:
        return
    row = next((r for r in g["walls"] if r["line"] == 2103), None)
    check("sk draft: 2103 accepted", row is not None and row["accept"])
    e = next(e for e in g["spec"]["wall_positions"] if e["at"].endswith(":2103:35"))
    check("sk draft: BoolOp wall capped at level 1", e.get("match_level") == 1)
    dr = (row or {}).get("dry_run") or {}
    low = [t for t in dr.get("targets", []) if t["status"] == "lowered"]
    check("sk draft: exactly the BoolOp member is lowered",
          [t["target"] for t in low] == ["semantic_kernel.data._shared.default_dynamic_filter_function"], str(low))
    check("sk draft: member evidence", low and "BoolOp member" in low[0]["evidence"])
    check("sk draft: impl map from the semantic_kernel rows only",
          set(g["spec"].get("dispatch_impl_map", {})) <= {"invoke", "invoke_stream"}
          and "semantic_kernel" in g["spec"]["_provenance"].get("dispatch_impl_map", ""),
          str(g["spec"].get("dispatch_impl_map")))
    # the full result dir (pysa/projects/sk_real/cond_A, untracked) is probed
    # only on request: its numbers depend on an untracked Pysa output. The
    # fan-out / stub rules are covered by the self-contained fixture below.
    full = os.path.join(HERE, "..", "pysa", "projects", "sk_real", "cond_A")
    if os.environ.get("DRAFT_FULL_TREE") and os.path.isdir(os.path.join(full, "r")):
        plan_full = D.build_plan(full)
        gf = next((g for g in plan_full["groups"] if g["wall_files"] == ["semantic_kernel/data/vector.py"]), None)
        stub = next((r for r in (gf or {"walls": []})["walls"] if r["line"] == 997), None)
        dr = (stub or {}).get("dry_run") or {}
        check("sk draft (full tree): stub wall keeps no name-incompatible candidate",
              stub is not None and dr.get("lowered", 0) == 0 and dr.get("unreasonable", 0) >= 40
              and dr.get("links", 0) >= 40, str({k: dr.get(k) for k in ("links", "lowered", "unreasonable")}))
        row_full = next((r for r in gf["walls"] if r["line"] == 2103), None)
        check("sk draft (full tree): BoolOp wall still 1 lowered of 49 built",
              row_full is not None and row_full["accept"] and row_full["dry_run"]["lowered"] == 1
              and row_full["dry_run"]["links"] > 40, str((row_full or {}).get("dry_run", {}).get("links")))
    else:
        print("SKIP sk draft (full tree): set DRAFT_FULL_TREE=1 with pysa/projects/sk_real/cond_A/r present")


def test_receiver_unknown_stub_policy():
    """Review C5 policy (repair) — the boundary of the unlowerable rule at the
    plan level. sk_real's six ``self.definition.<m>`` stubs have a
    ``typing.Protocol`` receiver: ``receiver_unknown``, no engine target BY
    CONSTRUCTION (no override row for a Protocol). They are NOT unlowerable:
    their candidates come from the draft's recovery, so the rows stay
    pre-accepted (confirmed) with or without ``--include-proposed``; the
    excerpt's recovery finds nothing, which the dry run reports as
    ``no candidate to link`` and the plan as a ``no_candidates`` hint — never
    an ``unlowerable`` hint / note. The claim "the draft never accepts a
    zero-candidate resolved_stub" therefore holds ONLY for
    ``receiver_subclass_no_overrides`` (test_lc_0_0_131_unlowerable_stub):
    an accepted zero-target S2 row is always receiver_unknown."""
    def mk(status, targets, reason):
        return EW.EngineWall(id="X", file="a.py", line=1, col=0, end_line=1, end_col=5, callable="a.f",
                             engine_status=status, dispatch_targets=list(targets), s2_reason=reason)
    got = {label: D._unlowerable(w) for label, w in (
        ("no_overrides", mk("resolved_stub", [], "receiver_subclass_no_overrides")),
        ("unknown", mk("resolved_stub", [], "receiver_unknown")),
        ("subclasses", mk("resolved_stub", ["b.C.m"], "receiver_subclasses")),
        ("no_overrides_with_target", mk("resolved_stub", ["b.C.m"], "receiver_subclass_no_overrides")),
        ("obscure", mk("resolved_obscure", [], "receiver_subclass_no_overrides")),
        ("unresolved", mk("unresolved:UnknownCallCallee", [], "")))}
    check("C5 policy (repair): _unlowerable is exactly the zero-target receiver_subclass_no_overrides resolved_stub",
          got == {"no_overrides": True, "unknown": False, "subclasses": False, "no_overrides_with_target": False,
                  "obscure": False, "unresolved": False}, str(got))
    six = ["semantic_kernel/data/vector.py:927:19", "semantic_kernel/data/vector.py:940:19",
           "semantic_kernel/data/vector.py:997:23", "semantic_kernel/data/vector.py:998:19",
           "semantic_kernel/data/vector.py:1015:23", "semantic_kernel/data/vector.py:1016:18"]
    for include in (False, True):
        plan = D.build_plan(os.path.join(R, "sk_real"), include_proposed=include)
        tag = " (--include-proposed)" if include else ""
        rows = {r["position"]: r for g in plan["groups"] for r in g["walls"]}
        stubs = sorted(p for p, r in rows.items() if r["engine_status"] == "resolved_stub")
        check(f"sk C5 policy (repair){tag}: the six Protocol-receiver stubs are the plan's resolved_stub rows", stubs == sorted(six), str(stubs))
        for pos in six:
            r = rows.get(pos)
            dr = (r or {}).get("dry_run") or {}
            check(f"sk C5 policy (repair){tag}: {pos} receiver_unknown / 0 engine targets stays accepted, confirmed, no unlowerable note",
                  r is not None and r["accept"] is True and r["confidence"] == "confirmed" and r["dispatch_targets"] == []
                  and r["s2_reason"] == "receiver_unknown" and r["receiver_class"].endswith("Protocol")
                  and "unlowerable" not in (r["note"] or ""),
                  str(r and (r["accept"], r["confidence"], r["dispatch_targets"], r["s2_reason"], r["note"])))
            check(f"sk C5 policy (repair){tag}: {pos} dry run — the recovery found no candidate (status unresolved, 0 links)",
                  dr.get("status") == "unresolved" and dr.get("reason") == "no candidate to link" and dr.get("links") == 0
                  and dr.get("lowered") == 0 and dr.get("targets") == [], str(dr))
            kinds = sorted(h["kind"] for h in plan["hints"] if h.get("wall") == pos)
            check(f"sk C5 policy (repair){tag}: {pos} gets the no_candidates hint, not an unlowerable one", kinds == ["no_candidates"], str(kinds))
        check(f"sk C5 policy (repair){tag}: no unlowerable hint anywhere in the plan",
              not any(h.get("kind") == "unlowerable" for h in plan["hints"]), str([h for h in plan["hints"] if h.get("kind") == "unlowerable"]))
        acc0 = sorted((r["position"], r["s2_reason"]) for r in rows.values()
                      if r["accept"] and r["engine_status"] == "resolved_stub" and not r["dispatch_targets"])
        check(f"sk C5 policy (repair){tag}: every accepted zero-target resolved_stub row is receiver_unknown (never receiver_subclass_no_overrides)",
              acc0 == sorted((p, "receiver_unknown") for p in six), str(acc0))


def test_openmanus_catalog_base():
    """OpenManus (gate 2): the catalogue row ``ToolCollection.execute`` names
    ``BaseTool`` as the candidate base, so the S1 wall ``await tool(**tool_input)``
    inside ToolCollection.execute gets every tool's ``execute`` as a candidate."""
    plan = D.build_plan(os.path.join(R, "openmanus"))
    check("openmanus: outcome ok, framework detected (in-repo app.tool / app.agent imports, review M4)",
          plan["outcome"] == "ok" and plan["catalog"]["detected"][:1] == ["openmanus"] and plan["catalog"].get("top") == "openmanus"
          and set(plan["catalog"]["scores"]["openmanus"]["imports"]) == {"app.tool", "app.agent"},
          str((plan["outcome"], plan["catalog"]["detected"], plan["catalog"]["scores"].get("openmanus"))))
    g = next((g for g in plan["groups"] if g["wall_files"] == ["app/tool/tool_collection.py"]), None)
    check("openmanus: tool_collection group", g is not None)
    if not g:
        return
    check("openmanus: candidate base from the catalogue row",
          g["spec"].get("tool_base_classes") == ["BaseTool"] and g["spec"].get("tool_impl_methods") == ["execute"],
          str({k: g["spec"].get(k) for k in ("tool_base_classes", "tool_impl_methods")}))
    r = next((r for r in g["walls"] if r["line"] == 32), None)
    dr = (r or {}).get("dry_run") or {}
    check("openmanus: tool(**tool_input) is S1 higher_order, accepted",
          r is not None and r["engine_status"] == "unresolved:UnknownIdentifierCallee" and r["idiom"] == "higher_order" and r["accept"])
    names = sorted(t["target"].split(".")[-2] for t in dr.get("targets", []) if t["status"] == "lowered")
    check("openmanus: >= 8 tools' execute lowered (Bash, PythonExecute among them)",
          dr.get("lowered", 0) >= 8 and "Bash" in names and "PythonExecute" in names, str(names))
    check("openmanus: splat delivered per parameter of execute",
          any(any(a.endswith("=tool_input") for a in t["args"]) for t in dr.get("targets", [])))
    s3 = next((r for gg in plan["groups"] for r in gg["walls"] if r["file"].endswith("agent/toolcall.py") and r["line"] == 189), None)
    check("openmanus: available_tools.execute(...) is S3 by the catalogue (no override evidence -> confirmed)",
          s3 is not None and s3["engine_status"].endswith("ToolCollection.execute") and s3["accept"])
    # the method-name filter's work on this excerpt (20 unreasonable links on
    # 2 rows): a regression guard for the impl-map vocabulary (review M10)
    rows = [r for gg in plan["groups"] for r in gg["walls"]]
    unr = sum((r.get("dry_run") or {}).get("unreasonable", 0) for r in rows)
    check("openmanus: unreasonable link count on the excerpt is 20 (2 rows)",
          unr == 20 and sum(1 for r in rows if (r.get("dry_run") or {}).get("unreasonable")) == 2,
          str([(r["position"], (r.get("dry_run") or {}).get("unreasonable")) for r in rows if (r.get("dry_run") or {}).get("unreasonable")]))


def test_lc_0_0_131_stub_overrides():
    """langchain 0.0.131 (batch): ``llm_cache.lookup(...)`` resolves to the
    abstract ``BaseCache.lookup``; Pysa's override-graph.json names its three
    implementations, which become the wall's level-1 candidates. A plain
    function can never be such a candidate (it cannot override a method) —
    the excerpt has no such function candidate, so that rule is exercised by
    ``test_stub_wall_fixture`` below."""
    plan = D.build_plan(os.path.join(R, "lc_0_0_131"))
    rows = {r["position"]: (r, g) for g in plan["groups"] for r in g["walls"]}
    r, g = rows.get("langchain/llms/base.py:30:24", (None, None))
    check("lc131: BaseCache.lookup stub wall is S2 and accepted", r is not None and r["engine_status"] == "resolved_stub" and r["accept"])
    if not r:
        return
    e = next(e for e in g["spec"]["wall_positions"] if e["id"] == r["id"])
    check("lc131: candidates are the override-graph implementations",
          e.get("anchor") == "overrides:langchain.cache.BaseCache.lookup"
          and sorted(m["cls"] for m in e["anchor_members"]) == ["InMemoryCache", "RedisCache", "SQLAlchemyCache"], str(e.get("anchor_members")))
    dr = r.get("dry_run") or {}
    low = sorted(t["target"].split(".")[-2] for t in dr.get("targets", []) if t["status"] == "lowered")
    check("lc131: exactly the three overrides lowered", low == ["InMemoryCache", "RedisCache", "SQLAlchemyCache"], str(low))
    check("lc131: every lowered link on the stub wall is an override candidate",
          low and all(t["origin"] == "anchor" for t in dr.get("targets", []) if t["status"] == "lowered"),
          str([(t["target"].split(".")[-1], t["origin"], t["status"]) for t in dr.get("targets", [])][:8]))
    check("lc131: impl map from the langchain rows only (no OpenManus / fastmcp entries)",
          set(g["spec"].get("dispatch_impl_map", {})) <= {"run", "arun", "invoke", "ainvoke"}
          and g["spec"]["dispatch_impl_map"].get("run") == ["_run"], str(g["spec"].get("dispatch_impl_map")))
    # review C5: the same stub method on a sibling receiver has no override candidate -> not a wall
    for pos in ("langchain/agents/chat/base.py:95:8", "langchain/agents/conversational/base.py:105:8",
                "langchain/agents/conversational_chat/base.py:137:8"):
        check(f"lc131 C5: {pos} cls._validate_tools (receiver without overriding subclass) is not drafted", pos not in rows)
    r2, g2 = rows.get("langchain/llms/base.py:30:24", (None, None))
    check("lc131 C5: BaseCache.lookup row carries receiver_class / target_form / s2_reason",
          r2 is not None and r2.get("receiver_class") == "langchain.cache.BaseCache" and r2.get("target_form") == "plain"
          and r2.get("s2_reason") == "receiver_subclasses",
          str({k: (r2 or {}).get(k) for k in ("receiver_class", "target_form", "s2_reason")}))
    # review C5 (repair): the plan-level consequence. The 01:16 langchain-0.0.131
    # plan lowered 9 links to ZeroShotAgent / ReActDocstoreAgent /
    # SelfAskWithSearchAgent._validate_tools from the three sibling-receiver
    # walls — type-impossible edges. No dry-run link of any row may target an
    # ``_validate_tools`` override, an S2 row is accepted only on receiver
    # evidence (receiver_class + a receiver-derived s2_reason), and the
    # excerpt's lowered links are exactly the six BaseCache overrides.
    all_rows = [r for g in plan["groups"] for r in g["walls"]]
    vt = [(r["position"], t["target"]) for r in all_rows
          for t in (r.get("dry_run") or {}).get("targets", []) if t["target"].endswith("._validate_tools")]
    check("lc131 C5: no dry-run link targets an Agent._validate_tools override", vt == [], str(vt))
    s2_acc = [r for r in all_rows if r["accept"] and r["engine_status"].startswith("resolved_stub")]
    check("lc131 C5: every accepted S2 row carries receiver_class and a receiver-derived s2_reason",
          bool(s2_acc) and all(r.get("receiver_class") and r.get("s2_reason") in ("receiver_subclasses", "receiver_unknown")
                               for r in s2_acc),
          str([(r["position"], r.get("receiver_class"), r.get("s2_reason")) for r in s2_acc]))
    low_all = sorted(tuple(t["target"].split(".")[-2:]) for r in all_rows if r["accept"]
                     for t in (r.get("dry_run") or {}).get("targets", []) if t["status"] == "lowered")
    check("lc131 C5: the excerpt's lowered links are exactly the six BaseCache overrides (no sibling-receiver edge)",
          low_all == sorted((c, m) for c in ("InMemoryCache", "RedisCache", "SQLAlchemyCache") for m in ("lookup", "update")),
          str(low_all))


def test_lc_0_0_131_unlowerable_stub():
    """Review C5 policy in the draft: ``self.output_parser.parse`` (agents/
    agent.py:176 / :194) is an unlowerable S2 wall — abstract stub, receiver ==
    owner, no in-tree implementation, 0 candidates. It is IN the plan (a wall
    the reviewer sees, and residual() keeps counting it) but never accepted:
    proposed with the ``unlowerable`` note, no anchor block in its entry, an
    ``unlowerable`` hint — even under ``--include-proposed``. An accepted
    entry can never come from a zero-candidate resolved_stub wall."""
    for include in (False, True):
        plan = D.build_plan(os.path.join(R, "lc_0_0_131"), include_proposed=include)
        rows = {r["position"]: (r, g) for g in plan["groups"] for r in g["walls"]}
        tag = " (--include-proposed)" if include else ""
        for pos in ("langchain/agents/agent.py:176:15", "langchain/agents/agent.py:194:15"):
            r, g = rows.get(pos, (None, None))
            check(f"lc131 C5 policy{tag}: {pos} output_parser.parse is in the plan as a proposed, unaccepted resolved_stub row with 0 candidates",
                  r is not None and r["engine_status"] == "resolved_stub" and r["accept"] is False and r["confidence"] == "proposed"
                  and r["dispatch_targets"] == [] and r["s2_reason"] == "receiver_subclass_no_overrides"
                  and r["note"].startswith("unlowerable: no in-tree implementation of langchain.agents.agent.AgentOutputParser.parse"),
                  str(r and (r["engine_status"], r["accept"], r["confidence"], r["dispatch_targets"], r["s2_reason"], r["note"])))
            if r is None:
                continue
            e = next(e for e in g["spec"]["wall_positions"] if e["id"] == r["id"])
            check(f"lc131 C5 policy{tag}: its spec entry is proposed / accept False with no anchor members",
                  e["accept"] is False and e["confidence"] == "proposed" and "anchor" not in e and "anchor_members" not in e
                  and e["s2_reason"] == "receiver_subclass_no_overrides", str(e))
            check(f"lc131 C5 policy{tag}: no dry-run record for {pos} (never lowered)", not (r.get("dry_run") or {}).get("targets"))
            hs = [h for h in plan["hints"] if h.get("kind") == "unlowerable" and h.get("wall") == pos]
            check(f"lc131 C5 policy{tag}: an `unlowerable` hint names {pos}", len(hs) == 1 and "residual_unlowerable" in hs[0]["text"], str(hs))
        acc0 = [r["position"] for r in (x for g in plan["groups"] for x in g["walls"])
                if r["accept"] and r["engine_status"] == "resolved_stub" and not r["dispatch_targets"]]
        check(f"lc131 C5 policy{tag}: no accepted resolved_stub row has zero candidates", acc0 == [], str(acc0))
        check(f"lc131 C5 policy{tag}: counts — resolved_stub 4 (2 BaseCache + 2 unlowerable), walls 33",
              plan["counts"]["by_status"].get("resolved_stub") == 4 and plan["counts"]["walls"] == 33, str(plan["counts"]))


# --------------------------------------------------------------------------- #
# self-contained fixtures
# --------------------------------------------------------------------------- #
# review (draft minors, repair): a FIXED size — 17 = FANOUT_MAX + 1 at the time
# of writing. Deriving it from D.FANOUT_MAX let a mutated constant (10**9)
# hang the suite instead of failing it; test_stub_wall_fixture asserts the
# constant against this size instead.
_N_METHODS = 17

_TOOLS_PY = "def kernel_function(fn=None, **kw):\n    return fn if fn else (lambda f: f)\n\n\n" + "".join(
    f"class T{i}:\n    @kernel_function\n    def deserialize(self, x):\n        return x\n\n\n" for i in range(_N_METHODS)
) + "".join(
    f"class S{i}:\n    @kernel_function\n    def serialize(self, x):\n        return x\n\n\n" for i in range(2)
) + "".join(
    f"@kernel_function\ndef helper{i}(x):\n    return x\n\n\n" for i in range(3)
)

_APP_PY = '''\
class Host:
    def __init__(self, definition, other):
        self.definition = definition
        self.other = other

    def go(self, x):
        return self.definition.deserialize(x)
'''

_APP2_PY = '''\
class Host2:
    def __init__(self, definition, other):
        self.definition = definition
        self.other = other

    def go(self, x):
        return (self.definition.serialize(x), self.other.serialize(x))
'''


def _calls_in(path: str):
    """(line, col) of every Call whose callee is an attribute, in source order."""
    tree = ast.parse(open(path).read())
    return sorted((n.lineno, n.col_offset) for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute))


def _stub_entry(file: str, line: int, col: int, callee: str, wid: str) -> tuple:
    entry = {"at": f"{file}:{line}:{col}", "callee": callee, "accept": True, "origin": "engine",
             "engine_status": "resolved_stub", "engine_reason": "stub", "engine_tier": "T2",
             "confidence": "confirmed", "id": wid}
    row = {"id": wid, "position": f"{file}:{line}:{col}", "file": file, "line": line, "col": col,
           "callee": callee, "idiom": "attr_call", "resolver": "", "key_expr": "", "receiver_binding": "attr",
           "members": [], "members_open": False, "engine_status": "resolved_stub", "engine_reason": "stub",
           "engine_targets": [], "dispatch_targets": [], "engine_tier": "T2", "origin": "engine",
           "confidence": "confirmed", "accept": True, "note": "", "callable": "", "stmt_kind": "Return",
           "in_async": False, "taint_args": ["x"]}
    return entry, row


def test_stub_wall_fixture():
    """Self-contained (review C1 / draft minors / test gaps):
    * FANOUT_MAX regression — 17 decorated methods on a stub wall are lowered
      by the dry run, so the row is demoted to ``proposed`` with the fan-out
      note, and its links are dropped from ``plan["dry_run"]`` / the stats;
    * a stub wall given decorated FUNCTION candidates marks them
      ``unreasonable`` with "cannot override";
    * two walls on one line are two dry-run records (join by file:line:col);
    * ``candidates_total`` is the maximum over groups, not their sum."""
    out = tempfile.mkdtemp(prefix="draft_fx_")
    try:
        src = os.path.join(out, "src")
        os.makedirs(src)
        open(os.path.join(src, "tools.py"), "w").write(_TOOLS_PY)
        open(os.path.join(src, "app.py"), "w").write(_APP_PY)
        open(os.path.join(src, "app2.py"), "w").write(_APP2_PY)
        (l1, c1), = _calls_in(os.path.join(src, "app.py"))
        (l2, c2), (l3, c3) = _calls_in(os.path.join(src, "app2.py"))
        check("fixture: two walls on one line", l2 == l3 and c2 != c3, str(((l2, c2), (l3, c3))))
        check("fanout: FANOUT_MAX is 16 and the fixture's 17 methods exceed it by one (fixed size, not derived from the constant)",
              D.FANOUT_MAX == 16 and _N_METHODS == D.FANOUT_MAX + 1, str((D.FANOUT_MAX, _N_METHODS)))
        base_spec = {"detect_subscript": False, "detect_getattr": False, "detect_higher_order": False,
                     "detect_boolop": False, "tool_decorators": ["kernel_function"], "dispatch_impl_map": {}}
        total = _N_METHODS + 2 + 3          # every decorated def is a candidate of every wall
        e1, r1 = _stub_entry("app.py", l1, c1, "self.definition.deserialize", "E0")
        e2, r2 = _stub_entry("app2.py", l2, c2, "self.definition.serialize", "E1")
        e3, r3 = _stub_entry("app2.py", l3, c3, "self.other.serialize", "E2")
        plan = {"version": D.PLAN_VERSION, "counts": {}, "hints": [], "env": {},
                "groups": [{"id": "G0", "wall_files": ["app.py"], "walls": [r1], "stages": None, "accepted": 1,
                            "spec": dict(base_spec, wall_positions=[e1], wall_files=["app.py"])},
                           {"id": "G1", "wall_files": ["app2.py"], "walls": [r2, r3], "stages": None, "accepted": 2,
                            "spec": dict(base_spec, wall_positions=[e2, e3], wall_files=["app2.py"])}]}
        # review (draft minors, repair): the groups' dry runs AND the plan-level
        # candidate diagnostics go through ONE memoised AutoLinksProvider.
        # Counted: dl.collect_candidates called DIRECTLY (not from inside
        # dl.describe_candidates) and dl.describe_candidates, over group 0's
        # first pass + its demotion re-run + group 1 + plan["candidates"].
        calls = {"collect": 0, "describe": 0, "inside": 0}
        orig_collect, orig_describe = dl.collect_candidates, dl.describe_candidates

        def counting_collect(*a, **k):
            if not calls["inside"]:
                calls["collect"] += 1
            return orig_collect(*a, **k)

        def counting_describe(*a, **k):
            calls["describe"] += 1
            calls["inside"] += 1
            try:
                return orig_describe(*a, **k)
            finally:
                calls["inside"] -= 1
        dl.collect_candidates, dl.describe_candidates = counting_collect, counting_describe
        try:
            D._dry_run(plan, src)
        finally:
            dl.collect_candidates, dl.describe_candidates = orig_collect, orig_describe
        D._recount(plan)
        dr1 = r1["dry_run"]
        check("fanout: 17 decorated methods lowered on the first pass",
              dr1.get("lowered") == _N_METHODS and dr1.get("demoted") is True, str({k: dr1.get(k) for k in ("lowered", "links", "demoted")}))
        check("fanout: row demoted to proposed with the fan-out note",
              r1["accept"] is False and r1["confidence"] == "proposed" and e1["accept"] is False
              and f"fan-out {_N_METHODS} without narrowing" in r1["note"], r1["note"])
        check("fanout: group 0 accepted count and plan counts follow the demotion",
              plan["groups"][0]["accepted"] == 0 and plan["counts"]["accepted"] == 2 and plan["counts"]["walls"] == 3
              and plan["groups"][0]["dry_run"]["demoted"] == ["E0"], str(plan["counts"]))
        st = plan["dry_run"]["stats"]
        # group 1's two serialize walls lower 2 each; the demoted wall's 17
        # lowered links are gone from the stats (they were 17 + 4 before)
        check("fanout: demoted wall's links dropped from the dry-run links / stats",
              not any(l["wall_id"] == dr1["wall_id"] and l["status"] == "lowered" for l in plan["dry_run"]["links"])
              and st["links_lowered"] == 4 and st["walls_rejected"] == 1 and st["links_built"] == 2 * total,
              str({k: st[k] for k in ("links_lowered", "links_built", "walls_rejected", "walls_detected")}))
        check("fanout: the demoted wall is a rejected_by_review record in the dry-run walls",
              any(w["id"] == dr1["wall_id"] and w["status"] == "rejected_by_review" for w in plan["dry_run"]["walls"]))
        check("stub: decorated functions cannot override the stub method",
              sum(1 for t in dr1["targets"] if t["status"] == "unreasonable" and "cannot override" in t["reason"]) == 3
              and all(t["origin"] == "decorator" for t in dr1["targets"]),
              str([(t["target"], t["status"], t["reason"][:40]) for t in dr1["targets"] if t["status"] != "lowered"]))
        dr2, dr3 = r2["dry_run"], r3["dry_run"]
        check("C1: two walls on one line join two distinct dry-run records",
              dr2.get("wall_id") and dr3.get("wall_id") and dr2["wall_id"] != dr3["wall_id"]
              and dr2.get("lowered") == 2 and dr3.get("lowered") == 2, str((dr2.get("wall_id"), dr3.get("wall_id"))))
        check("stub: methods of another name are unreasonable by the name filter (impl map empty)",
              dr2.get("unreasonable") == _N_METHODS + 3 and any("cannot be the callee" in t["reason"] for t in dr2["targets"]),
              str({k: dr2.get(k) for k in ("links", "lowered", "unreasonable")}))
        check("stats: candidates_total is the max over groups, not the sum",
              st["candidates_total"] == total and plan["candidates"]["total"] == total, str((st["candidates_total"], plan["candidates"].get("total"))))
        check("memo: 2 groups x (first pass + demotion re-run) + plan['candidates'] cost ONE direct collect_candidates "
              "and ONE describe_candidates (the rest hit the provider's caches)",
              calls["collect"] == 1 and calls["describe"] == 1, str(calls))
        key = pipeline._recovery_key(os.path.abspath(src), dl._coerce_spec(base_spec))
        check("memo: plan['candidates'] is the provider's cached list under the groups' own recovery key",
              key in pipeline.AutoLinksProvider._cand_cache
              and plan["candidates"]["total"] == len(pipeline.AutoLinksProvider._cand_cache[key]) == total
              and plan["candidates"]["by_origin"] == {"decorator": total} and "recovery" in plan["candidates"],
              str((plan["candidates"].get("total"), plan["candidates"].get("by_origin"), key in pipeline.AutoLinksProvider._cand_cache)))
        md = D.render_walls_md(plan | {"target": {"cond_dir": "fx"}, "outcome": "ok"})
        # fan-out column: 17 lowered / 0 filtered / 5 unreasonable (3 functions
        # + the 2 ``serialize`` methods) / 0 phantom, accept box empty
        check("fanout: walls.md shows the demoted row off with its fan-out",
              f"| {_N_METHODS}/0/5/0 |   |" in md, md.splitlines()[-3][:120] if md else "")
    finally:
        shutil.rmtree(out, ignore_errors=True)


def test_impl_map_vocabulary():
    """Review M10 / K7: the same tree lowers differently under a hand-written
    spec (no ``dispatch_impl_map`` -> DEFAULT_IMPL_MAP: ``run`` accepts
    ``_run``) and a plan-derived spec with an explicit empty map (``run``
    accepts ``run`` only). The difference is by design and recorded in
    ``LoweringSpec.impl_map_source``."""
    hand = dl._coerce_spec({"tool_decorators": ["tool"]})
    plan_spec = dl._coerce_spec({"tool_decorators": ["tool"], "dispatch_impl_map": {}})
    plan_spec2 = dl._coerce_spec({"tool_decorators": ["tool"], "dispatch_impl_map": {"run": ["_run"]}})
    check("impl map: hand spec falls back to DEFAULT_IMPL_MAP",
          hand.impl_map_source == "default" and dl.impl_map_of(hand)["run"] == ("_run",))
    check("impl map: plan spec with an empty map inherits nothing",
          plan_spec.impl_map_source == "spec" and dl.impl_map_of(plan_spec) == {})
    check("impl map: plan spec with a map has exactly its pairs",
          plan_spec2.impl_map_source == "spec" and dl.impl_map_of(plan_spec2) == {"run": ("_run",)})
    out = tempfile.mkdtemp(prefix="draft_im_")
    try:
        src = os.path.join(out, "src")
        os.makedirs(src)
        open(os.path.join(src, "tools.py"), "w").write(
            "def tool(fn):\n    return fn\n\n\nclass Shell:\n    @tool\n    def _run(self, x):\n        return x\n\n\n"
            "class Echo:\n    @tool\n    def run(self, x):\n        return x\n")
        open(os.path.join(src, "app.py"), "w").write(
            "class Host:\n    def __init__(self, t):\n        self.t = t\n\n    def go(self, x):\n        return self.t.run(x)\n")
        (line, col), = _calls_in(os.path.join(src, "app.py"))
        pos = [{"at": f"app.py:{line}:{col}", "accept": True, "engine_status": "unresolved:UnknownBaseType"}]
        wp = [os.path.join(src, "app.py")]
        r_hand = pipeline.run_spec(src, {"tool_decorators": ["tool"], "wall_positions": pos, "detect_subscript": False,
                                         "detect_getattr": False, "detect_higher_order": False}, wp,
                                   cand_dir=src, emit="redirector", write=False)
        r_plan = pipeline.run_spec(src, {"tool_decorators": ["tool"], "wall_positions": pos, "detect_subscript": False,
                                         "detect_getattr": False, "detect_higher_order": False, "dispatch_impl_map": {}}, wp,
                                   cand_dir=src, emit="redirector", write=False)
        low_h = sorted(l.target.qualname for l in r_hand.links if l.status == "lowered")
        low_p = sorted(l.target.qualname for l in r_plan.links if l.status == "lowered")
        check("impl map: hand spec lowers run and _run (built-in run -> _run)", low_h == ["Echo.run", "Shell._run"], str(low_h))
        check("impl map: plan spec with empty map lowers run only", low_p == ["Echo.run"], str(low_p))
        check("impl map: the dropped candidate is recorded, not silent",
              any(l.status == "unreasonable" and l.target.qualname == "Shell._run" for l in r_plan.links))
    finally:
        shutil.rmtree(out, ignore_errors=True)


def test_impl_map_catalog_fold():
    """Review M10 (repair): the impl map is ONE fold — ``catalog.impl_map_for``
    over the dispatch rows of the active frameworks — shared by
    ``derive_spec`` and by the aggregate's offline check
    ``catalog.impl_map_stale``, so a published plan.json can be told from a
    pre-fix one (merged all-framework map / no map) without re-drafting it,
    and a plan the current code drafts is never reported stale."""
    rows = [{"framework": "a", "api": "x.A.run", "impl": ["_run"]},
            {"framework": "a", "api": "y.B.run", "impl": ["_run", "fn"]},
            {"framework": "b", "api": "z.C.__call__", "impl": ["execute"]},
            {"framework": "b", "api": "z.D.execute", "impl": []},
            {"framework": "c", "api": "w.E.call", "impl": ["call"]}]
    check("fold: rows of the active frameworks only, keys sorted, impls deduplicated in row order",
          CAT.impl_map_for(rows, {"b", "a"}) == {"__call__": ["execute"], "run": ["_run", "fn"]}
          and CAT.impl_map_for(rows, set()) == {} and CAT.impl_map_for(rows, {"zzz"}) == {},
          str(CAT.impl_map_for(rows, {"b", "a"})))
    det = {"detected": ["nope", "a", "b"],
           "scores": {"nope": {"score": 50, "imports": {"nope": 50}}, "a": {"score": 30, "imports": {"a": 30}},
                      "b": {"score": 9, "imports": {}, "base_classes": {"BaseTool": 2}}}}
    check("active: imported presets + the explicit preset; base-class-only and row-less presets excluded; "
          "a version-2 plan's catalog.top counts, a version-1 plan recomputes top_preset() from its scores",
          CAT.active_frameworks(det, rows) == {"a"} and CAT.active_frameworks(det, rows, "c") == {"a", "c"}
          and CAT.active_frameworks(dict(det, top="b"), rows) == {"a", "b"}
          and CAT.active_frameworks(dict(det, top=None), rows) == {"a"}
          and CAT.active_frameworks({"detected": [], "scores": {}}, rows) == set()
          and CAT.active_frameworks({"detected": ["b"], "scores": {"b": {"score": 10, "base_classes": {"ToolCallAgent": 2}}}}, rows) == {"b"},
          str((CAT.active_frameworks(det, rows), CAT.active_frameworks(det, rows, "c"))))
    presets = CAT.load()
    real = CAT.dispatch_rows(presets)
    cat = os.path.join(HERE, "spec.presets.json")
    for name, preset in (("autogpt", ""), ("openmanus", ""), ("openmanus", "superagi"), ("lc_real", ""), ("lc_0_0_131", "")):
        plan = D.build_plan(os.path.join(R, name), preset=D.load_preset(cat, preset) if preset else None, dry_run=False)
        want = CAT.impl_map_for(real, CAT.active_frameworks(plan["catalog"], real, preset))
        maps = {json.dumps(g["spec"].get("dispatch_impl_map")) for g in plan["groups"]}
        check(f"fold: r_min/{name}{' --preset ' + preset if preset else ''}: derive_spec's map == the offline fold "
              f"({', '.join(sorted(want)) or 'empty'}); impl_map_stale ''",
              plan["groups"] and maps == {json.dumps(want)} and CAT.impl_map_stale(plan, presets, preset) == "",
              str((maps, want, CAT.impl_map_stale(plan, presets, preset))))
    plan = D.build_plan(os.path.join(R, "autogpt"), dry_run=False)
    # the map every pre-fix benchmark_out plan carries (all 17 rows folded)
    merged = {"__call__": ["execute"], "acall": ["acall"], "ainvoke": ["_arun"], "arun": ["_arun"],
              "call": ["call", "__call__", "_fn"], "call_tool": ["run"], "execute": ["execute"],
              "invoke": ["_run", "_invoke_internal"], "invoke_stream": ["_invoke_internal_stream"], "run": ["_run", "fn"]}
    stale = json.loads(json.dumps(plan))
    stale["groups"][0]["spec"]["dispatch_impl_map"] = merged
    why = CAT.impl_map_stale(stale, presets)
    check("stale: the pre-fix merged map in a no-framework tree is named with its extra keys",
          "extra keys" in why and "call_tool" in why and "no framework" in why and why.startswith("G0:"), why)
    nokey = json.loads(json.dumps(plan))
    del nokey["groups"][0]["spec"]["dispatch_impl_map"]
    check("stale: a plan without the key (the lowering's built-in fallback) is stale too",
          "no dispatch_impl_map" in CAT.impl_map_stale(nokey, presets), CAT.impl_map_stale(nokey, presets))
    v1 = json.loads(json.dumps(plan))
    v1["version"] = 1
    v1["catalog"].pop("top", None)
    check("stale: a version-1 plan (no catalog.top) is judged by top_preset() from its scores — current map, not stale",
          "top" not in v1["catalog"] and CAT.impl_map_stale(v1, presets) == "", CAT.impl_map_stale(v1, presets))
    om = D.build_plan(os.path.join(R, "openmanus"), dry_run=False)
    wrong = json.loads(json.dumps(om))
    wrong["groups"][-1]["spec"]["dispatch_impl_map"] = {"run": ["_run"]}
    why = CAT.impl_map_stale(wrong, presets)
    check("stale: a group whose map lost the openmanus rows names the missing keys and its group id",
          "missing keys" in why and "__call__" in why and why.startswith(wrong["groups"][-1]["id"] + ":"), why)


def test_catalog_detect_and_stale():
    """Review M4: relative imports never count; presets match by dotted
    prefix (``app.tool``, ``agents.function_tool``), not by a bare top-level
    name; a decorator-only match never becomes the top preset; ``stale()``
    tells a dispatch API defined in the tree from one found only on the
    analysis search path (venv)."""
    presets = CAT.load()
    out = tempfile.mkdtemp(prefix="draft_cat_")
    try:
        def tree(name: str, files: dict) -> str:
            d = os.path.join(out, name)
            for rel, txt in files.items():
                p = os.path.join(d, rel)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                open(p, "w").write(txt)
            return d
        # an ordinary package with its own ``app`` / ``agents`` sub-packages
        t = tree("plain", {"pkg/__init__.py": "", "pkg/agents/__init__.py": "", "pkg/app/__init__.py": "",
                           "pkg/main.py": "from .agents import x\nfrom . import app\nimport app.config\nfrom agents import Agent\n"
                                          "from pkg.agents import y\n\n\ndef f():\n    return x, app, y, Agent\n"})
        d = CAT.detect(t, presets)
        check("detect: an in-repo `app` / `agents` package matches no preset",
              "openmanus" not in d["detected"] and "openai_agents" not in d["detected"] and CAT.top_preset(d) == "", str(d["detected"]))
        # review M4 (repair): a relative import whose dotted tail IS a preset prefix
        # (``from ..app.tool import X`` -> "app.tool", ``from ..agents import function_tool``,
        # ``from .semantic_kernel import x``) still counts nothing — detect skips ImportFrom.level > 0
        t = tree("rel", {"pkg/__init__.py": "", "pkg/app/__init__.py": "", "pkg/app/tool.py": "class BaseTool:\n    pass\n",
                         "pkg/agents.py": "def function_tool(f):\n    return f\n\n\nclass Runner:\n    pass\n",
                         "pkg/semantic_kernel.py": "x = 1\n", "pkg/sub/__init__.py": "",
                         "pkg/sub/use.py": "from ..app.tool import BaseTool\nfrom ..agents import function_tool, Runner\n"
                                           "from .. import langchain\nfrom ..semantic_kernel import x\n\n\ndef f():\n"
                                           "    return BaseTool, function_tool, Runner, langchain, x\n"})
        d = CAT.detect(t, presets)
        check("detect: relative imports never count, even when their dotted tail is a preset prefix (app.tool / agents.function_tool / semantic_kernel)",
              d["detected"] == [] and CAT.top_preset(d) == "" and CAT.framework_of(d, presets) == "(none)", str(d))
        # OpenManus-shaped: absolute in-repo imports of app.tool / app.agent
        t = tree("om", {"app/__init__.py": "", "app/tool/__init__.py": "", "app/tool/base.py": "class BaseTool:\n    pass\n",
                        "app/agent/__init__.py": "", "app/agent/base.py": "from app.tool.base import BaseTool\n\n\nclass A:\n    pass\n",
                        "app/tool/bash.py": "from app.tool.base import BaseTool\n\n\nclass Bash(BaseTool):\n    pass\n",
                        "app/flow.py": "import app.agent.base\n"})
        d = CAT.detect(t, presets)
        check("detect: OpenManus by app.tool / app.agent prefixes",
              CAT.top_preset(d) == "openmanus" and d["scores"]["openmanus"]["imports"] == {"app.tool": 2, "app.agent": 1},
              str(d["scores"].get("openmanus")))
        # OpenAI Agents SDK usage: ``from agents import function_tool``
        t = tree("oa", {"bot.py": "from agents import Agent, Runner, function_tool\n\n\n@function_tool\ndef f(x):\n    return x\n"})
        d = CAT.detect(t, presets)
        check("detect: openai_agents by `from agents import function_tool / Runner`",
              CAT.top_preset(d) == "openai_agents"
              and d["scores"]["openai_agents"]["imports"] == {"agents.function_tool": 1, "agents.Runner": 1}, str(d["scores"].get("openai_agents")))
        # a click CLI: @command alone (litellm) must not make it an AutoGPT tree
        t = tree("cli", {"cli.py": "import click\n\n\n@click.command()\ndef main():\n    pass\n"})
        d = CAT.detect(t, presets)
        check("detect: decorator-only evidence never wins top",
              "autogpt_legacy" in d["detected"] and CAT.top_preset(d) == "", str((d["detected"], CAT.top_preset(d))))
        # a discriminating base class (ToolCallAgent) without imports is enough;
        # BaseTool alone (shared by four presets) is not
        t = tree("bases", {"a.py": "class MyAgent(ToolCallAgent):\n    pass\n\n\nclass T(BaseTool):\n    pass\n"})
        d = CAT.detect(t, presets)
        check("detect: a base class unique to one preset selects it; the shared BaseTool does not",
              CAT.top_preset(d) == "openmanus", str((d["detected"], CAT.top_preset(d))))
        t = tree("bases2", {"a.py": "class T(BaseTool):\n    pass\n"})
        check("detect: BaseTool alone selects no preset", CAT.top_preset(CAT.detect(t, presets)) == "")
        # review M4 (repair): attribution (framework_of) = the seeding preset only above the score
        # threshold, for a version-1 plan (no "top") and a version-2 plan (top recorded) alike —
        # MetaGPT-0.6.3's evidence: 9 semantic_kernel / 8 langchain imports in 170 files
        d_v1 = {"detected": ["semantic_kernel", "langchain"],
                "scores": {"semantic_kernel": {"score": 9, "imports": {"semantic_kernel": 9}, "base_classes": {}, "decorators": {}},
                           "langchain": {"score": 8, "imports": {"langchain": 6, "langchain_core": 2}, "base_classes": {}, "decorators": {}}}}
        d_v2 = dict(d_v1, top="semantic_kernel")
        strong = {"detected": ["langchain"], "scores": {"langchain": {"score": 40, "imports": {"langchain": 40}, "base_classes": {}, "decorators": {}}}}
        check("framework_of: MetaGPT-shaped evidence (semantic_kernel 9 < FW_MIN_SCORE 20) is (none) for a version-1 AND a version-2 plan, "
              "though it still seeds (top_preset)",
              CAT.framework_of(d_v1, presets) == "(none)" and CAT.framework_of(d_v2, presets) == "(none)"
              and CAT.top_preset(d_v1) == "semantic_kernel" and CAT.FW_MIN_SCORE == 20,
              str((CAT.framework_of(d_v1, presets), CAT.framework_of(d_v2, presets))))
        check("framework_of: a strong import match is attributed; a version-2 top None is (none) whatever the scores; a top without a score too",
              CAT.framework_of(strong, presets) == "langchain" and CAT.framework_of(dict(strong, top="langchain"), presets) == "langchain"
              and CAT.framework_of(dict(strong, top=None), presets) == "(none)"
              and CAT.framework_of({"top": "langchain", "detected": ["langchain"]}, presets) == "(none)" and CAT.framework_of({}, presets) == "(none)")
        low = dict(presets, semantic_kernel=dict(presets["semantic_kernel"], match=dict(presets["semantic_kernel"]["match"], min_score=5)))
        check("framework_of: a preset's match.min_score overrides FW_MIN_SCORE; so does an explicit min_score argument",
              CAT.framework_of(d_v2, low) == "semantic_kernel" and CAT.framework_of(d_v2, presets, min_score=5) == "semantic_kernel"
              and CAT.min_score_of("semantic_kernel", low) == 5 and CAT.min_score_of("langchain", low) == CAT.FW_MIN_SCORE)
        # stale(): the langchain rows exist only on the search path (venv). The evidence is above
        # FW_MIN_SCORE (review M4 repair: stale() judges the attributed framework only; the
        # score used to be 10, which no longer attributes the tree to anything)
        det = {"detected": ["langchain"], "scores": {"langchain": {"score": 40, "imports": {"langchain": 40},
                                                                    "base_classes": {}, "decorators": {}}}}
        st_venv = {api: {"in_repo": False, "search_path": True} for api in ("BaseTool.run", "BaseTool.arun", "BaseTool.invoke", "BaseTool.ainvoke")}
        msgs = CAT.stale(det, st_venv, presets)
        check("stale: a dispatch API found only on the search path is reported as stale",
              len(msgs) == 1 and msgs[0].startswith("langchain:") and "search path only" in msgs[0], str(msgs))
        sf = CAT.status_for(det, st_venv, presets)["langchain"]
        check("stale: status_for separates search_path from present / absent",
              sf["present"] == [] and len(sf["search_path"]) == 4 and sf["absent"] == [], str(sf))
        st_repo = dict(st_venv, **{"BaseTool.run": {"in_repo": True, "search_path": True}})
        check("stale: one row defined in the tree is enough", CAT.stale(det, st_repo, presets) == [])
        check("stale: old string values still work (present = in the tree)",
              CAT.stale(det, {"BaseTool.run": "present"}, presets) == []
              and CAT.stale(det, {"BaseTool.run": "absent"}, presets) and "search path" not in CAT.stale(det, {"BaseTool.run": "absent"}, presets)[0])
        # base-class-only evidence above the threshold (5 BaseTool subclasses = 25): attributed, yet never stale
        det_bc = {"detected": ["langchain"], "scores": {"langchain": {"score": 25, "imports": {}, "base_classes": {"BaseTool": 5}, "decorators": {}}}}
        check("stale: a framework matched by base class only never makes the catalogue stale",
              CAT.stale(det_bc, st_venv, presets) == [] and CAT.framework_of(det_bc, presets) == "langchain")
        # review M4 (repair): stale() judges the ATTRIBUTED framework only — incidental imports below the
        # threshold (MetaGPT: semantic_kernel 9 / langchain 8, both venv-only) never turn an accept-0 draft
        # into catalog_stale, and a venv-only framework imported next to the attributed one (SuperAGI also
        # imports llama_index / langchain) is not reported either
        st_all_venv = dict(st_venv, **{api: {"in_repo": False, "search_path": True} for api in ("KernelFunction.invoke", "KernelFunction.invoke_stream")})
        check("stale: below-threshold frameworks never make the catalogue stale (MetaGPT-shaped accept-0 draft stays no_surface / no_walls)",
              CAT.stale(d_v1, st_all_venv, presets) == [] and CAT.stale(d_v2, st_all_venv, presets) == [], str(CAT.stale(d_v1, st_all_venv, presets)))
        check("stale: the same evidence IS stale once the threshold is lowered (the rule is the threshold, not the shape)",
              len(CAT.stale(d_v2, st_all_venv, presets, min_score=5)) == 1 and CAT.stale(d_v2, st_all_venv, presets, min_score=5)[0].startswith("semantic_kernel:"),
              str(CAT.stale(d_v2, st_all_venv, presets, min_score=5)))
        two = {"detected": ["superagi", "langchain"],
               "scores": {"superagi": {"score": 100, "imports": {"superagi": 100}, "base_classes": {}, "decorators": {}},
                          "langchain": {"score": 30, "imports": {"langchain": 30}, "base_classes": {}, "decorators": {}}}}
        st_sa = dict(st_venv, **{"superagi.tools.base_tool.BaseTool.execute": {"in_repo": True, "search_path": True}})
        check("stale: only the attributed framework is judged — a venv-only second framework (SuperAGI's langchain, score 30) is not stale",
              CAT.stale(two, st_sa, presets) == [] and CAT.framework_of(two, presets) == "superagi", str(CAT.stale(two, st_sa, presets)))
        st_sa_absent = dict(st_venv, **{"superagi.tools.base_tool.BaseTool.execute": {"in_repo": False, "search_path": False}})
        msgs = CAT.stale(two, st_sa_absent, presets)
        check("stale: ... and it IS stale when the attributed framework's own row is nowhere (langchain still unreported)",
              len(msgs) == 1 and msgs[0].startswith("superagi:") and "search path" not in msgs[0], str(msgs))
        # review M4 (integration): engine_walls emits two string maps — catalog_status (in-repo)
        # and catalog_status_search_path (venv-inclusive); stale() merges them (agent A's request)
        msgs = CAT.stale(det, {"BaseTool.run": "absent"}, presets, catalog_status_search_path={"BaseTool.run": "present"})
        check("stale: catalog_status + catalog_status_search_path name a search-path-only row",
              len(msgs) == 1 and "search path only: ['BaseTool.run']" in msgs[0], str(msgs))
        check("stale: merge_status folds the two string maps into the {in_repo, search_path} shape",
              CAT.merge_status({"BaseTool.run": "absent"}, {"BaseTool.run": "present"})["BaseTool.run"] == {"in_repo": False, "search_path": True}
              and CAT.merge_status({"BaseTool.run": "present"}, {"BaseTool.run": "present"})["BaseTool.run"] == {"in_repo": True, "search_path": True}
              and CAT.stale(det, {"BaseTool.run": "present"}, presets, catalog_status_search_path={"BaseTool.run": "present"}) == [])
    finally:
        shutil.rmtree(out, ignore_errors=True)


def test_lc_real_search_path_only_is_stale():
    """Review M4 (repair), end to end on a real excerpt: ``r_min/lc_real`` is a
    langchain_classic tree (26 langchain / langchain_core imports, above
    FW_MIN_SCORE) whose ``BaseTool.run`` / ``arun`` live in the venv's
    langchain_core — ``functions.json`` lists them, no in-repo module defines
    them. The draft accepts nothing there, so engine_walls' in-repo
    ``catalog_status`` says absent while ``catalog_status_search_path`` says
    present, and the outcome is ``catalog_stale`` naming the search-path-only
    rows. With the pre-repair search-path semantics of ``catalog_status``
    ("present" if found anywhere) the same tree is ``no_walls``."""
    plan = D.build_plan(os.path.join(R, "lc_real"))
    env, cat = plan["env"], plan["catalog"]
    check("lc_real: attributed to langchain (score >= FW_MIN_SCORE) and seeded by it (plan.catalog.framework == top)",
          cat["top"] == "langchain" and cat["framework"] == "langchain" and cat["scores"]["langchain"]["score"] >= CAT.FW_MIN_SCORE
          and CAT.framework_of(cat, CAT.load()) == "langchain", str(cat.get("scores", {}).get("langchain")))
    check("lc_real: BaseTool.run / arun are on the analysis search path only (venv langchain_core), not defined in the tree",
          env["catalog_status"].get("BaseTool.run") == "absent" and env["catalog_status"].get("BaseTool.arun") == "absent"
          and env["catalog_status_search_path"].get("BaseTool.run") == "present" and env["catalog_status_search_path"].get("BaseTool.arun") == "present",
          str((env.get("catalog_status"), env.get("catalog_status_search_path"))))
    hint = next((h["text"] for h in plan["hints"] if h["kind"] == "catalog"), "")
    check("lc_real: accept 0 + the attributed framework's rows outside the tree -> catalog_stale; the hint names the search-path-only rows",
          plan["groups"] and not any(g["accepted"] for g in plan["groups"]) and plan["outcome"] == "catalog_stale"
          and hint.startswith("catalogue stale: langchain: none of ") and "(on the analysis search path only: ['BaseTool.run', 'BaseTool.arun'])" in hint,
          str((plan["outcome"], hint)))
    md = D.render_report_md(plan)
    check("lc_real: report.md carries the seeding preset, the attribution and both catalogue views",
          "(seeding preset: langchain; attributed framework: langchain)" in md
          and "dispatch rows defined in the tree []; on the analysis search path (venv included) ['BaseTool.arun', 'BaseTool.run']" in md, md[-600:])


def test_anchor_read_closedness():
    """Review C6 (agent B's request): narrowing and promotion key on the
    per-read ``anchor_closed`` flag, not on ``Anchor.closed`` — an *inherited*
    read (a subclass reading a base-assigned attribute) carries candidates but
    is never closed: no ``match_level`` 1, no promotion to confirmed, and the
    note records the binding."""
    from types import SimpleNamespace as NS
    import engine_walls as EW
    members = [{"cls": None, "name": "run_shell", "module": "tools", "origin": "anchor", "match_level": 1}]
    anchor = NS(name="pkg.mod.Base.handler", closed=True)
    exact = NS(candidates=members, anchor_closed=True, binding="exact")
    inherited = NS(candidates=members, anchor_closed=False, binding="inherited")

    def wall():
        return EW.EngineWall(id="E0", file="pkg/sub.py", line=10, col=8, end_line=10, end_col=30, callable="pkg.sub.Sub.go",
                             callee="self.handler", idiom="method_call", engine_status="unresolved:UnknownCallCallee")
    e_exact = D._entry(wall(), (anchor, exact))
    e_inh = D._entry(wall(), (anchor, inherited))
    check("C6 read: an exact closed read narrows (match_level 1, anchor_closed, binding exact)",
          e_exact.get("match_level") == 1 and e_exact["anchor_closed"] is True and e_exact["anchor_binding"] == "exact", str(e_exact))
    check("C6 read: an inherited read of the same closed anchor never narrows (no match_level, anchor_closed False)",
          "match_level" not in e_inh and e_inh["anchor_closed"] is False and e_inh["anchor_binding"] == "inherited"
          and e_inh["anchor_members"] == members, str(e_inh))
    for r, label, promoted in ((exact, "exact", True), (inherited, "inherited", False)):
        w = wall()
        out = D._apply_anchors([w], NS(by_position={(w.file, w.line, w.col): (anchor, r)}), {})
        check(f"C6 read: _apply_anchors {'promotes' if promoted else 'does not promote'} the {label} read",
              len(out) == 1 and out[0].accept is promoted and (out[0].confidence == "confirmed") is promoted
              and f", {label})" in out[0].note and ("(closed," if promoted else "(open,") in out[0].note,
              f"{out[0].accept} {out[0].confidence} {out[0].note}")


def main() -> int:
    test_autogpt_draft_and_plan()
    test_preset_priority()
    test_sk_draft_boolop_member()
    test_receiver_unknown_stub_policy()
    test_openmanus_catalog_base()
    test_lc_0_0_131_stub_overrides()
    test_lc_0_0_131_unlowerable_stub()
    test_stub_wall_fixture()
    test_impl_map_vocabulary()
    test_impl_map_catalog_fold()
    test_catalog_detect_and_stale()
    test_lc_real_search_path_only_is_stale()
    test_anchor_read_closedness()
    print(f"\n{N - len(FAILS)}/{N} passed" + ("" if not FAILS else f"; FAILED: {FAILS}"))
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
