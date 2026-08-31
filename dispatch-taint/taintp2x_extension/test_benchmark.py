"""Tests for run_benchmark.py — state machine, env assembly and aggregation,
no network and no pyre (a local-path fetch of r_min/openmanus; the pyre
stages are exercised with a stubbed ``_run``; review M5: run_ablation.sh
itself is run once end to end with a stub ``pyre`` executable on PATH —
``shell_condB_guard`` — and, when pyre / TaintP2X are installed, in DRAFT=1
mode on a reused cond_A).

    python3 test_benchmark.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
M2 = os.path.join(os.path.dirname(HERE), "taintp2x_m2_verification")
for _p in (HERE, M2):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import run_benchmark as RB      # noqa: E402
import ablation_helpers as H    # noqa: E402  (classify_outcome: the published outcomes are re-derived)
import toolver                  # noqa: E402

FAILS: list = []
N = 0
# review M10: the dispatch_impl_map the fixed draft writes under --preset openmanus (the test manifest's preset)
_OM_MAP = RB.CAT.impl_map_for(RB.CAT.dispatch_rows(RB.CAT.load()), {"openmanus"})
# the merged all-framework map every pre-fix benchmark_out plan carries
_MERGED_MAP = {"__call__": ["execute"], "acall": ["acall"], "ainvoke": ["_arun"], "arun": ["_arun"],
               "call": ["call", "__call__", "_fn"], "call_tool": ["run"], "execute": ["execute"],
               "invoke": ["_run", "_invoke_internal"], "invoke_stream": ["_invoke_internal_stream"], "run": ["_run", "fn"]}


def check(label, cond, detail=""):
    global N
    N += 1
    print(("PASS " if cond else "FAIL ") + label + ("" if cond or not detail else f": {detail}"))
    if not cond:
        FAILS.append(label)


def _plan(accepted: int, total: int = 2, outcome: str = "ok", stages=None, minutes=None) -> dict:
    walls = [{"id": f"E{i}", "position": f"a.py:{i + 1}:4", "file": "a.py", "line": i + 1, "col": 4, "callee": "t.run",
              "accept": i < accepted, "engine_status": "unresolved:UnknownCallCallee", "engine_tier": "T1",
              "origin": "engine", "confidence": "confirmed", "dry_run": {"lowered": 2 if i < accepted else 0}}
             for i in range(total)]
    return {"version": 1, "created": "2026-08-30T00:00:00", "outcome": outcome, "counts": {"walls": total, "accepted": accepted},
            "groups": [{"id": "G0", "wall_files": ["a.py"], "spec": {"wall_positions": [], "dispatch_impl_map": dict(_OM_MAP)}, "walls": walls,
                        "stages": stages, "accepted": accepted}],
            "env": {"catalog_hits": {}}, "catalog": {"detected": [], "scores": {}}, "anchors": {"counts": {}},
            "review": {"minutes": minutes, "notes": ""}, "tool_version": toolver.tool_version()}


def _touch(path: str, text: str = "x") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").write(text)


def main() -> int:
    work = tempfile.mkdtemp(prefix="bench_")
    orig_run = RB._run
    try:
        om = {"name": "om_local", "category": "RCE", "fetch": {"path": os.path.join(HERE, "r_min", "openmanus")},
              "pkg_root": ["src/app"], "dataset_dir": "", "preset": "openmanus",
              "pysa_models": "dispatch-taint/taintp2x_extension/benchmark_models/openmanus.pysa"}
        manifest = {"defaults": {"pyre_timeout": 5, "search_venv": 0},
                    "targets": [om,
                                {"name": "missing_root", "fetch": {"path": os.path.join(HERE, "r_min", "openmanus")},
                                 "pkg_root": ["nope"], "dataset_dir": ""},
                                {"name": "bad_fetch", "fetch": {"path": "/nonexistent/x"}, "pkg_root": ["a"], "dataset_dir": ""},
                                {"name": "om_derived", "category": "RCE", "derived": True, "derived_from": "om_local",
                                 "fetch": {"path": os.path.join(HERE, "r_min", "openmanus")}, "pkg_root": ["src/app"],
                                 "dataset_dir": None},
                                {"name": "never_started", "fetch": {"path": "/nonexistent/y"}, "pkg_root": ["a"]}]}
        defaults = manifest["defaults"]
        t = RB.Target(manifest["targets"][0], defaults, work)
        check("fetch: local path", RB.stage_fetch(t, False) and t.done("fetch") and t.state["stages"]["fetch"]["kind"] == "path")
        check("env: pkg_root copied under src/app", RB.stage_env(t, False) and os.path.isdir(os.path.join(t.src, "app", "tool")))
        check("env: py_files counted", t.state["stages"]["env"]["py_files"] > 10, str(t.state["stages"]["env"]))
        check("env: manual models copied", os.path.exists(t.models) and "ask_tool" in open(t.models).read())
        check("state: idempotent (done stages skipped)", RB.stage_fetch(t, False) and RB.stage_env(t, False))
        t2 = RB.Target(manifest["targets"][1], defaults, work)
        check("env: missing pkg_root -> env_failed", RB.stage_fetch(t2, False) and not RB.stage_env(t2, False)
              and t2.state["outcome"] == "env_failed")
        t3 = RB.Target(manifest["targets"][2], defaults, work)
        check("fetch: bad path -> fetch_failed", not RB.stage_fetch(t3, False) and t3.state["outcome"] == "fetch_failed")

        # --- draft stage: rc classification with a stubbed run_ablation.sh (review M5)
        cond_a_out = os.path.join(t.abl, "cond_A", "r", "taint-output.json")
        plan_path = os.path.join(t.abl, "draft", "plan.json")
        _touch(cond_a_out, "[]\n")
        RB._run = lambda *a, **k: 1
        check("draft: rc 1 (draft.py exception) -> draft_failed, stage not done",
              not RB.stage_draft(t, False) and t.state["outcome"] == "draft_failed" and not t.done("draft"))
        RB._run = lambda *a, **k: 124
        check("draft: rc 124 (timeout) -> draft_failed", not RB.stage_draft(t, False) and t.state["outcome"] == "draft_failed")
        RB._run = lambda *a, **k: 0
        check("draft: rc 0 without plan.json -> draft_failed", not RB.stage_draft(t, False) and t.state["outcome"] == "draft_failed")
        json.dump(_plan(0, outcome="no_walls"), open(_touch(plan_path) or plan_path, "w"))
        RB._run = lambda *a, **k: 5
        check("draft: rc 5 with plan.json -> done, outcome no_walls, tool_version recorded",
              RB.stage_draft(t, False) and t.done("draft") and t.state["outcome"] == "no_walls"
              and t.state["stages"]["draft"]["accepted"] == 0
              and t.state["stages"]["draft"]["tool_version"]["combined"] == toolver.tool_version()["combined"], str(t.state))
        # --- condB decides from the plan's content, not the recorded verdict (review M5)
        check("condB: a plan with no accepted wall is skipped", RB.stage_condB(t, False, accept_draft=False)
              and t.state["stages"]["condB"].get("skipped") and t.state["stages"]["condB"]["reason"] == "no_walls")
        json.dump(_plan(1, outcome="no_walls"), open(plan_path, "w"))       # the reviewer flipped one accept
        check("condB: a no_walls draft with a flipped accept is NOT skipped (reaches the review gate)",
              not RB.stage_condB(t, True, accept_draft=False) and "awaiting review" in t.state["errors"][-1]
              and not t.state["stages"]["condB"].get("skipped"))
        json.dump(_plan(0, stages=[{"spec": {}}]), open(plan_path, "w"))
        check("condB: analyst stages alone are something to lower", not RB.stage_condB(t, True, accept_draft=False)
              and "awaiting review" in t.state["errors"][-1])
        json.dump(_plan(1, minutes=3), open(plan_path, "w"))
        RB._run = lambda *a, **k: 0
        check("condB: reviewed plan, cond_B without results -> env_failed",
              not RB.stage_condB(t, True, accept_draft=False) and t.state["outcome"] == "env_failed")
        # review C2: the best-effort row of a condB that failed after the lowering can be
        # re-derived with --force (same failure, current definitions); never without it
        RB._run = orig_run
        json.dump({"links_lowered": 2, "walls_detected": 2, "walls_rejected": 1}, open(_touch(os.path.join(t.abl, "cond_B", "stats.json")) or os.path.join(t.abl, "cond_B", "stats.json"), "w"))
        check("row: a failed condB still refuses a plain row", not RB.stage_row(t, False) and "condB not done" in t.state["errors"][-1])
        check("row --force: re-derives the env_failed row of a condB that failed after lowering (K5 key, outcome_inputs)",
              RB.stage_row(t, True) and t.done("row") and t.state["outcome"] == "env_failed"
              and json.load(open(os.path.join(t.work, "row.json")))["sink_pairs"]["key"] == RB.SINK_PAIR_KEY
              and json.load(open(os.path.join(t.work, "row.json")))["outcome_inputs"]["has_b"] is False, str(t.state.get("errors", [])[-1:]))
        shutil.rmtree(os.path.join(t.abl, "cond_B"), ignore_errors=True)
        check("row --force: a condB that never lowered (no cond_B dir) is still refused",
              not RB.stage_row(t, True) and "condB not done" in t.state["errors"][-1])
        cond_b_out = os.path.join(t.abl, "cond_B", "r", "taint-output.json")

        def fake_condB(*a, **k):
            _touch(cond_b_out, "[]\n")
            json.dump({"links_lowered": 2, "walls_detected": 2, "walls_rejected": 1}, open(os.path.join(t.abl, "cond_B", "stats.json"), "w"))
            json.dump(_plan(1, minutes=3), open(os.path.join(t.abl, "cond_B", "plan.json"), "w"))
            return 0
        RB._run = fake_condB
        _touch(os.path.join(t.abl, "row.json"), "{}")
        check("condB: reviewed plan lowered -> done, stale row.json discarded, tool_version recorded",
              RB.stage_condB(t, True, accept_draft=False) and t.done("condB") and t.state["stages"]["condB"]["accepted"] == 1
              and not os.path.exists(os.path.join(t.abl, "row.json")) and t.state["stages"]["condB"]["tool_version"])
        # --- row requires condB and recomputes with --force (real ablation_helpers row, no pyre)
        RB._run = orig_run
        t.state["stages"].pop("condB")
        check("row: refused before condB", not RB.stage_row(t, False) and "condB not done" in t.state["errors"][-1])
        t.state["stages"]["condB"] = {"done": True}
        check("row: computed by ablation_helpers and merged", RB.stage_row(t, False) and t.done("row")
              and os.path.exists(os.path.join(t.work, "row.json")) and t.state["outcome"] == "delta0", str(t.state.get("outcome")))
        _touch(os.path.join(t.abl, "row.json"), json.dumps({"outcome": "marker"}))
        check("row: --force recomputes", RB.stage_row(t, True) and t.state["outcome"] == "delta0")
        check("row: not recomputed without --force", RB.stage_row(t, False)
              and json.load(open(os.path.join(t.abl, "row.json")))["outcome"] == "delta0")
        # --- draft --force discards cond_B / row / ablate and resets their stages (review C3 / M5)
        _touch(os.path.join(t.abl, "ablate", "none", "plan.json"), "{}")
        _touch(os.path.join(t.work, "ablation.json"), "{}")
        t.state["stages"]["ablate"] = {"done": True}
        t.save()

        def fake_draft(*a, **k):
            _touch(cond_a_out, "[]\n")
            json.dump(_plan(1), open(_touch(plan_path) or plan_path, "w"))
            return 0
        RB._run = fake_draft
        check("draft --force: cond_B, ablate, row.json, ablation.json gone; condB/row/ablate stages reset; outcome drafted",
              RB.stage_draft(t, True) and t.state["outcome"] == "drafted"
              and not os.path.exists(os.path.join(t.abl, "cond_B")) and not os.path.exists(os.path.join(t.abl, "ablate"))
              and not os.path.exists(os.path.join(t.abl, "row.json")) and not os.path.exists(os.path.join(t.work, "ablation.json"))
              and not any(s in t.state["stages"] for s in ("condB", "row", "ablate")), str(list(t.state["stages"])))
        # --- review C7 (repair): --force never keeps a reviewed plan silently. run_ablation.sh keeps a
        # plan.json that differs from plan.draft.json unless FORCE_DRAFT=1; the runner passes it on --force
        # (after backing the reviewed plan up) and records whether the plan on disk is one the current
        # code drafted (versions_match / plan_kept_reviewed in the draft stage)
        draft_dir = os.path.join(t.abl, "draft")
        orig_draft = os.path.join(draft_dir, "plan.draft.json")
        json.dump(_plan(1), open(orig_draft, "w"))
        reviewed = _plan(2, minutes=9)
        reviewed["tool_version"] = dict(toolver.tool_version(), combined="3" * 64)      # drafted by an older code
        json.dump(reviewed, open(plan_path, "w"))
        seen_env = []

        def fake_sh(cmd, *a_, **k):
            # what run_ablation.sh does in DRAFT=1 mode: a reviewed plan is kept unless FORCE_DRAFT=1
            env = k.get("env") or {}
            seen_env.append(env.get("FORCE_DRAFT", ""))
            _touch(cond_a_out, "[]\n")
            kept = os.path.exists(plan_path) and os.path.exists(orig_draft) and open(plan_path).read() != open(orig_draft).read()
            if env.get("FORCE_DRAFT") or not kept:
                shutil.rmtree(draft_dir, ignore_errors=True)
                fresh = _plan(1)
                json.dump(fresh, open(_touch(plan_path) or plan_path, "w"))
                json.dump(fresh, open(orig_draft, "w"))
            return 0
        RB._run = fake_sh
        t.reset("draft")
        check("draft (no --force): a reviewed plan is kept — FORCE_DRAFT not passed, plan.json untouched, stage records "
              "plan_kept_reviewed True and versions_match False (older tool_version)",
              RB.stage_draft(t, False) and seen_env == [""] and json.load(open(plan_path))["review"]["minutes"] == 9
              and t.state["stages"]["draft"]["plan_kept_reviewed"] is True and t.state["stages"]["draft"]["versions_match"] is False
              and t.state["stages"]["draft"]["accepted"] == 2 and t.state["stages"]["draft"]["reviewed_plan_backup"] is None,
              str(t.state["stages"]["draft"]))
        marker = os.path.join(t.abl, "cond_A", "marker")
        _touch(marker)
        check("draft --force --keep-cond-a: FORCE_DRAFT=1 passed, the reviewed plan (+ its original) backed up under "
              "reviewed_plans/, plan re-drafted (== plan.draft.json), versions_match True, cond_A kept",
              RB.stage_draft(t, True, keep_cond_a=True) and seen_env == ["", "1"]
              and json.load(open(plan_path))["review"]["minutes"] is None
              and open(plan_path).read() == open(orig_draft).read()
              and t.state["stages"]["draft"]["plan_kept_reviewed"] is False and t.state["stages"]["draft"]["versions_match"] is True
              and (t.state["stages"]["draft"].get("reviewed_plan_backup") or "").startswith(os.path.join(t.work, "reviewed_plans"))
              and json.load(open(t.state["stages"]["draft"]["reviewed_plan_backup"]))["review"]["minutes"] == 9
              and json.load(open(t.state["stages"]["draft"]["reviewed_plan_backup"][:-5] + ".draft.json"))["review"]["minutes"] is None
              and os.path.exists(marker) and t.state["outcome"] == "drafted",
              str(t.state["stages"]["draft"]))
        check("draft --force without review work: no backup made, cond_A discarded without --keep-cond-a",
              RB.stage_draft(t, True) and seen_env == ["", "1", "1"] and t.state["stages"]["draft"]["reviewed_plan_backup"] is None
              and sorted(os.listdir(os.path.join(t.work, "reviewed_plans"))) == sorted(
                  [os.path.basename(p_) for p_ in (lambda b: [b, b[:-5] + ".draft.json"])(
                      os.path.join(t.work, "reviewed_plans", "plan.2026-08-30T00-00-00.json"))])
              and not os.path.exists(marker), str(os.listdir(os.path.join(t.work, "reviewed_plans"))))
        check("main: --stage all --from draft runs draft -> condB -> row; a single stage ignores --from",
              RB._stage_sequence("all", "draft") == ["draft", "condB", "row"] and RB._stage_sequence("all") == RB.STAGES
              and RB._stage_sequence("condB", "draft") == ["condB"] and RB._stage_sequence("ablate", "draft") == ["ablate"])
        # --stage all --from draft on a target whose fetch/env never ran starts from fetch
        # (vanna-0.3.3 / 0.3.4 on the 2026-08-31 re-run failed in the preflight instead)
        t_ns = RB.Target(manifest["targets"][3], defaults, work)
        check("stage sequence: --from draft falls back to the first stage not done (fetch) on a never-fetched target, "
              "and stays at draft when fetch/env are done",
              RB._effective_sequence(t_ns, "all", "draft") == RB.STAGES
              and RB._effective_sequence(t, "all", "draft") == ["draft", "condB", "row"]
              and RB._effective_sequence(t_ns, "condB", "draft") == ["condB"],
              str((RB._effective_sequence(t_ns, "all", "draft"), RB._effective_sequence(t, "all", "draft"))))
        RB._run = orig_run

        # subset: import closure of app from tool_collection.py (no pyre)
        t4 = RB.Target({"name": "om_subset", "fetch": {"path": os.path.join(HERE, "r_min", "openmanus")},
                        "pkg_root": ["src/app"], "dataset_dir": "",
                        "subset": {"pkg": "app", "entries": ["app/tool/tool_collection.py"]}}, defaults, work)
        ok = RB.stage_fetch(t4, False) and RB.stage_env(t4, False)
        sub = t4.state.get("subset") or {}
        check("subset: env stage keeps the import closure only", ok and 0 < sub.get("kept_files", 0) < t.state["stages"]["env"]["py_files"],
              str(sub))
        # the closure follows the package __init__ re-exports (app/tool/__init__.py
        # imports every tool), so the tools stay; modules nothing imports go
        check("subset: tool_collection, base and the re-exported tools kept; unreached modules removed",
              os.path.exists(os.path.join(t4.src, "app", "tool", "tool_collection.py"))
              and os.path.exists(os.path.join(t4.src, "app", "tool", "base.py"))
              and os.path.exists(os.path.join(t4.src, "app", "tool", "bash.py"))
              and not os.path.exists(os.path.join(t4.src, "app", "agent", "toolcall.py"))
              and not os.path.exists(os.path.join(t4.src, "app", "llm.py")))
        check("subset: imports of modules absent from the tree are counted, not hidden",
              sub.get("broken_imports", 0) >= 1 and all("app." in r for r in sub.get("broken_import_rows", [])), str(sub.get("broken_import_rows")))
        check("subset: search_extra points at deps_iso / stubs_min",
              [os.path.basename(x) for x in t4.state.get("search_extra", [])] == ["deps_iso", "stubs_min"]
              and os.path.isdir(t4.state["search_extra"][0]))
        env = RB._ablation_env(t4)
        check("subset: ablation env uses PYRE_EXTRA_SEARCH and no venv", env.get("PYRE_SEARCH_VENV") == "0" and "deps_iso" in env.get("PYRE_EXTRA_SEARCH", ""))
        shutil.rmtree(os.path.join(work, "om_subset"), ignore_errors=True)      # not a manifest target

        # --- review C7 (repair), end to end: the real run_ablation.sh in DRAFT=1 mode on a reused
        # cond_A (r_min/openmanus, REUSE_COND_A: no pyre) writes plan.json + read-only plan.draft.json,
        # keeps a reviewed plan.json on a plain re-run and discards it on FORCE_DRAFT=1 (--force)
        typeshed = os.environ.get("TYPESHED", os.path.join(RB.ROOT, ".venv", "lib", "pyre_check", "typeshed"))
        tp2x = os.environ.get("TP2X", os.path.join(RB.ROOT, "TaintP2X", "Taint_Propagation"))
        if shutil.which("pyre") and os.path.isdir(os.path.join(tp2x, "taint")) and os.path.isdir(typeshed):
            t5 = RB.Target(dict(om, name="om_shell"), defaults, work)
            ok = RB.stage_fetch(t5, False) and RB.stage_env(t5, False)
            shutil.copytree(os.path.join(HERE, "r_min", "openmanus"), os.path.join(t5.abl, "cond_A"), symlinks=False)
            ok = ok and RB.stage_draft(t5, False)
            d5 = t5.state["stages"].get("draft", {})
            p5, o5 = os.path.join(t5.abl, "draft", "plan.json"), os.path.join(t5.abl, "draft", "plan.draft.json")
            check("shell DRAFT=1 on a reused cond_A: plan.json == read-only plan.draft.json, versions_match True, "
                  "not kept, outcome drafted, abl/row.json says drafted",
                  ok and d5.get("done") and d5.get("versions_match") is True and d5.get("plan_kept_reviewed") is False
                  and os.path.exists(o5) and open(p5).read() == open(o5).read() and (os.stat(o5).st_mode & 0o222) == 0
                  and t5.state["outcome"] == "drafted" and d5.get("accepted", 0) > 0
                  and json.load(open(os.path.join(t5.abl, "row.json")))["outcome"] == "drafted",
                  str(d5) + str(t5.state.get("errors")))
            p = json.load(open(p5))
            first = next(w for g in p["groups"] for w in g["walls"])
            first["accept"] = not first["accept"]
            p["review"]["minutes"] = 4
            p["tool_version"] = dict(p.get("tool_version") or toolver.tool_version(), combined="5" * 64)
            json.dump(p, open(p5, "w"), indent=2)
            t5.reset("draft")
            ok = RB.stage_draft(t5, False)
            d5 = t5.state["stages"].get("draft", {})
            check("shell DRAFT=1 again (no --force): the reviewed plan is kept — minutes / flip / tool_version untouched, "
                  "stage says plan_kept_reviewed True, versions_match False",
                  ok and json.load(open(p5))["review"]["minutes"] == 4 and d5.get("plan_kept_reviewed") is True
                  and d5.get("versions_match") is False and open(p5).read() != open(o5).read(), str(d5))
            ok = RB.stage_draft(t5, True, keep_cond_a=True)
            d5 = t5.state["stages"].get("draft", {})
            check("shell FORCE_DRAFT=1 (--force --keep-cond-a): re-drafted — plan.json == plan.draft.json, minutes null, "
                  "versions_match True, the reviewed plan backed up, cond_A reused",
                  ok and open(p5).read() == open(o5).read() and json.load(open(p5))["review"]["minutes"] is None
                  and d5.get("versions_match") is True and d5.get("plan_kept_reviewed") is False
                  and d5.get("reviewed_plan_backup") and json.load(open(d5["reviewed_plan_backup"]))["review"]["minutes"] == 4
                  and os.path.exists(os.path.join(t5.abl, "cond_A", "r", "taint-output.json")), str(d5) + str(t5.state.get("errors")))
            shutil.rmtree(os.path.join(work, "om_shell"), ignore_errors=True)   # not a manifest target
        else:
            print("SKIP shell DRAFT=1 (review C7): pyre / TaintP2X / typeshed not available")

        # ablate (draft level, no pyre) on the local cond_A = r_min/openmanus
        shutil.rmtree(t.abl, ignore_errors=True)
        os.makedirs(t.abl, exist_ok=True)
        shutil.copytree(os.path.join(HERE, "r_min", "openmanus"), os.path.join(t.abl, "cond_A"), symlinks=False)
        check("ablate: runs the five axes without pyre", RB.stage_ablate(t, True, with_pyre=False) and t.done("ablate"))
        a = json.load(open(os.path.join(t.work, "ablation.json")))
        axes = a.get("axes") or {}
        check("ablate: axes recorded under 'axes', tool_version and draft_args recorded",
              sorted(axes) == ["S1", "S2", "S3", "anchoring", "none"]
              and a["tool_version"]["combined"] == toolver.tool_version()["combined"] and a["draft_args"] == ["--preset", "openmanus"],
              str(sorted(axes)) + str(a.get("draft_args")))
        check("ablate: every axis produced a plan", all("accepted" in (axes.get(k) or {}) for k in RB.AXES),
              str({k: (axes.get(k) or {}).get("error") for k in RB.AXES}))
        check("ablate: -S1 removes the unresolved rows", axes["S1"].get("accepted", 99) < axes["none"].get("accepted", 0)
              and "unresolved" not in axes["S1"].get("by_status", {"unresolved": 1}), str(axes["S1"]))
        check("ablate: -S2 / -anchoring leave OpenManus unchanged",
              axes["S2"].get("lowered_links") == axes["none"].get("lowered_links") == axes["anchoring"].get("lowered_links", -1))
        check("ablate: no symlinked work dirs", not any(os.path.islink(os.path.join(r_, d_))
                                                     for r_, ds, _f in os.walk(os.path.join(t.abl, "ablate")) for d_ in ds))
        check("ablate: no abl/draft/plan.json -> plan info null", a.get("plan") is None)
        sentinel = os.path.join(t.abl, "ablate", "none", "sentinel")
        _touch(sentinel)
        # review C3: the done contract is pinned on the WORK the stage would do, not on the
        # sentinel alone -- draft.py --out does not clear abl/ablate/none, so a runner that
        # ignored t.done('ablate') re-drafted every axis and rewrote ablation.json with the
        # sentinel still in place (the old check passed with the guard replaced by ``if False``)
        abl_json = os.path.join(t.work, "ablation.json")
        abl_text0 = open(abl_json).read()
        ablate_at0 = t.state["stages"]["ablate"]["at"]
        no_work_calls = []

        def no_work(cmd, *a_, **k):
            no_work_calls.append(list(cmd))
            return 0
        RB._run = no_work
        skipped = RB.stage_ablate(t, False, with_pyre=False)
        RB._run = orig_run
        check("ablate: done -> skipped without --force: no draft.py / run_ablation.sh call, ablation.json byte-identical, "
              "stage 'at' unchanged, sentinel kept",
              skipped is True and no_work_calls == [] and open(abl_json).read() == abl_text0
              and t.state["stages"]["ablate"]["at"] == ablate_at0 and t.done("ablate") and os.path.exists(sentinel),
              str((len(no_work_calls), no_work_calls[:1], open(abl_json).read() == abl_text0)))
        # the runner's plan on disk: recorded in ablation.json, refreshed into the draft stage (review C3)
        shutil.copy(os.path.join(t.abl, "ablate", "none", "plan.json"), os.path.join(_touch(plan_path) or plan_path))
        t.state["stages"]["draft"] = {"done": True, "outcome": "ok", "plan": plan_path, "walls": 999, "accepted": 999}
        t.spec["draft_args"] = "--include-proposed"
        seen = []

        def rec_run(cmd, *a_, **k):
            seen.append(cmd)
            return orig_run(cmd, *a_, **k)
        RB._run = rec_run
        ok = RB.stage_ablate(t, True, with_pyre=False)
        RB._run = orig_run
        a = json.load(open(os.path.join(t.work, "ablation.json")))
        check("ablate --force: DID re-run (one draft.py call per axis, sentinel gone, new 'at'); draft_args forwarded to every axis",
              ok and not os.path.exists(sentinel) and len(seen) == 5 and t.done("ablate")
              and open(abl_json).read() != abl_text0
              and all("--include-proposed" in c and "--preset" in c for c in seen), str(seen[:1]))
        check("ablate: plan created / tool_version / counts recorded",
              (a.get("plan") or {}).get("created") and a["plan"]["tool_version"] and a["plan"]["accepted"] == a["axes"]["none"]["accepted"]
              if not t.spec["draft_args"] else (a.get("plan") or {}).get("created") and a["plan"]["tool_version"], str(a.get("plan")))
        check("ablate: draft stage of state.json refreshed from the plan on disk",
              t.state["stages"]["draft"]["accepted"] == a["plan"]["accepted"] and t.state["stages"]["draft"].get("refreshed_by") == "ablate",
              str(t.state["stages"]["draft"]))
        t.spec["draft_args"] = ""
        # review C3 (repair): the plan on disk was drafted without --include-proposed and
        # is kept as it is (copying the re-drafted 'none' plan over it would be the very
        # re-draft the provenance check flags); the ablation is made again against it
        plan_created = json.load(open(plan_path))["created"]
        check("ablate --force against the unchanged plan: records that plan's created stamp",
              RB.stage_ablate(t, True, with_pyre=False)
              and json.load(open(os.path.join(t.work, "ablation.json")))["plan"]["created"] == plan_created
              and json.load(open(os.path.join(t.work, "ablation.json")))["complete"] is True, str(t.state["stages"].get("ablate")))

        # --- the pyre pass of ablate (review C3 repair): stubbed run_ablation.sh, real draft.py
        a0 = json.load(open(os.path.join(t.work, "ablation.json")))
        axis_p = next(k for k in ("S1", "S2", "S3", "anchoring") if (a0["axes"].get(k) or {}).get("lowered_links"))
        axis_work = os.path.join(t.abl, "ablate", axis_p, "abl")
        leftover = os.path.join(axis_work, "row.json")
        _touch(leftover, json.dumps({"issues": {"cond_A": 1, "cond_B": 99, "delta": 98}, "links": {"links_lowered": 77},
                                     "outcome": "delta_pos"}))
        t.state["stages"].pop("ablate", None)
        t.save()

        def sh_fail(cmd, *a_, **k):
            if cmd[0] == "bash":
                return 124                       # pyre timed out: no cond_B results, no new row.json
            return orig_run(cmd, *a_, **k)
        RB._run = sh_fail
        ok = RB.stage_ablate(t, False, with_pyre=True)
        RB._run = orig_run
        a1 = json.load(open(os.path.join(t.work, "ablation.json")))
        ax = a1["axes"].get(axis_p) or {}
        check("ablate --ablate-pyre: run_ablation.sh rc 124 -> stage NOT done, axis records pyre_rc and pyre_error, "
              "no issues from a leftover row.json, ablation.json incomplete",
              not ok and not t.done("ablate") and "pyre pass failed" in t.state["errors"][-1]
              and ax.get("pyre_rc") == 124 and "rc=124" in ax.get("pyre_error", "") and "issues" not in ax
              and "links_lowered_real" not in ax and a1["complete"] is False and axis_p in a1["pyre_errors"]
              and not os.path.exists(leftover), str(ax) + str(t.state["errors"][-1:]))
        RB.aggregate(work, manifest)
        md = open(os.path.join(work, "summary.md")).read()
        check("aggregate: an incomplete ablation is marked stale and the failed axis cell says so",
              "incomplete: pyre pass failed for " + axis_p in md and f"[pyre failed: run_ablation.sh rc=124" in md,
              md.split("## leave-one-out")[1][:700])

        def sh_ok(cmd, *a_, **k):
            if cmd[0] != "bash":
                return orig_run(cmd, *a_, **k)
            w = k["env"]["WORK"]
            _touch(os.path.join(w, "cond_B", "r", "taint-output.json"), "[]\n")
            open(_touch(os.path.join(w, "cond_B", "pyre_seconds")) or os.path.join(w, "cond_B", "pyre_seconds"), "w").write("7\n")
            json.dump({"issues": {"cond_A": 1, "cond_B": 3, "delta": 2}, "sink_pairs": {"cond_A": 1, "cond_B": 2, "new": ["x"], "lost": []},
                       "links": {"links_lowered": 5}, "outcome": "delta_pos"}, open(os.path.join(w, "row.json"), "w"))
            return 0
        RB._run = sh_ok
        ok = RB.stage_ablate(t, False, with_pyre=True)
        RB._run = orig_run
        a2 = json.load(open(os.path.join(t.work, "ablation.json")))
        ax = a2["axes"].get(axis_p) or {}
        check("ablate --ablate-pyre: rc 0 with cond_B results -> issues / links_lowered_real / pyre_rc / pyre_seconds recorded, stage done",
              ok and t.done("ablate") and ax.get("pyre_rc") == 0 and ax.get("pyre_seconds") == 7
              and ax.get("issues") == {"cond_A": 1, "cond_B": 3, "delta": 2} and ax.get("links_lowered_real") == 5
              and ax.get("sink_pairs") == {"cond_A": 1, "cond_B": 2} and a2["complete"] is True and not a2["pyre_errors"]
              and "pyre_error" not in ax and "issues" not in (a2["axes"]["none"] or {}), str(ax))

        # aggregate over fake row.json files (+ a derived row, + a never-started target)
        tv = toolver.tool_version()
        row = {"name": "om_local", "category": "RCE", "outcome": "delta_pos", "issues": {"cond_A": 0, "cond_B": 12, "delta": 12},
               "sink_pairs": {"key": RB.SINK_PAIR_KEY, "cond_A": 0, "cond_B": 12, "new": ["a"] * 12, "lost": []},
               "links": {"walls_detected": 20, "walls_rejected": 8, "walls_lowered": 5, "links_lowered": 30,
                         "links_unreasonable": 90, "links_phantom": 0}, "residual": {"raw": 0, "net": 0},
               "pyre_seconds": {"cond_A": 345, "cond_B": 379}, "draft_walls": 20, "draft_accepted": 12,
               "accepted_by_tier": {"T1": 7, "none": 5},
               "review_edits": {"accept_flips": 0, "minutes": None}, "tool_version": tv, "plan_tool_version": tv, "versions_match": True}
        json.dump(row, open(os.path.join(t.work, "row.json"), "w"))
        os.makedirs(os.path.join(work, "om_derived", "abl", "draft"), exist_ok=True)
        # review C1: a residual netted through a pre-C1 (basename-keyed) links.json is flagged, not hidden
        # review C2: a row written under the old first-hop key (no sink_pairs.key) is flagged, not hidden
        drow = dict(row, name="om_derived", outcome="no_candidates", outcome_reason="phantom_majority", dataset_reference_issues=7,
                    plan_tool_version=dict(tv, combined="0" * 64), versions_match=False,
                    sink_pairs={"cond_A": 0, "cond_B": 12, "new": ["a"] * 12, "lost": []},
                    residual={"raw": 3, "net": 3, "lowered_walls": 1, "generated_excluded": 4, "remapped": 1, "legacy_links": True})
        json.dump(drow, open(os.path.join(work, "om_derived", "row.json"), "w"))
        json.dump({"groups": [{"id": "G0", "wall_files": ["a.py"], "walls": [],
                               "spec": {"wall_positions": [], "dispatch_impl_map": dict(_MERGED_MAP)}}],   # pre-M10 merged map
                   "env": {"catalog_hits": {}}, "anchors": {},
                   "catalog": {"detected": ["autogpt_legacy"], "scores": {"autogpt_legacy": {"score": 3, "decorators": {"command": 1}}}}},
                  open(os.path.join(work, "om_derived", "abl", "draft", "plan.json"), "w"))
        RB.aggregate(work, manifest)
        md = open(os.path.join(work, "summary.md")).read()
        lines = [json.loads(l) for l in open(os.path.join(work, "summary.jsonl"))]
        check("aggregate: one jsonl line per manifest target (pending rows included)",
              len(lines) == len(manifest["targets"]) and [l["name"] for l in lines][-2:] == ["never_started", "om_derived"], str([l["name"] for l in lines]))
        check("aggregate: never-started target is pending", next(l for l in lines if l["name"] == "never_started")["outcome"] == "pending")
        flat = RB._flat(row, tv)
        check("aggregate: walls_lowered from links.walls_lowered, walls_accepted = detected - rejected",
              flat["delta"] == 12 and flat["walls_lowered"] == 5 and flat["walls_accepted"] == 12 and flat["links_lowered"] == 30, str(flat))
        check("aggregate: accepted tiers and versions_match flattened",
              flat["accepted_tier_T1"] == 7 and flat["accepted_tier_none"] == 5 and flat["accepted_tier_T2"] is None and flat["versions_match"] == "yes")
        check("aggregate: a plan from another version -> versions_match no, listed in the footer",
              RB._flat(drow, tv)["versions_match"] == "no" and "differ from the current code: om_derived" in md, md[-400:])
        # review C2/M5 follow-up: a no_sources draft whose cond_B measured 0 -> 0 keeps the
        # environment verdict in the table (vacuous delta0); a real measurement is left alone
        vac = dict(row, outcome="delta0", outcome_reason="", draft_outcome="no_sources",
                   issues={"cond_A": 0, "cond_B": 0, "delta": 0})
        real = dict(row, outcome="delta0", outcome_reason="", draft_outcome="no_sources",
                    issues={"cond_A": 3, "cond_B": 3, "delta": 0})
        check("aggregate: no_sources draft + vacuous 0 -> 0 delta0 -> table outcome no_sources with reason",
              RB._flat(vac, tv)["outcome"] == "no_sources" and "vacuous" in RB._flat(vac, tv)["outcome_reason"]
              and RB._flat(real, tv)["outcome"] == "delta0" and RB._flat(dict(vac, draft_outcome="ok"), tv)["outcome"] == "delta0",
              str((RB._flat(vac, tv)["outcome"], RB._flat(real, tv)["outcome"])))
        check("aggregate (review C1): residual_net stays numeric; a residual netted through a pre-C1 links.json is "
              "flagged in the jsonl (residual_legacy_links) and listed in the footer",
              next(l for l in lines if l["name"] == "om_derived")["residual_net"] == 3
              and next(l for l in lines if l["name"] == "om_derived")["residual_legacy_links"] is True
              and next(l for l in lines if l["name"] == "om_local")["residual_legacy_links"] is False
              and "basename keys; re-run cond_B to confirm): om_derived" in md
              and "residual_legacy_links" not in RB.COLUMNS, md[-500:])
        check("aggregate (review C2): a row.json without the K5 sink-pair key is flagged in the jsonl and the footer, never a column",
              next(l for l in lines if l["name"] == "om_derived")["sink_pairs_legacy_key"] is True
              and next(l for l in lines if l["name"] == "om_local")["sink_pairs_legacy_key"] is False
              and "issue callable) key (re-run --stage row --force): om_derived" in md
              and "sink_pairs_legacy_key" not in RB.COLUMNS, md[-700:])
        check("aggregate: derived rows in their own table, counted separately, dataset column blanked",
              "## derived rows" in md and "- TaintP2X targets (4): " in md and "- derived rows (1): no_candidates: 1" in md
              and next(l for l in lines if l["name"] == "om_derived")["dataset_ref_issues_whole_repo"] is None
              and next(l for l in lines if l["name"] == "om_derived")["derived_from"] == "om_local", md[-900:])
        check("aggregate: markdown main table + outcome counts", "| om_local |" in md and "delta_pos: 1" in md and "env_failed: 1" in md
              and "pending: 1" in md, md[-300:])
        check("aggregate: framework table — explicit preset kept, decorator-only detection is (none)",
              "| openmanus | 1 |" in md and "| (none) | 1 |" in md and "om_derived" in md.split("| (none) | 1 |")[1].split("\n")[0], md)
        m10_line = next((ln for ln in md.splitlines() if ln.startswith(RB.M10_FOOTER_PREFIX)), "")
        check("aggregate (review M10): a plan carrying the pre-fix merged impl map is flagged in the jsonl (impl_map_stale) "
              "and listed in the footer, never a column; a plan whose map is the catalogue fold of its frameworks is False, "
              "a target without a plan None",
              "call_tool" in (next(l for l in lines if l["name"] == "om_derived")["impl_map_stale"] or "")
              and next(l for l in lines if l["name"] == "om_local")["impl_map_stale"] is False
              and next(l for l in lines if l["name"] == "never_started")["impl_map_stale"] is None
              and m10_line.endswith("): om_derived") and "impl_map_stale" not in RB.COLUMNS,
              str((next(l for l in lines if l["name"] == "om_derived")["impl_map_stale"],
                   next(l for l in lines if l["name"] == "om_local")["impl_map_stale"], m10_line[-120:])))
        check("aggregate (review M10): the explicit preset reaches the check — manifest preset, else --preset in draft_args",
              RB._preset_name({"preset": "vanna"}) == "vanna" and RB._preset_name({"draft_args": "--preset superagi --include-proposed"}) == "superagi"
              and RB._preset_name({}) == "" and RB._preset_name({"draft_args": "--preset"}) == "")
        presets = RB._load_presets()
        lc = {"top": "langchain", "detected": ["langchain", "llama_index"],
              "scores": {"langchain": {"score": 1305, "imports": {"langchain": 1305}}, "llama_index": {"score": 159, "imports": {"llama_index": 159}}}}
        mg = {"detected": ["semantic_kernel", "langchain"],          # MetaGPT-0.6.3's evidence: 9 SK / 8 langchain imports in 170 files
              "scores": {"semantic_kernel": {"score": 9, "imports": {"semantic_kernel": 9}},
                         "langchain": {"score": 8, "imports": {"langchain": 6, "langchain_core": 2}}}}
        check("framework: a version-2 plan's catalog.top is the attribution when its score reaches the threshold; explicit preset first; top None -> (none)",
              RB._framework_of({"catalog": lc}, {}, presets) == "langchain"
              and RB._framework_of({"catalog": {"top": None, "detected": ["autogpt_legacy"],
                                                "scores": {"autogpt_legacy": {"score": 99, "imports": {"autogpt": 99}}}}}, {}, presets) == "(none)"
              and RB._framework_of({"catalog": lc}, {"preset": "vanna"}, presets) == "vanna")
        check("framework (review M4 repair): the score threshold applies to version-2 plans too — MetaGPT's evidence is (none) as a "
              "version-1 plan AND as a version-2 plan with top semantic_kernel (score 9 < FW_MIN_SCORE 20); a top without a score is (none)",
              RB._framework_of({"catalog": mg}, {}, presets) == "(none)"
              and RB._framework_of({"catalog": dict(mg, top="semantic_kernel")}, {}, presets) == "(none)"
              and RB._framework_of({"catalog": {"top": "langchain", "detected": ["langchain"]}}, {}, presets) == "(none)"
              and RB.FW_MIN_SCORE == 20 and "match.min_score, default 20" in md,
              str((RB._framework_of({"catalog": mg}, {}, presets), RB._framework_of({"catalog": dict(mg, top="semantic_kernel")}, {}, presets))))
        check("aggregate: leave-one-out labelled dry-run links, not stale", "dry-run links (redirector" in md
              and "| om_local |" in md.split("## leave-one-out")[1] and "| om_local | " in md and "plan.json now" not in md, md.split("## leave-one-out")[1][:600])
        plan_text0 = open(plan_path).read()          # the plan the ablation was made against, verbatim
        p = json.load(open(plan_path))
        for g in p["groups"]:
            for w in g["walls"]:
                w["accept"] = False
        json.dump(p, open(plan_path, "w"))
        RB.aggregate(work, manifest)
        md = open(os.path.join(work, "summary.md")).read()
        check("aggregate: leave-one-out marked stale when plan.json no longer matches the 'none' axis",
              "plan.json now 0 / 0" in md, md.split("## leave-one-out")[1][:600])
        # review C3 (repair): a plan re-drafted after the ablation — identical counts, a
        # new created stamp — is another draft; the ablation's recorded plan tells them apart
        abl_path = os.path.join(t.work, "ablation.json")
        a_ok = json.load(open(abl_path))
        p = json.loads(plan_text0)
        json.dump(p, open(plan_path, "w"))
        RB.aggregate(work, manifest)
        md_ = open(os.path.join(work, "summary.md")).read()
        loo = _loo_row(work)
        check("aggregate: accepts restored -> not stale again (control)", "| om_local |" in loo and "plan.json" not in loo
              and "tool version" not in loo, loo[:600])
        p["created"] = "2099-01-01T20:00:00"
        json.dump(p, open(plan_path, "w"))
        RB.aggregate(work, manifest)
        loo = _loo_row(work)
        check("aggregate: plan.json re-drafted with the same counts -> stale (created stamp differs), counts not blamed",
              "plan.json re-drafted 2099-01-01T20:00:00 (ablation used " + a_ok["plan"]["created"] + ")" in loo
              and "plan.json now" not in loo, loo[:700])
        p["created"] = a_ok["plan"]["created"]
        p["tool_version"] = dict(toolver.tool_version(), combined="1" * 64)
        json.dump(p, open(plan_path, "w"))
        RB.aggregate(work, manifest)
        loo = _loo_row(work)
        check("aggregate: plan.json re-made by another tool version (same created stamp) -> stale",
              "plan.json tool version changed since the ablation" in loo and "re-drafted" not in loo, loo[:700])
        p["tool_version"] = toolver.tool_version()
        json.dump(p, open(plan_path, "w"))
        json.dump(dict(a_ok, tool_version=dict(toolver.tool_version(), combined="2" * 64)), open(abl_path, "w"))
        RB.aggregate(work, manifest)
        loo = _loo_row(work)
        check("aggregate: ablation made by another tool version -> 'tool version differs'",
              "| om_local |" in loo and "tool version differs" in loo and "plan.json" not in loo, loo[:700])
        legacy = {k: v for k, v in a_ok["axes"].items()}          # the pre-C3 layout: top-level axes, nothing else
        json.dump(legacy, open(abl_path, "w"))
        RB.aggregate(work, manifest)
        loo = _loo_row(work)
        check("aggregate: legacy ablation.json (top-level axes, no plan / tool version) -> cells shown, "
              "'plan provenance not recorded' and 'no tool version recorded'",
              f"| om_local | {legacy['none']['accepted']} / {legacy['none']['lowered_links']} |" in loo
              and "plan provenance not recorded (re-run --stage ablate --force)" in loo and "no tool version recorded" in loo
              and "plan.json now" not in loo, loo[:700])
        json.dump(a_ok, open(abl_path, "w"))
        check("aggregate: csv written with the columns", os.path.exists(os.path.join(work, "summary.csv"))
              and open(os.path.join(work, "summary.csv")).readline().strip().split(",") == RB.COLUMNS)
    finally:
        RB._run = orig_run
        shutil.rmtree(work, ignore_errors=True)
    published_rows_consistent()
    published_rows_c2()
    published_rows_c7()
    docs_manifest_shape()
    published_rows_m6_m11()
    published_plans_m10()
    shell_condB_guard()
    print(f"\n{N - len(FAILS)}/{N} passed" + ("" if not FAILS else f"; FAILED: {FAILS}"))
    return 0 if not FAILS else 1


def _loo_row(work: str, name: str = "om_local") -> str:
    """The leave-one-out table row of ``name`` in work/summary.md ('' when
    absent) — the row only, never the section header (which names every
    staleness reason)."""
    sec = open(os.path.join(work, "summary.md")).read().split("## leave-one-out")[-1].split("## tool version")[0]
    return next((l for l in sec.splitlines() if l.startswith(f"| {name} |")), "")


def _md_cell(md: str, name: str, column: str):
    """The cell ``column`` of the row ``name`` in the first summary.md table
    that holds it (None when the row or the column is absent)."""
    header = None
    for line in md.splitlines():
        if line.startswith("| name |"):
            header = [c.strip() for c in line.strip().strip("|").split("|")]
        elif header and line.startswith(f"| {name} |"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            return cells[header.index(column)] if column in header and len(cells) == len(header) else None
    return None


def published_rows_consistent() -> None:
    """Review C1 (6): the published benchmark_out — the residual the review
    re-measured (langchain-0.0.131) is recorded by post-C1 code (the netting
    keys are present) and the summary table / jsonl repeat what the row.json
    files say. Skipped when the evidence directory is not checked out."""
    work = os.path.join(RB.ROOT, "benchmark_out")
    md_path, jl_path = os.path.join(work, "summary.md"), os.path.join(work, "summary.jsonl")
    if not (os.path.exists(md_path) and os.path.exists(jl_path)):
        print("SKIP published rows: benchmark_out/summary.{md,jsonl} not present")
        return
    md = open(md_path).read()
    flat = {json.loads(l)["name"]: json.loads(l) for l in open(jl_path) if l.strip()}
    keys = ("raw", "net", "lowered_walls", "generated_excluded", "remapped", "legacy_links")
    name = "langchain-0.0.131"
    top, abl = os.path.join(work, name, "row.json"), os.path.join(work, name, "abl", "row.json")
    if os.path.exists(top) and os.path.exists(abl):
        r, ra = json.load(open(top)), json.load(open(abl))
        res = r.get("residual") or {}
        check(f"published {name}: residual re-measured by post-C1 code (netting keys), abl/row.json == row.json, "
              "residual_rows lists the net walls, net <= raw",
              all(k in res for k in keys) and res == (ra.get("residual") or {})
              and len(r.get("residual_rows") or []) == res.get("net") and res["net"] <= res["raw"]
              and r.get("tool_version") and r["tool_version"] == ra.get("tool_version"), str(res))
        check(f"published {name}: summary.md / summary.jsonl residual_net repeat row.json (legacy links flagged)",
              _md_cell(md, name, "residual_net") == str(res.get("net"))
              and flat.get(name, {}).get("residual_net") == res.get("net")
              and flat.get(name, {}).get("residual_legacy_links") == bool(res.get("legacy_links"))
              and (name in md.split("re-run cond_B to confirm):")[-1].split("\n")[0]) == bool(res.get("legacy_links")),
              str((_md_cell(md, name, "residual_net"), flat.get(name, {}).get("residual_net"))))
    else:
        print(f"SKIP published rows: {name} row.json / abl/row.json not present")
    # every published row: the table repeats its row.json (residual_net, outcome)
    bad = []
    for n, fl in flat.items():
        rj = os.path.join(work, n, "row.json")
        if not os.path.exists(rj):
            continue
        r = json.load(open(rj))
        want = (r.get("residual") or {}).get("net") if r.get("residual") else None
        # the table outcome is row.json's outcome after the environment-verdict precedence
        # (a no_sources draft measured 0 -> 0 keeps no_sources; see run_benchmark._table_outcome)
        want_outcome = RB._table_outcome(r)[0]
        if fl.get("residual_net") != want or _md_cell(md, n, "residual_net") != ("" if want is None else str(want)) \
                or (want_outcome and fl.get("outcome") != want_outcome):
            bad.append((n, want, fl.get("residual_net"), _md_cell(md, n, "residual_net"), want_outcome, fl.get("outcome")))
    check("published rows: summary.{md,jsonl} residual_net / outcome repeat every row.json", not bad, str(bad))


def published_rows_c2() -> None:
    """Review C2 (fix items 2-3): the published benchmark_out rows embody the
    K5 definition, not the old one — every row.json (top-level and abl/) keys
    its sink pairs by (sink kind, issue callable), carries the first-hop
    diagnostics and the classifier inputs its outcome re-derives from
    (delta_pos never hides a lost pair; no_walls only when the draft accepted
    0; no_candidates only for accepted > 0 with nothing lowered) — and the
    summary's cells, outcome counts and footer repeat them. Skipped when the
    evidence directory is not checked out."""
    work = os.path.join(RB.ROOT, "benchmark_out")
    md_path, jl_path = os.path.join(work, "summary.md"), os.path.join(work, "summary.jsonl")
    if not (os.path.exists(md_path) and os.path.exists(jl_path)):
        print("SKIP published rows (C2): benchmark_out/summary.{md,jsonl} not present")
        return
    md = open(md_path).read()
    flat = {json.loads(l)["name"]: json.loads(l) for l in open(jl_path) if l.strip()}
    bad, seen = [], 0
    for n, fl in flat.items():
        if not os.path.exists(os.path.join(work, n, "row.json")):      # never published by the runner (condB unfinished)
            continue
        for rj in (os.path.join(work, n, "row.json"), os.path.join(work, n, "abl", "row.json")):
            if not os.path.exists(rj):
                continue
            r = json.load(open(rj))
            if r.get("issues") is None:                    # no cond_A results: nothing was classified
                if r.get("outcome") != "env_failed":
                    bad.append((n, "no issues but outcome", r.get("outcome")))
                continue
            seen += 1
            sp, inp = r.get("sink_pairs") or {}, r.get("outcome_inputs")
            if sp.get("key") != RB.SINK_PAIR_KEY or "first_hops" not in r or not inp:
                bad.append((n, os.path.basename(os.path.dirname(rj)), "pre-K5 row", sp.get("key")))
                continue
            new, lost = len(sp.get("new") or []), len(sp.get("lost") or [])
            o = r.get("outcome")
            if H.classify_outcome(**inp)[0] != o or (inp["new"], inp["lost"]) != (new, lost):
                bad.append((n, "outcome not re-derivable", inp, o, new, lost))
            if (o == "delta_pos" and lost) or (o == "no_walls" and inp["accepted"]) \
                    or (o == "no_candidates" and (not inp["accepted"] or inp["links_lowered"])) \
                    or (o.startswith("delta") and not inp["links_lowered"]):
                bad.append((n, "K5 invariant", o, inp))
            if rj.endswith(os.path.join(n, "row.json")) and (fl.get("sinks_A"), fl.get("sinks_B"), fl.get("sinks_new"), fl.get("sinks_lost")) \
                    != (sp.get("cond_A"), sp.get("cond_B"), new if sp.get("cond_B") is not None else None,
                        lost if sp.get("cond_B") is not None else None):
                bad.append((n, "summary sinks", fl.get("sinks_A"), fl.get("sinks_B"), fl.get("sinks_new"), fl.get("sinks_lost"), sp))
    check(f"published rows (review C2): the {seen} classified row.json files use the K5 key, re-derive their outcome "
          "from the recorded inputs and the summary repeats their sink columns", seen > 0 and not bad, str(bad[:6]))
    main_rows = [fl for fl in flat.values() if not fl.get("derived_from")]
    derived = [fl for fl in flat.values() if fl.get("derived_from")]
    check("published summary (review C2): the outcome counts are those of the jsonl rows; no row predates the K5 key",
          f"- TaintP2X targets ({len(main_rows)}): {RB._outcome_counts(main_rows)}" in md
          and (not derived or f"- derived rows ({len(derived)}): {RB._outcome_counts(derived)}" in md)
          and "(re-run --stage row --force): (none)" in md,
          md.split("## outcomes")[-1][:400])


def published_rows_c7() -> None:
    """Review C7 (fix items 2-3): the published summary is made by the
    versioned aggregate — it carries the versions_match column and the tool
    version footer; every published row.json records its tool_version; a row
    whose plan predates the fingerprint (plan_tool_version null) shows 'plan
    unversioned' and is listed in the footer's re-draft line, a versioned row
    shows yes / no and is listed in the mismatch line exactly when 'no'; the
    jsonl repeats the cell. Skipped when the evidence directory is not
    checked out."""
    work = os.path.join(RB.ROOT, "benchmark_out")
    md_path, jl_path = os.path.join(work, "summary.md"), os.path.join(work, "summary.jsonl")
    if not (os.path.exists(md_path) and os.path.exists(jl_path)):
        print("SKIP published rows (C7): benchmark_out/summary.{md,jsonl} not present")
        return
    md = open(md_path).read()
    flat = {json.loads(l)["name"]: json.loads(l) for l in open(jl_path) if l.strip()}
    foot = md.split("## tool version")[-1] if "## tool version" in md else ""
    def names(key):
        """The target names a footer line lists after its last '):' (exact tokens, never substrings)."""
        tail = next((l for l in foot.splitlines() if key in l), "").split("):")[-1]
        return {x.strip() for x in tail.split(",") if x.strip()}
    unversioned, mismatch = names("predates the fingerprint"), names("differ from the current code")
    check("published summary (review C7): versions_match column and the tool version footer are present",
          "versions_match" in md.split("\n|---")[0] and "- current: " in foot
          and any("predates the fingerprint" in l for l in foot.splitlines())
          and any("differ from the current code" in l for l in foot.splitlines()), foot[:300])
    bad, seen = [], 0
    for n, fl in flat.items():
        rj = os.path.join(work, n, "row.json")
        if not os.path.exists(rj):
            continue
        r = json.load(open(rj))
        cell = _md_cell(md, n, "versions_match")
        seen += 1
        if not r.get("tool_version"):
            bad.append((n, "row.json without tool_version"))
        if r.get("plan_tool_version") is None:
            if cell != "plan unversioned" or n not in unversioned or r.get("versions_match") is not None:
                bad.append((n, "unversioned plan", cell, r.get("versions_match")))
        elif cell not in ("yes", "no") or (cell == "no") != (n in mismatch) or n in unversioned:
            bad.append((n, "versioned plan", cell))
        if fl.get("versions_match") != cell:
            bad.append((n, "jsonl", fl.get("versions_match"), cell))
    check(f"published rows (review C7): the {seen} published row.json files record tool_version and the summary "
          "shows each as plan unversioned / yes / no consistently with its plan_tool_version and the footer",
          seen > 0 and not bad, str(bad[:6]))


def published_plans_m10() -> None:
    """Review M10 (repair): the published summary names every benchmark_out
    plan whose ``dispatch_impl_map`` is not the catalogue fold of its own
    frameworks (a pre-fix merged all-framework map, or no map) — in the jsonl
    (``impl_map_stale``) and in the footer — so a row made from such a plan is
    never cited as current. The list is recomputed here from the plans
    themselves (``catalog.impl_map_stale`` on plan.draft.json / plan.json)
    and must agree with what summary.{md,jsonl} say. Skipped without the
    evidence directory."""
    work = os.path.join(RB.ROOT, "benchmark_out")
    md_path, jl_path = os.path.join(work, "summary.md"), os.path.join(work, "summary.jsonl")
    if not (os.path.exists(md_path) and os.path.exists(jl_path)):
        print("SKIP published plans (M10): benchmark_out/summary.{md,jsonl} not present")
        return
    m, _, _ = _manifest_shape()
    presets = RB._load_presets()
    want, checked = {}, 0
    for t in m["targets"]:
        why = RB._impl_map_stale(work, t, presets)
        if why is None:
            continue
        checked += 1
        if why:
            want[t["name"]] = why
    md = open(md_path).read()
    lines = [json.loads(l) for l in open(jl_path) if l.strip()]
    got = {l["name"]: l.get("impl_map_stale") for l in lines}
    footer = next((ln for ln in md.splitlines() if ln.startswith(RB.M10_FOOTER_PREFIX)), "")
    tail = footer.rsplit("): ", 1)[-1] if footer else ""
    listed = set() if (not footer or tail.strip() == "(none)") else {x.strip() for x in tail.split(",") if x.strip()}
    bad = [(n, "jsonl", got.get(n), n in want) for n in got if bool(got.get(n)) != (n in want)]
    bad += [(n, "footer") for n in set(want) ^ listed]
    check(f"published plans (review M10): summary.md footer + summary.jsonl name exactly the {len(want)} of {checked} "
          "published plans whose dispatch_impl_map predates the framework-restricted fold (recomputed from the plans)",
          bool(footer) and checked > 0 and not bad, str(bad[:6]))
    if want:
        print(f"INFO published plans (review M10): {len(want)} of {checked} plans still carry a pre-fix impl map and "
              "must be re-drafted (--stage all --from draft --force --keep-cond-a --accept-draft) before their rows are cited: "
              + ", ".join(sorted(want)))


# review M5: the tiny target the shell guard test lowers -- test_pipeline.py's
# fixture (a @tool registry read by ``REGISTRY[name](args)``): the plan pins the
# one wall, the lowering produces 2 links, so cmd_row's outcome is decided by
# cond_B's results (measured) and not by the draft verdict
_SH_TOOLS = "def tool(fn):\n    return fn\n\n\n@tool\ndef run_shell(cmd):\n    return cmd\n\n\n@tool\ndef echo(msg):\n    return msg\n\n\n" \
            "REGISTRY = {\"shell\": run_shell, \"echo\": echo}\n"
_SH_APP = "from tools import REGISTRY\n\n\ndef llm_decide(prompt):\n    return prompt, prompt\n\n\ndef agent(prompt):\n" \
          "    name, args = llm_decide(prompt)\n    result = REGISTRY[name](args)\n    return result\n"
_SH_PLAN = {"version": 1, "created": "2026-08-30T00:00:00", "outcome": "ok", "counts": {"walls": 1, "accepted": 1},
            "groups": [{"id": "G0", "wall_files": ["app.py"], "accepted": 1,
                        "spec": {"tool_decorators": ["tool"], "registry_vars": ["REGISTRY"], "detect_subscript": False,
                                 "detect_getattr": False, "detect_higher_order": False,
                                 "wall_positions": [{"at": "app.py:10:13", "callee": "REGISTRY[name]", "accept": True,
                                                     "origin": "engine", "engine_status": "unresolved:UnknownCallCallee"}]},
                        "walls": [{"id": "E0", "position": "app.py:10:13", "file": "app.py", "line": 10, "col": 13,
                                   "callee": "REGISTRY[name]", "accept": True, "engine_status": "unresolved:UnknownCallCallee",
                                   "engine_tier": "T1", "origin": "engine", "confidence": "confirmed", "dry_run": {"lowered": 2}}]}],
            "env": {"catalog_hits": {}}, "catalog": {"detected": [], "scores": {}}, "anchors": {"counts": {}},
            "review": {"minutes": None, "notes": ""}}
# the stub ``pyre``: cond_A gets an empty result set, cond_B "times out" (exit 124 -- what
# ``timeout`` returns -- and no r/taint-output.json)
_SH_PYRE = """#!/usr/bin/env bash
# stub pyre (test_benchmark.py shell_condB_guard, review M5): decides by the cond dir it runs in
case "$(basename "$PWD")" in
  cond_A) mkdir -p r && printf '[]\\n' > r/taint-output.json; echo "stub pyre: cond_A ok"; exit 0 ;;
  *) echo "stub pyre: cond_B timing out"; exit 124 ;;
esac
"""


def shell_condB_guard(script: str = "") -> None:
    """Review M5 (shell level): the real run_ablation.sh is run past the draft
    stop (PLAN_JSON route, no DRAFT) with a stub ``pyre`` first on PATH -- the
    cond_A invocation writes an empty taint-output.json, the cond_B invocation
    exits 124 without one. Covered: run_pyre's bookkeeping on rc 124
    (pyre_seconds / pyre_rc), the ``require_output "$WORK/cond_B"`` guard (row
    written as env_failed, the guard's message, non-zero exit, no RESULT /
    delta line -- the script used to print "cond_B issues = 0" and exit 0). Not
    covered: a real pyre timeout (the stub returns 124 the way ``timeout`` does)
    and the draft route (the pipeline / cmd_row side is covered by the stubbed
    _run tests in main). ``script`` names another copy of run_ablation.sh (the
    mutant check); ROOT / EXT / HELP are passed explicitly so a copy outside
    the tree resolves them."""
    import subprocess
    script = script or os.path.join(M2, "run_ablation.sh")
    if not (shutil.which("bash") and shutil.which("timeout")):
        print("SKIP shell cond_B guard (review M5): bash / timeout not available")
        return
    work = tempfile.mkdtemp(prefix="bench_sh_")
    try:
        target = os.path.join(work, "target")
        _touch(os.path.join(target, "tools.py"), _SH_TOOLS)
        _touch(os.path.join(target, "app.py"), _SH_APP)
        plan = os.path.join(work, "plan.json")
        json.dump(_SH_PLAN, open(_touch(plan) or plan, "w"), indent=2)
        models = os.path.join(work, "target.pysa")
        _touch(models, "# stub models (the stub pyre never reads them)\n")
        tp2x, typeshed = os.path.join(work, "tp2x"), os.path.join(work, "typeshed")
        for d in (os.path.join(tp2x, "taint"), os.path.join(tp2x, "stubs"), typeshed):
            os.makedirs(d, exist_ok=True)
        stub = os.path.join(work, "bin", "pyre")
        _touch(stub, _SH_PYRE)
        os.chmod(stub, 0o755)
        abl = os.path.join(work, "abl")
        env = dict(os.environ, PATH=os.path.join(work, "bin") + os.pathsep + os.environ.get("PATH", ""),
                   ROOT=RB.ROOT, EXT=HERE, HELP=os.path.join(M2, "ablation_helpers.py"), TP2X=tp2x, TYPESHED=typeshed,
                   TARGET_SRC=target, PYSA_MODELS=models, PLAN_JSON=plan, WORK=abl, PYRE_TIMEOUT="5",
                   PYRE_SEARCH_VENV="0", EMIT="inline")
        for k in ("DRAFT", "ACCEPT_DRAFT", "DRAFT_ARGS", "FORCE_DRAFT", "WALL_FILES", "SPEC_JSON", "LINKS_IN", "CAND_DIR",
                  "REUSE_COND_A", "EXPECT_A", "EXPECT_B", "EXPECT_SINKS_B", "DATASET_DIR"):
            env.pop(k, None)
        p = subprocess.run(["bash", script], cwd=M2, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=300)
        log = p.stdout or ""
        row_path = os.path.join(abl, "row.json")
        row = json.load(open(row_path)) if os.path.exists(row_path) else {}
        rc_b = os.path.join(abl, "cond_B", "pyre_rc")
        secs_b = os.path.join(abl, "cond_B", "pyre_seconds")
        tail = "\n".join(log.splitlines()[-25:])
        check("shell (review M5): cond_A passes its guard with the stub pyre (issues = 0) and cond_B is lowered (2 links)",
              "cond_A issues = 0" in log and "=== 5. analyze cond_B ===" in log
              and (row.get("links") or {}).get("links_lowered") == 2, tail)
        check("shell (review M5): run_pyre bookkeeping on a timed-out cond_B -- pyre_rc 124, pyre_seconds written, no taint-output.json",
              RB._int_file(rc_b) == 124 and RB._int_file(secs_b) is not None
              and not os.path.exists(os.path.join(abl, "cond_B", "r", "taint-output.json")),
              str((RB._int_file(rc_b), RB._int_file(secs_b))))
        check("shell (review M5): the cond_B guard exits non-zero with its message (timed out, PYRE_TIMEOUT, env_failed)",
              p.returncode != 0 and "cond_B analysis produced no taint-output.json" in log
              and "pyre timed out (PYRE_TIMEOUT=5s)" in log and "env_failed" in log, f"rc={p.returncode}\n{tail}")
        check("shell (review M5): abl/row.json says env_failed (cond_B lowered, no results), pyre_seconds.cond_B recorded",
              row.get("outcome") == "env_failed" and (row.get("outcome_inputs") or {}).get("has_b") is False
              and (row.get("outcome_inputs") or {}).get("links_lowered") == 2
              and (row.get("pyre_seconds") or {}).get("cond_B") is not None, str(row.get("outcome_inputs")))
        check("shell (review M5): no 'cond_B issues = 0', no RESULT / delta line after the guard",
              "cond_B issues =" not in log and "delta from wall resolution" not in log and "=== RESULT ===" not in log, tail)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _manifest_shape() -> tuple:
    """(manifest, non-derived names, derived names) of the real benchmark.json."""
    m = json.load(open(os.path.join(HERE, "benchmark.json")))
    return (m, [t["name"] for t in m["targets"] if not t.get("derived")],
            [t["name"] for t in m["targets"] if t.get("derived")])


def docs_manifest_shape() -> None:
    """Review M11 (docs): README / RESEARCH_DIRECTION / SCALE_OUT_DESIGN state
    the manifest as the runner has it — N TaintP2X targets + M derived rows
    (N + M manifest rows), the counts taken from benchmark.json — and no
    longer describe an N-row manifest / a batch of N targets; the README also
    documents walls_accepted vs walls_lowered and the pending rows (review M6)."""
    import re
    m, main_, derived = _manifest_shape()
    n, d, total = len(main_), len(derived), len(m["targets"])
    check("manifest (review M11): the derived rows name a non-derived manifest target as derived_from",
          d > 0 and total == n + d and all(t.get("derived_from") in main_ for t in m["targets"] if t.get("derived")))
    docs = [os.path.join(os.path.dirname(HERE), p) for p in ("README.md", "RESEARCH_DIRECTION.md", os.path.join("docs", "SCALE_OUT_DESIGN.md"))]
    # "N ... M derived" / "N ... 派生 M" within one statement; the total next to manifest / rows
    pair = re.compile(rf"\b{n}\b\D{{0,80}}?(?:\b{d}\b\s*(?:derived|派生)|(?:derived|派生)\s*{d}\b)")
    tot = re.compile(rf"\b{total}\b[^\n]{{0,40}}(?:manifest|マニフェスト|rows|行)")
    stale = re.compile(rf"the {n} (?:TaintP2X )?Benchmark targets:|all {n},|{n} 行のマニフェスト|マニフェスト {n} 行|"
                       rf"{n} 対象のバッチ|{n} 対象を無人|{n} 件のレビュー")
    bad = []
    for path in docs:
        base = os.path.relpath(path, os.path.dirname(HERE))
        if not os.path.exists(path):
            bad.append((base, "missing"))
            continue
        txt = open(path, encoding="utf-8").read()
        if not pair.search(txt):
            bad.append((base, f"no '{n} targets + {d} derived' statement"))
        if not tot.search(txt):
            bad.append((base, f"{total} manifest rows not stated"))
        hit = stale.search(txt)
        if hit:
            bad.append((base, "stale wording", hit.group(0)))
    check(f"docs (review M11): README / RESEARCH_DIRECTION / SCALE_OUT_DESIGN state {n} targets + {d} derived rows "
          f"({total} manifest rows) and drop the '{n}-row manifest' wording", not bad, str(bad))
    readme = open(docs[0], encoding="utf-8").read()
    check("docs (review M6 / M11): README documents walls_accepted vs walls_lowered as separate summary columns and the pending rows",
          "walls_accepted" in readme and "walls_lowered" in readme and "`pending`" in readme)


def published_rows_m6_m11() -> None:
    """Review M6 / M11: the published benchmark_out summary is the current
    aggregate's — its header counts the manifest (N TaintP2X targets + M
    derived rows), the jsonl has one row per manifest entry in manifest order
    (a target never started is pending, the derived rows sit in their own
    table), and walls_lowered — in every published row.json, the jsonl and
    the md cell — is the number of distinct walls with a lowered link in
    cond_B/links.json (ablation_helpers._lowered_walls), never the accept
    count (walls_accepted), which it can never exceed. Skipped when the
    evidence directory is not checked out."""
    work = os.path.join(RB.ROOT, "benchmark_out")
    md_path, jl_path = os.path.join(work, "summary.md"), os.path.join(work, "summary.jsonl")
    if not (os.path.exists(md_path) and os.path.exists(jl_path)):
        print("SKIP published rows (M6 / M11): benchmark_out/summary.{md,jsonl} not present")
        return
    m, main_, derived = _manifest_shape()
    md = open(md_path).read()
    lines = [json.loads(l) for l in open(jl_path) if l.strip()]

    def table_names(section: str) -> list:
        return [l.split("|")[1].strip() for l in section.splitlines()
                if l.startswith("| ") and not l.startswith("| name |") and not l.startswith("|---")]
    main_sec = md.split("## TaintP2X targets")[-1].split("\n## ")[0] if "## TaintP2X targets" in md else ""
    der_sec = md.split("## derived rows")[-1].split("\n## ")[0] if "## derived rows" in md else ""
    never_started = [l["name"] for l in lines if not os.path.exists(os.path.join(work, l["name"], "state.json"))]
    check("published summary (review M11): header = manifest counts, one jsonl row per manifest entry in manifest order, "
          "never-started targets pending, main and derived tables hold exactly the manifest's rows",
          f"{len(main_)} TaintP2X targets + {len(derived)} derived rows ({len(m['targets'])} manifest rows)" in md
          and [l["name"] for l in lines] == main_ + derived
          and all(l["outcome"] == "pending" for l in lines if l["name"] in never_started)
          and table_names(main_sec) == main_ and table_names(der_sec) == derived
          and f"- TaintP2X targets ({len(main_)}): " in md and f"- derived rows ({len(derived)}): " in md,
          str(([l["name"] for l in lines], never_started, table_names(main_sec)[:3], table_names(der_sec))))
    bad, seen = [], 0
    for l in lines:
        n = l["name"]
        rj = os.path.join(work, n, "row.json")
        if not os.path.exists(rj):
            continue
        r = json.load(open(rj))
        st = r.get("links") or {}
        if "walls_lowered" not in st:
            bad.append((n, "row.json links without walls_lowered (pre-M6 row)"))
            continue
        seen += 1
        lk = os.path.join(work, n, "abl", "cond_B", "links.json")
        want = H._lowered_walls(lk) if os.path.exists(lk) else None
        cell = _md_cell(md, n, "walls_lowered")
        if st["walls_lowered"] != want or l.get("walls_lowered") != want or cell != ("" if want is None else str(want)):
            bad.append((n, "walls_lowered", st.get("walls_lowered"), l.get("walls_lowered"), cell, want))
        acc = l.get("walls_accepted")
        if want is not None and (acc is None or want > acc):
            bad.append((n, "walls_lowered exceeds walls_accepted", want, acc))
        if l.get("outcome") == "no_candidates" and (want or l.get("links_lowered")):
            bad.append((n, "no_candidates with lowered walls / links", want, l.get("links_lowered")))
        if str(l.get("outcome") or "").startswith("delta") and not want:
            bad.append((n, "delta outcome without a lowered wall", want))
    check(f"published rows (review M6): the {seen} published row.json files carry links.walls_lowered = walls with a "
          "lowered link in cond_B/links.json, the summary repeats it, and it never exceeds walls_accepted",
          seen > 0 and not bad, str(bad[:6]))


if __name__ == "__main__":
    sys.exit(main())
