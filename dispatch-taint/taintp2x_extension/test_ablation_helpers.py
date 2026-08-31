"""Tests for taintp2x_m2_verification/ablation_helpers.py — the row.json
writer (``cmd_row``) on fake work dirs in a temp directory, no pyre
(review C2 / C7 / M5 / M6, contracts K4 / K5).

    python3 test_ablation_helpers.py
"""
from __future__ import annotations

import contextlib
import io
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
os.environ["EXT"] = HERE

import ablation_helpers as H   # noqa: E402
import run_benchmark as RB     # noqa: E402  (the aggregate's SINK_PAIR_KEY must be the row's)
import toolver                 # noqa: E402

FAILS: list = []
N = 0


def check(label, cond, detail=""):
    global N
    N += 1
    print(("PASS " if cond else "FAIL ") + label + ("" if cond or not detail else f": {detail}"))
    if not cond:
        FAILS.append(label)


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
def issue(callable_, kind="ExecArgSink", hop=("m.sink",), code=5005, line=1):
    """One Pysa issue record: the sink kind on the backward root, the first
    hop (``resolves_to``) of that root, and the callable the issue is in."""
    return {"kind": "issue", "data": {
        "callable": callable_, "code": code, "line": line, "filename": "src/x.py",
        "traces": [{"name": "forward", "roots": [{"kinds": [{"kind": "LLMControlled"}]}]},
                   {"name": "backward", "roots": [{"kinds": [{"kind": kind}],
                                                   "call": {"resolves_to": list(hop)}}]}]}}


def write_taint(path, issues):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("[\n" + ",\n".join(json.dumps(i) for i in issues) + "\n]\n")


def plan(walls, outcome="ok", tool_version=None, created="2026-08-30T00:00:00", counts_extra=None):
    """walls: [(position, accept, tier)] in one group."""
    rows = []
    for i, (pos, acc, tier) in enumerate(walls):
        f, ln, col = pos.split(":")
        rows.append({"id": f"E{i}", "position": pos, "file": f, "line": int(ln), "col": int(col), "callee": "t.run",
                     "accept": bool(acc), "engine_status": "unresolved:UnknownCallCallee", "engine_tier": tier,
                     "origin": "engine", "confidence": "confirmed" if acc else "proposed"})
    p = {"version": 1, "created": created, "outcome": outcome,
         "counts": dict({"walls": len(rows), "accepted": sum(1 for r in rows if r["accept"])}, **(counts_extra or {})),
         "groups": [{"id": "G0", "wall_files": ["a.py"],
                     "spec": {"tool_decorators": ["tool"], "wall_positions": [], "_provenance": {}},
                     "walls": rows, "stages": None, "accepted": sum(1 for r in rows if r["accept"])}] if rows else [],
         "env": {"outcome": outcome, "catalog_hits": {}, "env_gaps": 1, "unresolved_by_reason": {"UnknownCallCallee": 2}},
         "review": {"minutes": None, "notes": ""}, "ablation": {"disabled": []}}
    if tool_version is not None:
        p["tool_version"] = tool_version
    return p


def stats(lowered=0, built=None, phantom=0, unreasonable=0, filtered=0, no_args=0, detected=2, rejected=0):
    built = (lowered + phantom + unreasonable + filtered + no_args) if built is None else built
    return {"files": 1, "walls_detected": detected, "walls_rejected": rejected, "walls_unmatched": 0,
            "walls_skipped_no_args": 0, "candidates_total": built, "links_built": built, "links_lowered": lowered,
            "links_filtered_registry": filtered, "links_filtered_level": 0, "links_unreasonable": unreasonable,
            "links_no_args": no_args, "links_phantom": phantom, "redirectors": 0, "lines_added": lowered * 3,
            "walls_by_engine_status": {"unresolved": detected}, "walls_by_origin": {"engine": detected}}


def links_json(entries):
    """entries: [(wall_id, status)] -> a links.json body."""
    return {"walls": [{"id": w, "file": "a.py", "line": 1, "end_line": 1, "idiom": "method_call", "callee": "t.run"}
                      for w in sorted({e[0] for e in entries})],
            "links": [{"id": f"L{i}", "wall_id": w, "file": "a.py", "line": 1, "status": st,
                       "target": {"qualname": f"T{i}.run", "module": "m"}} for i, (w, st) in enumerate(entries)]}


def make_work(root, name, issues_a, plan_orig, plan_used=None, issues_b=None, st=None, lk=None,
              draft_original=True, cond_a=True):
    work = os.path.join(root, name)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(os.path.join(work, "draft"), exist_ok=True)
    if cond_a:
        write_taint(os.path.join(work, "cond_A", "r", "taint-output.json"), issues_a)
    if draft_original:
        json.dump(plan_orig, open(os.path.join(work, "draft", "plan.draft.json"), "w"))
    json.dump(plan_used or plan_orig, open(os.path.join(work, "draft", "plan.json"), "w"))
    json.dump(plan_orig["env"], open(os.path.join(work, "draft", "env_report.json"), "w"))
    if plan_used is not None or st is not None or lk is not None or issues_b is not None:
        os.makedirs(os.path.join(work, "cond_B"), exist_ok=True)
        json.dump(plan_used or plan_orig, open(os.path.join(work, "cond_B", "plan.json"), "w"))
    if st is not None:
        json.dump(st, open(os.path.join(work, "cond_B", "stats.json"), "w"))
    if lk is not None:
        json.dump(lk, open(os.path.join(work, "cond_B", "links.json"), "w"))
    if issues_b is not None:
        write_taint(os.path.join(work, "cond_B", "r", "taint-output.json"), issues_b)
    return work


def row_of(work):
    out = os.path.join(work, "row.json")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = H.cmd_row(work, out)
    assert rc == 0, buf.getvalue()
    return json.load(open(out))


# --------------------------------------------------------------------------- #
def main() -> int:
    root = tempfile.mkdtemp(prefix="abh_")
    try:
        A = [issue("m.Agent.run", "ExecArgSink", ("m.exec",)), issue("m.Agent.run", "SQLSink", ("m.exec",)),
             issue("m.Chain.call", "ExecArgSink", ("m.other",))]
        NEW = issue("m.Tool.execute", "ExecArgSink", ("m.exec",))
        two = [("a.py:3:4", True, "T1"), ("a.py:9:4", True, "none")]
        lk2 = links_json([("G0W0", "lowered"), ("G0W0", "lowered"), ("G0W1", "lowered"), ("G0W1", "unreasonable")])

        # --- sink pairs: (sink kind, issue callable); first hop only diagnostics (C2 / K5)
        data = lambda xs: [x["data"] for x in xs]      # _sink_pairs takes what _issues returns  # noqa: E731
        pa = H._sink_pairs(data(A))
        check("sink pairs keyed by (kind, issue callable)", pa == {("ExecArgSink", "m.Agent.run"), ("SQLSink", "m.Agent.run"),
                                                                    ("ExecArgSink", "m.Chain.call")}, str(pa))
        A_hop = [issue("m.Agent.run", "ExecArgSink", ("m.exec", "m.exec2")), issue("m.Agent.run", "SQLSink", ("m.exec",)),
                 issue("m.Chain.call", "ExecArgSink", ())]
        check("a changed first hop does not change the pair set", H._sink_pairs(data(A_hop)) == pa)
        hops = H._sink_first_hops(data(A_hop))
        check("first hops: whole resolves_to set, <direct> when empty",
              ("ExecArgSink", "m.exec | m.exec2") in hops and ("ExecArgSink", "<direct>") in hops, str(hops))
        buf = io.StringIO()
        p = os.path.join(root, "t.json")
        write_taint(p, A)
        with contextlib.redirect_stdout(buf):
            H.cmd_count(p)
        check("count prints SINK_PAIRS (K5 key) and SINK_FIRST_HOPS (legacy)",
              "SINK_PAIRS=3" in buf.getvalue() and "SINK_FIRST_HOPS=3" in buf.getvalue(), buf.getvalue())

        # --- outcome vocabulary (K5): the draft's verdict first, only while nothing was lowered
        r = row_of(make_work(root, "no_walls", A, plan([("a.py:3:4", False, "T1")], outcome="no_walls")))
        check("draft no_walls (0 accepted, no cond_B) -> no_walls", r["outcome"] == "no_walls", r["outcome"])
        check("draft counts come from plan.draft.json", r["draft_walls"] == 1 and r["draft_accepted"] == 0 and r["draft_source"] == "plan.draft.json")
        check("row carries draft_framework / draft_engine_walls / draft_accepted_by_tier (agent C's keys); residual None without cond_B",
              r["draft_framework"] == "(none)" and r["draft_engine_walls"] is None and r["draft_accepted_by_tier"] == r["accepted_by_tier"]
              and r["residual"] is None and r["residual_rows"] == [],
              str({k: r.get(k) for k in ("draft_framework", "draft_engine_walls", "draft_accepted_by_tier", "residual", "residual_rows")}))
        # review M4 (repair): draft_framework is thresholded like the summary.md table (catalog.framework_of):
        # a version-2 top below FW_MIN_SCORE (MetaGPT: semantic_kernel 9) is (none); above it the preset
        mg_cat = {"top": "semantic_kernel", "detected": ["semantic_kernel"],
                  "scores": {"semantic_kernel": {"score": 9, "imports": {"semantic_kernel": 9}}}}
        lc_cat = {"top": "langchain", "detected": ["langchain"], "scores": {"langchain": {"score": 39, "imports": {"langchain": 39}}}}
        r_mg = row_of(make_work(root, "fw_mg", A, dict(plan([("a.py:3:4", False, "T1")], outcome="no_walls"), catalog=mg_cat)))
        r_lc = row_of(make_work(root, "fw_lc", A, dict(plan([("a.py:3:4", False, "T1")], outcome="no_walls"), catalog=lc_cat)))
        check("draft_framework (review M4 repair): a version-2 top below FW_MIN_SCORE is (none); above it the preset",
              r_mg["draft_framework"] == "(none)" and r_lc["draft_framework"] == "langchain", str((r_mg["draft_framework"], r_lc["draft_framework"])))
        # residual keys (review C1 / K2, agent A's request): a real cond_B excerpt lowered by the
        # current pipeline (r_min/two_walls_before_stub: block inserted BEFORE the wall, stub call
        # below) -> raw 1 / net 0 / generated 2 / remapped 1, as pinned by test_engine_walls
        rm = os.path.join(H._ext_dir(), "r_min", "two_walls_before_stub")
        if os.path.isdir(os.path.join(rm, "cond_B", "r")):
            work = make_work(root, "residual", A, plan(two))
            shutil.copytree(os.path.join(rm, "cond_B"), os.path.join(work, "cond_B"), dirs_exist_ok=True)
            json.dump(plan(two), open(os.path.join(work, "cond_B", "plan.json"), "w"))
            r = row_of(work)
            res = r.get("residual") or {}
            check("residual: row.json carries raw / net / lowered_walls / generated_excluded / remapped / legacy_links (+ rows)",
                  res.get("raw") == 1 and res.get("net") == 0 and res.get("generated_excluded") == 2 and res.get("remapped") == 1
                  and res.get("lowered_walls") == 1 and res.get("legacy_links") is False and isinstance(r.get("residual_rows"), list),
                  str((res, r.get("residual_rows"))))
            # review C5 policy: residual.{confirmed,unlowerable} split the net (both 0 once the one wall is netted)
            check("residual: row.json carries residual.confirmed / residual.unlowerable (review C5 policy) — 0 / 0 on two_walls",
                  "confirmed" in res and "unlowerable" in res and res["confirmed"] == 0 and res["unlowerable"] == 0
                  and sorted(res) == ["confirmed", "generated_excluded", "legacy_links", "lowered_walls", "net", "raw", "remapped", "unlowerable"],
                  str(res))
        else:
            print("SKIP residual keys: r_min/two_walls_before_stub/cond_B/r not present")
        # review C5 policy (repair): residual.confirmed / residual.unlowerable are the
        # VALUES engine_walls.residual() computed (a row writer hard-wiring 0 / 0 fails
        # here). Two real excerpts as cond_B with no links.json:
        #   r_min/lc_0_0_131 -> the two unlowerable abstract stubs (agent.py:176/194):
        #     net 2 = confirmed 0 + unlowerable 2;
        #   r_min/sk_real -> 2103 (BoolOp, confirmed) + 2130 (param_call, proposed):
        #     net 2 = confirmed 1 + unlowerable 0.
        for name, want, want_rows in (
                ("lc_0_0_131", {"raw": 2, "net": 2, "confirmed": 0, "unlowerable": 2, "lowered_walls": 0},
                 [(176, "resolved_stub", "proposed", "receiver_subclass_no_overrides"),
                  (194, "resolved_stub", "proposed", "receiver_subclass_no_overrides")]),
                ("sk_real", {"raw": 2, "net": 2, "confirmed": 1, "unlowerable": 0, "lowered_walls": 0},
                 [(2103, "unresolved:UnknownIdentifierCallee", "confirmed", ""),
                  (2130, "unresolved:UnknownIdentifierCallee", "proposed", "")])):
            rm = os.path.join(H._ext_dir(), "r_min", name)
            if not os.path.isdir(os.path.join(rm, "r")):
                print(f"SKIP residual values: r_min/{name}/r not present")
                continue
            work = make_work(root, f"residual_{name}", A, plan(two))
            shutil.copytree(rm, os.path.join(work, "cond_B"), dirs_exist_ok=True)
            json.dump(plan(two), open(os.path.join(work, "cond_B", "plan.json"), "w"))
            r = row_of(work)
            res = r.get("residual") or {}
            check(f"residual values (review C5 policy, repair): {name} as cond_B -> " + ", ".join(f"{k} {v}" for k, v in want.items()),
                  {k: res.get(k) for k in want} == want, str(res))
            rows_got = sorted((x["line_cond_a"], x["engine_status"], x["confidence"], x["s2_reason"]) for x in r.get("residual_rows") or [])
            check(f"residual values (review C5 policy, repair): {name} residual_rows carry line / status / confidence / s2_reason",
                  rows_got == sorted(want_rows), str(rows_got))
        r = row_of(make_work(root, "no_sources", A, plan(two, outcome="no_sources")))
        check("draft no_sources beats accepted > 0 without cond_B", r["outcome"] == "no_sources", r["outcome"])
        r = row_of(make_work(root, "stale", [], plan([], outcome="catalog_stale")))
        check("catalog_stale kept", r["outcome"] == "catalog_stale", r["outcome"])
        r = row_of(make_work(root, "drafted", A, plan(two)))
        check("draft ok, no cond_B -> drafted (not env_failed)", r["outcome"] == "drafted", r["outcome"])
        check("no cond_B: issues / sinks of cond_B are null", r["issues"]["cond_B"] is None and r["sink_pairs"]["cond_B"] is None)
        check("no cond_B: outcome_inputs record new / lost 0 (nothing compared), as sink_pairs does",
              r["outcome_inputs"]["new"] == 0 and r["outcome_inputs"]["lost"] == 0 and r["outcome_inputs"]["has_b"] is False
              and r["sink_pairs"]["lost"] == [], str(r["outcome_inputs"]))
        r = row_of(make_work(root, "no_cand", A, plan(two), st=stats(lowered=0, phantom=3, unreasonable=1),
                             lk=links_json([("G0W0", "phantom")] * 3 + [("G0W1", "unreasonable")])))
        check("accepted > 0, links_lowered 0 -> no_candidates (phantom_majority)",
              r["outcome"] == "no_candidates" and r["outcome_reason"] == "phantom_majority", f"{r['outcome']} {r['outcome_reason']}")
        check("no_candidates: walls_lowered 0", r["links"]["walls_lowered"] == 0, str(r["links"]))
        r = row_of(make_work(root, "no_links", A, plan(two), st=stats(lowered=0, built=0), lk=links_json([])))
        check("no links at all -> no_candidates (no_links)", r["outcome"] == "no_candidates" and r["outcome_reason"] == "no_links")
        r = row_of(make_work(root, "no_cand_b", A, plan(two), st=stats(lowered=0, unreasonable=4),
                             lk=links_json([("G0W0", "unreasonable")] * 4), issues_b=A))
        check("cond_B analysed but nothing lowered -> still no_candidates (unreasonable_majority)",
              r["outcome"] == "no_candidates" and r["outcome_reason"] == "unreasonable_majority")
        r = row_of(make_work(root, "pos", A, plan(two), st=stats(lowered=3, unreasonable=1), lk=lk2, issues_b=A + [NEW]))
        check("new > 0, lost == 0 -> delta_pos", r["outcome"] == "delta_pos", r["outcome"])
        check("delta_pos: sink pairs 3 -> 4, new lists the callable", r["sink_pairs"]["cond_A"] == 3 and r["sink_pairs"]["cond_B"] == 4
              and r["sink_pairs"]["new"] == ["ExecArgSink in m.Tool.execute"] and r["sink_pairs"]["lost"] == [], str(r["sink_pairs"]))
        check("walls_lowered = distinct walls with a lowered link (M6)", r["links"]["walls_lowered"] == 2, str(r["links"]))
        check("sink_pairs.key is the K5 key and the aggregate's SINK_PAIR_KEY (review C2)",
              r["sink_pairs"]["key"] == H.SINK_PAIR_KEY == RB.SINK_PAIR_KEY, str(r["sink_pairs"].get("key")))
        check("outcome_inputs re-derive the outcome (review C2: the published outcome is reproducible from its row)",
              r["outcome_inputs"] == {"draft_outcome": "ok", "accepted": 2, "lowering_ran": True, "links_lowered": 3,
                                      "has_b": True, "new": 1, "lost": 0}
              and H.classify_outcome(**r["outcome_inputs"])[0] == r["outcome"], str(r.get("outcome_inputs")))
        r = row_of(make_work(root, "mixed", A, plan(two), st=stats(lowered=3), lk=lk2, issues_b=A[1:] + [NEW]))
        check("new > 0, lost > 0 -> delta_mixed", r["outcome"] == "delta_mixed" and r["sink_pairs"]["lost"] == ["ExecArgSink in m.Agent.run"], r["outcome"])
        r = row_of(make_work(root, "neg", A, plan(two), st=stats(lowered=3), lk=lk2, issues_b=A[1:]))
        check("new == 0, lost > 0 -> delta_neg", r["outcome"] == "delta_neg", r["outcome"])
        r = row_of(make_work(root, "zero", A, plan(two), st=stats(lowered=3), lk=lk2, issues_b=A))
        check("same pairs -> delta0", r["outcome"] == "delta0", r["outcome"])
        r = row_of(make_work(root, "zero_hop", A, plan(two), st=stats(lowered=3), lk=lk2, issues_b=A_hop))
        check("issues_B > issues_A alone is not delta_pos; a first-hop reshuffle is delta0",
              r["outcome"] == "delta0" and r["first_hops"]["new"] > 0 and r["first_hops"]["lost"] > 0, f"{r['outcome']} {r['first_hops']}")
        more = A + [issue("m.Agent.run", "ExecArgSink", ("m.exec",), line=7)]      # a second flow into a known pair
        r = row_of(make_work(root, "zero_more", A, plan(two), st=stats(lowered=3), lk=lk2, issues_b=more))
        check("more issues into the same pairs -> delta0 (issue count 3 -> 4 recorded)",
              r["outcome"] == "delta0" and r["issues"]["delta"] == 1, f"{r['outcome']} {r['issues']}")
        r = row_of(make_work(root, "envf", A, plan(two), st=stats(lowered=3), lk=lk2))
        check("cond_B lowered but no taint-output.json -> env_failed", r["outcome"] == "env_failed" and "cond_B" in r["outcome_reason"], r["outcome"])
        r = row_of(make_work(root, "envfa", A, plan(two), cond_a=False))
        check("no cond_A results -> env_failed", r["outcome"] == "env_failed" and r["env_state"] == "env_failed")
        check("no cond_A: no outcome_inputs (nothing was classified)", "outcome_inputs" not in r)

        # --- review edits against the read-only original (C7) and the verdict override (M5)
        orig = plan([("a.py:3:4", False, "T1"), ("a.py:9:4", False, "T3")], outcome="no_walls")
        used = json.loads(json.dumps(orig))
        used["groups"][0]["walls"][0]["accept"] = True
        used["groups"][0]["spec"]["registry_vars"] = ["REG"]
        used["review"]["minutes"] = 12
        r = row_of(make_work(root, "flip", A, orig, plan_used=used, st=stats(lowered=2, detected=2, rejected=1),
                             lk=links_json([("G0W0", "lowered")] * 2), issues_b=A + [NEW]))
        check("one accept flipped in the reviewed plan -> accept_flips == 1",
              r["review_edits"]["accept_flips"] == 1 and r["review_edits"]["accept_flipped_positions"] == ["a.py:3:4"], str(r["review_edits"]))
        check("spec key edit and review minutes recorded", r["review_edits"]["spec_key_edits"] == 1 and r["review_edits"]["minutes"] == 12)
        check("draft_accepted stays the original's (0); accepted_used is the reviewed plan's (1)",
              r["draft_accepted"] == 0 and r["review_edits"]["accepted_used"] == 1)
        check("a no_walls draft with a reviewed accept and lowered links -> the measured outcome wins",
              r["outcome"] == "delta_pos", r["outcome"])
        same = json.loads(json.dumps(orig))
        r = row_of(make_work(root, "noflip", A, orig, plan_used=same, st=stats(lowered=0, built=0), lk=links_json([])))
        check("unedited plan -> 0 flips; 0 accepted after review -> no_walls even though the lowering ran",
              r["review_edits"]["accept_flips"] == 0 and r["outcome"] == "no_walls", f"{r['review_edits']} {r['outcome']}")
        r = row_of(make_work(root, "noorig", A, plan(two), draft_original=False))
        check("without plan.draft.json the draft counts fall back to plan.json and say so",
              r["draft_walls"] == 2 and r["draft_source"].startswith("plan.json"), r.get("draft_source"))

        # --- tool version (K4)
        tv = toolver.tool_version()
        r = row_of(make_work(root, "tv_ok", A, plan(two, tool_version=tv), st=stats(lowered=3), lk=lk2, issues_b=A))
        check("row records the current tool_version", r["tool_version"]["combined"] == tv["combined"])
        check("plan made by the current code -> versions_match True", r["versions_match"] is True and r["plan_tool_version"]["combined"] == tv["combined"])
        other = dict(tv, combined="0" * 64)
        r = row_of(make_work(root, "tv_bad", A, plan(two, tool_version=other), st=stats(lowered=3), lk=lk2, issues_b=A))
        check("plan made by another version -> versions_match False", r["versions_match"] is False)
        r = row_of(make_work(root, "tv_none", A, plan(two)))
        check("plan without tool_version -> versions_match null", r["versions_match"] is None and r["plan_tool_version"] is None)
        r = row_of(make_work(root, "tv_used", A, plan(two), plan_used=plan(two, tool_version=tv), st=stats(lowered=3), lk=lk2, issues_b=A))
        check("plan_tool_version is cond_B/plan.json's when present", r["plan_tool_version"]["combined"] == tv["combined"])

        # --- accepted tier distribution (M7 consumer)
        r = row_of(make_work(root, "tier_calc", A, plan([("a.py:3:4", True, "T1"), ("a.py:5:4", True, "none"), ("a.py:9:4", False, "T3")])))
        check("accepted_by_tier computed from the accepted rows when the plan has no counts", r["accepted_by_tier"] == {"T1": 1, "none": 1}, str(r["accepted_by_tier"]))
        r = row_of(make_work(root, "tier_given", A, plan(two, counts_extra={"accepted_by_tier": {"T1": 1, "T2": 0, "T3": 0, "none": 1}})))
        check("counts.accepted_by_tier of the plan is preferred", r["accepted_by_tier"] == {"T1": 1, "T2": 0, "T3": 0, "none": 1})

        # --- classify_outcome directly (pure)
        C = H.classify_outcome
        check("classify: draft verdicts", C("no_surface", 0, False, 0, False, 0, 0)[0] == "no_surface"
              and C("catalog_stale", 0, False, 0, False, 0, 0)[0] == "catalog_stale"
              and C("no_sources", 3, True, 0, True, 0, 0)[0] == "no_sources")
        check("classify: net delta", C("ok", 2, True, 5, True, 1, 0)[0] == "delta_pos" and C("ok", 2, True, 5, True, 1, 1)[0] == "delta_mixed"
              and C("ok", 2, True, 5, True, 0, 2)[0] == "delta_neg" and C("ok", 2, True, 5, True, 0, 0)[0] == "delta0")
        check("classify: measured beats the draft verdict", C("no_walls", 1, True, 2, True, 1, 0)[0] == "delta_pos"
              and C("no_sources", 1, True, 2, True, 0, 0)[0] == "delta0")
        check("classify: env_failed only after a lowering", C("ok", 2, True, 5, False, 0, 0)[0] == "env_failed"
              and C("ok", 2, False, 0, False, 0, 0)[0] == "drafted")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print(f"\n{N - len(FAILS)}/{N} passed" + ("" if not FAILS else f"; FAILED: {FAILS}"))
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
