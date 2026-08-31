"""Helpers for run_ablation.sh — invoked as subcommands (no heredocs needed).

    python3 ablation_helpers.py config <target_dir> <tp2x> <typeshed>
    python3 ablation_helpers.py lower  <ext_dir> <cand_dir> <spec_json> <wall_file>...
        env: SRC_ROOT=<cond_B/src>  (REQUIRED — the Pysa source root)
             EMIT=inline|redirector  LINKS_IN=<links.json>  LINKS_OUT=<path>  STATS_OUT=<path>
    python3 ablation_helpers.py count  <taint_output.json>
    python3 ablation_helpers.py table  <cond_A_taint_output> <cond_B_taint_output> <stats.json> [<links.json> <cond_B_dir>]
    python3 ablation_helpers.py draft  <ext_dir> <cond_A_dir> <out_dir> [draft.py options...]
        env: PLAN_JSON=<plan.json> makes `lower` run pipeline.run_plan (wall files come from the plan)
    python3 ablation_helpers.py row    <work_dir> <row.json>

Outcome vocabulary of ``row`` (review C2 / M5, contract K5):
    env_failed | no_sources | no_surface | catalog_stale | no_walls (the draft accepted
    0 walls) | no_candidates (accepted > 0 but links_lowered == 0) | drafted (draft ok,
    no cond_B yet) | delta_pos (new > 0, lost == 0) | delta_mixed (new > 0, lost > 0) |
    delta_neg (new == 0, lost > 0) | delta0.
Sink pairs are keyed by (sink kind, the issue's ``callable``); the first hop of the
backward trace is kept as a diagnostic set only (``first_hops``).
"""
import collections
import json
import os
import sys


def _load_ext(ext_dir):
    """Import the extension package (dispatch_lowering / links / pipeline) from ext_dir."""
    ext_dir = os.path.abspath(ext_dir)
    if ext_dir not in sys.path:
        sys.path.insert(0, ext_dir)
    import dispatch_lowering, pipeline   # noqa: F401
    return dispatch_lowering, pipeline


def _load_dl(ext_dir):
    return _load_ext(ext_dir)[0]


def _ext_dir():
    return os.environ.get("EXT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "taintp2x_extension"))


def _draft_framework(plan):
    """review M4 (repair): the framework a draft is attributed to = catalog.framework_of
    (the seeding preset plan.catalog.top only when its score reaches match.min_score /
    FW_MIN_SCORE; version-1 plans recomputed from their scores), the same rule as the
    summary.md "by framework" table — never an unthresholded ``top``. Falls back to
    ``top`` only when catalog.py is not importable."""
    cat = (plan or {}).get("catalog") or {}
    ext_dir = os.path.abspath(_ext_dir())
    if ext_dir not in sys.path:
        sys.path.insert(0, ext_dir)
    try:
        import catalog
        return catalog.framework_of(cat, catalog.load())
    except Exception:
        return cat.get("top") or "(none)"


def _load_toolver(ext_dir):
    """toolver.py (contract K4) the way _load_ext loads the extension; None when absent."""
    ext_dir = os.path.abspath(ext_dir)
    if ext_dir not in sys.path:
        sys.path.insert(0, ext_dir)
    try:
        import toolver
        return toolver
    except Exception:
        return None


def cmd_config(target, tp2x, typeshed):
    """Write a .pyre_configuration identical in shape to reproduce_m2.sh's."""
    search = [os.path.join(tp2x, "stubs")]
    # Include the active venv's site-packages so third-party deps of a vendored
    # target (e.g. pydantic/anyio for a vendored real mcp library) resolve.
    # No-op when not in a venv -> existing targets (AutoGPT) are unaffected.
    # PYRE_SEARCH_VENV=0 keeps the venv out even when one is active: a target
    # whose deps are vendored (or absent) analyses 10-100x faster without it
    # (AutoGPT: a 44 KB vs 156 MB call graph), and the committed AutoGPT
    # verification was produced that way.
    import glob as _glob
    venv = os.environ.get("VIRTUAL_ENV") if os.environ.get("PYRE_SEARCH_VENV", "1") != "0" else ""
    if venv:
        for sp in _glob.glob(os.path.join(venv, "lib", "python*", "site-packages")):
            search.append(sp)
    # PYRE_EXTRA_SEARCH: ':'-separated dirs appended to search_path (a subset's
    # deps_iso / stubs_min from subset_extractor, instead of the whole venv)
    for extra in [x for x in os.environ.get("PYRE_EXTRA_SEARCH", "").split(":") if x]:
        if os.path.isdir(extra) and extra not in search:
            search.append(extra)
    cfg = {
        "source_directories": [os.path.join(target, "src")],
        "taint_models_path": [os.path.join(tp2x, "taint"), os.path.join(target, "source")],
        "search_path": search,
        "typeshed": typeshed,
        "strict": False,
    }
    with open(os.path.join(target, ".pyre_configuration"), "w") as f:
        json.dump(cfg, f, indent=2)
    print(f"[ctaudit] wrote {os.path.join(target, '.pyre_configuration')}")


def cmd_lower(ext_dir, cand_dir, spec_json, *wall_files):
    """Run the lowering pipeline in place on the wall files (cond_B tree):
    provider -> links (with filters) -> instrument; persist links/stats."""
    _dl, pipeline = _load_ext(ext_dir)
    spec = {}
    if spec_json and os.path.exists(spec_json):
        spec = json.load(open(spec_json))
    # SRC_ROOT is the Pysa source root: the redirect module is written there and
    # imported as a top-level module, so guessing it from a nested wall file
    # would put it where the inserted import cannot resolve.
    src_root = os.environ.get("SRC_ROOT")
    if not src_root:
        sys.exit("SRC_ROOT is required (the Pysa source root, e.g. cond_B/src)")
    emit = os.environ.get("EMIT", "")
    links_in = os.environ.get("LINKS_IN", "")
    plan_json = os.environ.get("PLAN_JSON", "")
    wall_files = [w for w in wall_files if w]
    if plan_json:
        # reviewed draft: groups of pinned walls, each with its spec
        plan = json.load(open(plan_json))
        res = pipeline.run_plan(src_root, plan, cand_dir=cand_dir, emit=emit, write=True,
                                only_files=[os.path.relpath(w, src_root) for w in wall_files] or None)
    else:
        if not wall_files:
            wall_files = [os.path.join(src_root, w) for w in (spec.get("wall_files") or [])]
        if not wall_files:
            sys.exit("no wall files: pass them, set spec.wall_files, or use PLAN_JSON")
        res = pipeline.run_spec(src_root, spec, list(wall_files), cand_dir=cand_dir,
                                links_in=links_in, emit=emit, write=True)
    pipeline._print_report(res)
    if res.stats.candidates_total == 0 and not links_in:
        print("[ctaudit] WARNING: 0 candidates — check spec (tool_decorators / "
              "scan_all_callables) and CAND_DIR. Lowering was a no-op.")
    links_out = os.environ.get("LINKS_OUT") or os.path.join(os.path.dirname(src_root), "links.json")
    stats_out = os.environ.get("STATS_OUT") or os.path.join(os.path.dirname(src_root), "stats.json")
    pipeline.write_links(links_out, res)   # review C7 / K4: stamps tool_version
    json.dump(res.stats.to_dict(), open(stats_out, "w"), indent=2)
    print(f"[ctaudit] wrote {links_out} and {stats_out}")


def _issues(taint_output):
    """kind=='issue' records in pyre's taint-output.json (array, 1 obj/line)."""
    out = []
    if not os.path.exists(taint_output):
        return out
    for line in open(taint_output):
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        if isinstance(o, list):             # a one-line ``[]`` / whole array on one line
            out += [x.get("data", {}) for x in o if isinstance(x, dict) and x.get("kind") == "issue"]
        elif isinstance(o, dict) and o.get("kind") == "issue":
            out.append(o.get("data", {}))
    return out


def _sink_kinds(d):
    """Sink kinds named by the backward-trace roots of one issue."""
    kinds = []
    for tr in d.get("traces", []):
        if tr.get("name") != "backward":
            continue
        for r in tr.get("roots", []):
            for k in r.get("kinds", []):
                kk = k.get("kind")
                if kk and kk not in kinds:
                    kinds.append(kk)
    return kinds or ["<nokind>"]


def _sink_pairs(issues):
    """Distinct (sink kind, issue callable) pairs reached — issue *coverage*
    (review C2, contract K5). Pysa reports one issue per tainted argument
    flow into a sink call, so a call with two tainted arguments counts twice;
    the pair set is the stable measure of *what* the wall resolution made
    reachable. The key is the callable Pysa reports the issue in, never the
    first hop of the backward trace (``resolves_to[0]`` flips between runs
    when a call site's resolved set shrinks; see ``_sink_first_hops``)."""
    pairs = set()
    for d in issues:
        callable_ = str(d.get("callable", "") or "<unknown>")
        for k in _sink_kinds(d):
            pairs.add((k, callable_))
    return pairs


def _sink_first_hops(issues):
    """Diagnostics only (review C2): the legacy key — (sink kind, the whole
    ``resolves_to`` set of the backward trace's root call, ``<direct>`` when it
    has none). Kept so the old numbers stay explainable; never in the outcome."""
    pairs = set()
    for d in issues:
        for tr in d.get("traces", []):
            if tr.get("name") != "backward":
                continue
            for r in tr.get("roots", []):
                kinds = [k.get("kind") for k in r.get("kinds", [])]
                call = r.get("call") or {}
                callee = " | ".join(sorted(call.get("resolves_to") or ())) or "<direct>"
                for k in kinds:
                    pairs.add((k, callee))
    return pairs


def cmd_count(taint_output):
    """Count issues by code and callable, plus distinct sink coverage."""
    issues = _issues(taint_output)
    codes = collections.Counter(d.get("code") for d in issues)
    callables = collections.Counter(str(d.get("callable", "")) for d in issues)
    print(f"ISSUES={len(issues)}")
    for c, n in sorted(codes.items(), key=lambda kv: (kv[0] is None, kv[0])):
        print(f"  code {c}: {n}")
    for c, n in callables.items():
        print(f"  callable {c}: {n}")
    pairs = _sink_pairs(issues)
    print(f"SINK_PAIRS={len(pairs)}")
    for k, callee in sorted(pairs):
        print(f"  sink {k} in {callee}")
    # legacy diagnostic key (sink kind, first hop of the backward trace)
    hops = _sink_first_hops(issues)
    print(f"SINK_FIRST_HOPS={len(hops)}")
    for k, callee in sorted(hops):
        print(f"  sink {k} via {callee}")


def cmd_draft(ext_dir, cond_dir, out_dir, *extra):
    """Write the review bundle (plan.json, walls.md, ...) from cond_A's Pysa
    results — engine_walls + derived spec + pipeline dry run. Exit code is the
    draft's outcome (0 ok, 2 no surface, 3 catalogue stale, 4 no sources,
    5 no accepted walls)."""
    _load_ext(ext_dir)
    import draft
    return draft.main([cond_dir, "--out", out_dir] + list(extra))


def _fmt(d):
    return ", ".join(f"{k}={v}" for k, v in (d or {}).items()) or "-"


def cmd_table(a_out, b_out, stats_json, links_json="", cond_b_dir=""):
    """Evaluation row: lowering statistics next to the A/B issue delta
    (IccTA's Beginning/Ending InfoStatistic + leak counts in one table)."""
    s = json.load(open(stats_json)) if os.path.exists(stats_json) else {}
    ia, ib = _issues(a_out), _issues(b_out)
    rows = [
        ("wall files", s.get("files", 0)),
        ("walls detected", s.get("walls_detected", 0)),
        ("  by idiom", _fmt(s.get("walls_by_idiom"))),
        ("  by origin", _fmt(s.get("walls_by_origin"))),
        ("  by engine status", _fmt(s.get("walls_by_engine_status"))),
        ("  rejected by review", s.get("walls_rejected", 0)),
        ("  pinned position not found", s.get("walls_unmatched", 0)),
        ("  skipped (no forwardable args)", s.get("walls_skipped_no_args", 0)),
        ("  with a lowered link", _lowered_walls(links_json) if links_json else "-"),
        ("candidates", s.get("candidates_total", 0)),
        ("links built", s.get("links_built", 0)),
        ("  lowered", s.get("links_lowered", 0)),
        ("  filtered (registry membership)", s.get("links_filtered_registry", 0)),
        ("  filtered (match_level cap)", s.get("links_filtered_level", 0)),
        ("  unreasonable (signature mismatch)", s.get("links_unreasonable", 0)),
        ("  no forwardable argument", s.get("links_no_args", 0)),
        ("  phantom (target not importable)", s.get("links_phantom", 0)),
        ("redirectors generated", s.get("redirectors", 0)),
        ("lines added", s.get("lines_added", 0)),
        ("issues cond_A (host alone)", len(ia)),
        ("issues cond_B (host + wall resolution)", len(ib)),
        ("delta", len(ib) - len(ia)),
        ("distinct (sink kind, issue callable) cond_A", len(_sink_pairs(ia))),
        ("distinct (sink kind, issue callable) cond_B", len(_sink_pairs(ib))),
        ("distinct (sink kind, first hop) cond_A [diag]", len(_sink_first_hops(ia))),
        ("distinct (sink kind, first hop) cond_B [diag]", len(_sink_first_hops(ib))),
    ]
    w = max(len(r[0]) for r in rows)
    for k, v in rows:
        print(f"  {k.ljust(w)}  {v}")
    new_codes = collections.Counter(d.get("code") for d in ib) - collections.Counter(d.get("code") for d in ia)
    if new_codes:
        print("  new issues by code: " + ", ".join(f"{c}={n}" for c, n in sorted(new_codes.items())))
    for k, callee in sorted(_sink_pairs(ib) - _sink_pairs(ia)):
        print(f"  newly reached sink: {k} in {callee}")
    for k, callee in sorted(_sink_pairs(ia) - _sink_pairs(ib)):
        print(f"  lost sink: {k} in {callee}")
    if cond_b_dir and os.path.isdir(os.path.join(cond_b_dir, "r")):
        r = _residual(cond_b_dir, links_json)
        if r:
            # review C5 policy: the net splits into confirmed (lowerable, left) and
            # unlowerable (abstract stub, no in-tree implementation) walls
            print(f"  residual walls (taint-reaching, still unresolved/obscure): raw {r['residual_raw']}, "
                  f"net of lowered {r['residual']} (confirmed {r.get('residual_confirmed')}, "
                  f"unlowerable {r.get('residual_unlowerable')})")


def _residual(cond_b_dir, links_json=""):
    # a cond_B without the engine's own outputs (call-graph.json) cannot be scanned
    if not os.path.exists(os.path.join(cond_b_dir, "r", "call-graph.json")):
        return None
    try:
        _load_ext(_ext_dir())
        import engine_walls
        return engine_walls.residual(cond_b_dir, links_json=links_json or os.path.join(cond_b_dir, "links.json"))
    except Exception as e:      # diagnostics only
        print(f"  residual: n/a ({e})")
        return None


def _read_json(p, default=None):
    try:
        return json.load(open(p)) if os.path.exists(p) else default
    except Exception:
        return default


def _plan_rows(plan):
    return [w for g in (plan or {}).get("groups", []) for w in g.get("walls", [])]


def _lowered_walls(links_json):
    """Distinct walls that carry a ``status == 'lowered'`` link in a links.json
    (review M6: the summary's walls_lowered is NOT the accepted count). None
    when the file is absent."""
    data = _read_json(links_json)
    if not isinstance(data, dict):
        return None
    ids = set()
    for l in data.get("links", []):
        if l.get("status", "lowered") == "lowered":
            ids.add(l.get("wall_id") or f"{l.get('file', '')}:{l.get('line', '')}")
    return len(ids)


def review_edits(plan_orig, plan_used):
    """Diff of the read-only draft original (``plan.draft.json``, review C7)
    against the plan the lowering consumed (``cond_B/plan.json``): accept
    flips (by position), spec key edits (per group, ignoring ``_*`` keys and
    ``wall_positions``), stages added, review minutes."""
    d = {w["position"]: bool(w.get("accept")) for w in _plan_rows(plan_orig)}
    u = {w["position"]: bool(w.get("accept")) for w in _plan_rows(plan_used)}
    flipped = sorted(k for k in u if k in d and d[k] != u[k])
    spec_edits = 0
    for gd, gu in zip(plan_orig.get("groups", []), plan_used.get("groups", [])):
        kd = {k: v for k, v in (gd.get("spec") or {}).items() if not k.startswith("_") and k != "wall_positions"}
        ku = {k: v for k, v in (gu.get("spec") or {}).items() if not k.startswith("_") and k != "wall_positions"}
        spec_edits += sum(1 for k in set(kd) | set(ku) if kd.get(k) != ku.get(k))
    stages = sum(1 for g in plan_used.get("groups", []) if g.get("stages"))
    return {"accept_flips": len(flipped), "accept_flipped_positions": flipped[:50],
            "accepted_draft": sum(1 for v in d.values() if v), "accepted_used": sum(1 for v in u.values() if v),
            "spec_key_edits": spec_edits, "stages_added": stages,
            "minutes": (plan_used.get("review") or {}).get("minutes")}


def _accepted_by_tier(plan):
    """Tier distribution of the accepted rows (review M7). Prefers the draft's
    own ``counts.accepted_by_tier`` when it records one; else computed from
    the plan rows."""
    c = ((plan or {}).get("counts") or {}).get("accepted_by_tier")
    if isinstance(c, dict):
        return dict(c)
    rows = _plan_rows(plan)
    if not rows:
        return None
    return _counts(w.get("engine_tier") or "none" for w in rows if w.get("accept"))


DRAFT_VERDICTS = ("no_sources", "no_surface", "catalog_stale")   # the draft's own verdict: no cond_B expected
SINK_PAIR_KEY = "(sink kind, issue callable)"   # review C2 / K5: recorded in row.json sink_pairs.key (run_benchmark
                                                 # flags rows written under the old first-hop key)
NO_CANDIDATE_STATUSES = ("phantom", "unreasonable", "filtered_registry", "filtered_level", "no_args")


def _no_candidates_reason(stats):
    """Sub-reason of a ``no_candidates`` outcome: which link status dominates."""
    built = stats.get("links_built") or 0
    if not built:
        return "no_links"
    counts = {k: (stats.get(f"links_{k}") or 0) for k in NO_CANDIDATE_STATUSES}
    top = max(counts, key=lambda k: counts[k])
    return f"{top}_majority" if counts[top] * 2 >= built else "mixed"


def classify_outcome(draft_outcome, accepted, lowering_ran, links_lowered, has_b, new, lost):
    """The K5 outcome of one target from its measured facts (pure; unit-tested).

    draft_outcome: the draft's verdict ('ok' / 'no_walls' / 'no_sources' / ...)
    accepted:      accepted walls in the plan the lowering used (else the draft's)
    lowering_ran:  cond_B/links.json or stats.json exists
    links_lowered: stats.links_lowered of cond_B
    has_b:         cond_B/r/taint-output.json exists
    new / lost:    sink-pair counts cond_B - cond_A and cond_A - cond_B
    Returns (outcome, reason)."""
    measured = lowering_ran and (links_lowered or 0) > 0
    if not measured:
        if draft_outcome in DRAFT_VERDICTS:
            return draft_outcome, "draft verdict"
        if not accepted:
            return "no_walls", "the draft accepted 0 walls"
        if not lowering_ran:
            return "drafted", "draft ok, cond_B not built yet"
        return "no_candidates", ""          # caller fills the sub-reason from stats
    # the lowering changed the tree: the measured outcome overrides the draft verdict
    if not has_b:
        return "env_failed", "cond_B was lowered but produced no taint-output.json"
    if new and not lost:
        return "delta_pos", ""
    if new and lost:
        return "delta_mixed", ""
    if lost:
        return "delta_neg", ""
    return "delta0", ""


def cmd_row(work_dir, out_json):
    """One target = one row.json: environment state, timings, engine view,
    review edits, link statistics, issue / sink deltas, residual, outcome,
    tool version (K4)."""
    ext_dir = _ext_dir()
    _load_ext(ext_dir)
    try:
        import engine_walls                 # only for the env fallback scan
    except Exception:                       # the row must still be written
        engine_walls = None
    toolver = _load_toolver(ext_dir)
    ca, cb = os.path.join(work_dir, "cond_A"), os.path.join(work_dir, "cond_B")
    a_out, b_out = os.path.join(ca, "r", "taint-output.json"), os.path.join(cb, "r", "taint-output.json")
    tv = toolver.tool_version() if toolver else None
    row = {"work_dir": os.path.abspath(work_dir), "env_state": "ok", "outcome": "", "outcome_reason": "",
           "pyre_seconds": {"cond_A": _read_num(os.path.join(ca, "pyre_seconds")),
                            "cond_B": _read_num(os.path.join(cb, "pyre_seconds"))},
           "tool_version": tv}
    if not os.path.exists(a_out):
        row["env_state"] = "env_failed"
        row["outcome"] = "env_failed"
        row["outcome_reason"] = "cond_A produced no taint-output.json"
        json.dump(row, open(out_json, "w"), indent=2)
        print(f"[ctaudit] wrote {out_json} (env_failed)")
        return 0
    # engine view of cond_A (the draft's env_report when present, else a fresh scan)
    draft_dir = os.path.join(work_dir, "draft")
    env = _read_json(os.path.join(draft_dir, "env_report.json"))
    if env is None:
        try:
            env = engine_walls.scan(ca).env
        except Exception as e:      # a cond_A without the engine's outputs
            env = {"scan_error": f"{type(e).__name__}: {e}"}
    row["unresolved_by_reason"] = env.get("unresolved_by_reason", {})
    row["env_gaps"] = env.get("env_gaps", 0)
    row["env_gaps_by_reason"] = env.get("env_gaps_by_reason", {})
    row["model_verification_errors"] = env.get("model_verification_errors", 0)
    row["source_models"] = env.get("source_models", 0)
    row["source_models_in_repo"] = env.get("source_models_in_repo", 0)
    row["catalog_hits"] = env.get("catalog_hits", {})
    row["engine_outcome"] = env.get("outcome", "")
    # the draft original (review C7: write_bundle emits a read-only
    # plan.draft.json; plan.json is what the reviewer edits in place) vs the
    # plan the lowering actually used
    plan_orig = _read_json(os.path.join(draft_dir, "plan.draft.json"))
    row["draft_source"] = "plan.draft.json"
    if plan_orig is None:
        plan_orig = _read_json(os.path.join(draft_dir, "plan.json"))
        row["draft_source"] = "plan.json (no plan.draft.json: review edits are not observable)" if plan_orig else ""
    plan_used = _read_json(os.path.join(cb, "plan.json"))
    if plan_used and plan_used.get("ablation"):
        row["ablation"] = plan_used["ablation"]
    draft_accepted = None
    if plan_orig:
        rows_d = _plan_rows(plan_orig)
        draft_accepted = sum(1 for w in rows_d if w.get("accept"))
        row["draft_walls"] = len(rows_d)
        row["draft_accepted"] = draft_accepted
        row["draft_outcome"] = plan_orig.get("outcome")
        row["draft_created"] = plan_orig.get("created")
        row["draft_by_status"] = _counts((w.get("engine_status") or "").split(":")[0] for w in rows_d)
        row["draft_by_tier"] = _counts(w.get("engine_tier") or "none" for w in rows_d)
        row["accepted_by_tier"] = _accepted_by_tier(plan_orig)
        row["draft_accepted_by_tier"] = row["accepted_by_tier"]                                   # review M7 (draft's key name)
        row["draft_engine_walls"] = (plan_orig.get("counts") or {}).get("engine_walls")
        row["draft_framework"] = _draft_framework(plan_orig)          # review M4: never detected[0]; thresholded (repair)
    accepted_used = draft_accepted
    if plan_used:
        accepted_used = sum(1 for w in _plan_rows(plan_used) if w.get("accept"))
        row["plan_created"] = plan_used.get("created")
    if plan_orig and plan_used:
        row["review_edits"] = review_edits(plan_orig, plan_used)
    # tool version (K4): the plan the lowering used, else the draft's
    plan_tv = (plan_used or {}).get("tool_version") or (plan_orig or {}).get("tool_version")
    row["plan_tool_version"] = plan_tv
    row["versions_match"] = (toolver.same_version(tv, plan_tv) if (toolver and plan_tv) else None)
    # lowering statistics
    stats_path, links_path = os.path.join(cb, "stats.json"), os.path.join(cb, "links.json")
    stats = _read_json(stats_path, {}) or {}
    if not stats and os.path.exists(links_path):
        stats = (_read_json(links_path, {}) or {}).get("stats") or {}
    lowering_ran = os.path.exists(stats_path) or os.path.exists(links_path)
    row["links"] = {k: stats.get(k, 0) for k in ("walls_detected", "walls_rejected", "walls_unmatched",
                                                  "walls_skipped_no_args", "candidates_total", "links_built",
                                                  "links_lowered", "links_filtered_registry", "links_filtered_level",
                                                  "links_unreasonable", "links_no_args", "links_phantom",
                                                  "redirectors", "lines_added")}
    # review M6: walls that actually got a lowered link (not the accepted count)
    row["links"]["walls_lowered"] = _lowered_walls(links_path)
    row["walls_by_engine_status"] = stats.get("walls_by_engine_status", {})
    row["walls_by_origin"] = stats.get("walls_by_origin", {})
    # issues (cond_B may not exist: the draft found nothing to lower)
    ia = _issues(a_out)
    has_b = os.path.exists(b_out)
    ib = _issues(b_out) if has_b else []
    pa, pb = _sink_pairs(ia), _sink_pairs(ib)
    row["issues"] = {"cond_A": len(ia), "cond_B": len(ib) if has_b else None,
                     "delta": (len(ib) - len(ia)) if has_b else None}
    # ``lost``: pairs cond_A reported that cond_B does not — never hidden; the
    # net outcome (delta_mixed / delta_neg) carries it
    row["sink_pairs"] = {"key": SINK_PAIR_KEY,
                         "cond_A": len(pa), "cond_B": len(pb) if has_b else None,
                         "new": sorted(f"{k} in {c}" for k, c in (pb - pa)) if has_b else [],
                         "lost": sorted(f"{k} in {c}" for k, c in (pa - pb)) if has_b else []}
    ha, hb = _sink_first_hops(ia), _sink_first_hops(ib)
    row["first_hops"] = {"key": "(sink kind, resolves_to set of the backward root) — diagnostics only",
                         "cond_A": len(ha), "cond_B": len(hb) if has_b else None,
                         "new": len(hb - ha) if has_b else None, "lost": len(ha - hb) if has_b else None}
    r = _residual(cb, links_path) if has_b else None
    # review C1 / K2: every key of engine_walls.residual() — net = raw minus the
    # lowered walls netted through the guard-block line map (cond_B lines mapped
    # back to cond_A), generated-block / redirector sites excluded, legacy_links =
    # a pre-C1 basename-keyed links.json (numbers indicative only)
    # review C5 policy: residual.{confirmed,unlowerable} split the net —
    # confirmed = walls the lowering could have taken, unlowerable = abstract
    # stubs with no in-tree implementation (s2_reason receiver_subclass_no_overrides)
    row["residual"] = ({"raw": r["residual_raw"], "net": r["residual"],
                        "lowered_walls": r.get("lowered_walls"), "generated_excluded": r.get("generated_excluded"),
                        "remapped": r.get("remapped"), "legacy_links": r.get("legacy_links"),
                        "confirmed": r.get("residual_confirmed"), "unlowerable": r.get("residual_unlowerable")} if r else None)
    row["residual_rows"] = [{k: x.get(k) for k in ("file", "line_cond_b", "line_cond_a", "col", "callee", "engine_status",
                                                     "receiver_class", "s2_reason", "tier", "confidence")}
                            for x in ((r or {}).get("rows") or [])]
    ds = os.environ.get("DATASET_DIR", "")
    if ds:
        row["dataset_reference_issues"] = len(_issues(os.path.join(ds, "taint-output.json")))
    # outcome (K5): the draft's verdict only while nothing was lowered; once
    # cond_B carries lowered links the measured outcome wins (review M5)
    draft_outcome = (plan_orig or {}).get("outcome") or env.get("outcome") or ""
    # the classifier's inputs are recorded so a published outcome can be re-derived
    # from its row alone (review C2: the table must not mix outcome definitions)
    # (new / lost are 0 without a cond_B: nothing was compared, as sink_pairs records)
    row["outcome_inputs"] = {"draft_outcome": draft_outcome, "accepted": accepted_used or 0,
                             "lowering_ran": bool(lowering_ran), "links_lowered": stats.get("links_lowered") or 0,
                             "has_b": has_b, "new": len(pb - pa) if has_b else 0, "lost": len(pa - pb) if has_b else 0}
    outcome, reason = classify_outcome(**row["outcome_inputs"])
    if outcome == "no_candidates" and not reason:
        reason = _no_candidates_reason(stats)
    row["outcome"], row["outcome_reason"] = outcome, reason
    json.dump(row, open(out_json, "w"), indent=2, ensure_ascii=False)
    print(f"[ctaudit] wrote {out_json}: outcome={row['outcome']}"
          + (f" ({reason})" if reason else "") + f" issues={row['issues']} sink_pairs="
          f"{row['sink_pairs']['cond_A']}->{row['sink_pairs']['cond_B']} residual={row['residual']}")
    return 0


def _counts(it):
    return dict(collections.Counter(it))


def _read_num(p):
    try:
        return float(open(p).read().strip())
    except Exception:
        return None


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "config":
        cmd_config(*sys.argv[2:])
    elif cmd == "lower":
        cmd_lower(*sys.argv[2:])
    elif cmd == "count":
        cmd_count(*sys.argv[2:])
    elif cmd == "table":
        cmd_table(*sys.argv[2:])
    elif cmd == "draft":
        sys.exit(cmd_draft(*sys.argv[2:]))
    elif cmd == "row":
        sys.exit(cmd_row(*sys.argv[2:]))
    else:
        sys.exit(f"unknown subcommand: {cmd!r}")
