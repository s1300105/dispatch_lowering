"""Helpers for run_ablation.sh — invoked as subcommands (no heredocs needed).

    python3 ablation_helpers.py config <target_dir> <tp2x> <typeshed>
    python3 ablation_helpers.py lower  <ext_dir> <cand_dir> <spec_json> <wall_file>...
        env: SRC_ROOT=<cond_B/src>  (REQUIRED — the Pysa source root)
             EMIT=inline|redirector  LINKS_IN=<links.json>  LINKS_OUT=<path>  STATS_OUT=<path>
    python3 ablation_helpers.py count  <taint_output.json>
    python3 ablation_helpers.py table  <cond_A_taint_output> <cond_B_taint_output> <stats.json>
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


def cmd_config(target, tp2x, typeshed):
    """Write a .pyre_configuration identical in shape to reproduce_m2.sh's."""
    search = [os.path.join(tp2x, "stubs")]
    # Include the active venv's site-packages so third-party deps of a vendored
    # target (e.g. pydantic/anyio for a vendored real mcp library) resolve.
    # No-op when not in a venv -> existing targets (AutoGPT) are unaffected.
    import glob as _glob
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        for sp in _glob.glob(os.path.join(venv, "lib", "python*", "site-packages")):
            search.append(sp)
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
    res = pipeline.run_spec(src_root, spec, list(wall_files), cand_dir=cand_dir,
                            links_in=links_in, emit=emit, write=True)
    pipeline._print_report(res)
    if res.stats.candidates_total == 0 and not links_in:
        print("[ctaudit] WARNING: 0 candidates — check spec (tool_decorators / "
              "scan_all_callables) and CAND_DIR. Lowering was a no-op.")
    links_out = os.environ.get("LINKS_OUT") or os.path.join(os.path.dirname(src_root), "links.json")
    stats_out = os.environ.get("STATS_OUT") or os.path.join(os.path.dirname(src_root), "stats.json")
    import links as L
    L.dump_links(links_out, res.walls, res.links, res.stats)
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
        if o.get("kind") == "issue":
            out.append(o.get("data", {}))
    return out


def _sink_pairs(issues):
    """Distinct (sink kind, sink callee) pairs reached — issue *coverage*.
    Pysa reports one issue per tainted argument flow into a sink call, so a
    call with two tainted arguments counts twice; the pair set is the stable
    measure of *what* the wall resolution made reachable."""
    pairs = set()
    for d in issues:
        for tr in d.get("traces", []):
            if tr.get("name") != "backward":
                continue
            for r in tr.get("roots", []):
                kinds = [k.get("kind") for k in r.get("kinds", [])]
                call = r.get("call") or {}
                callee = tuple(call.get("resolves_to") or ()) or ("<direct>",)
                for k in kinds:
                    pairs.add((k, callee[0]))
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
        print(f"  sink {k} via {callee}")


def cmd_table(a_out, b_out, stats_json):
    """Evaluation row: lowering statistics next to the A/B issue delta
    (IccTA's Beginning/Ending InfoStatistic + leak counts in one table)."""
    s = json.load(open(stats_json)) if os.path.exists(stats_json) else {}
    ia, ib = _issues(a_out), _issues(b_out)
    rows = [
        ("wall files", s.get("files", 0)),
        ("walls detected", s.get("walls_detected", 0)),
        ("  by idiom", ", ".join(f"{k}={v}" for k, v in (s.get("walls_by_idiom") or {}).items()) or "-"),
        ("  skipped (no forwardable args)", s.get("walls_skipped_no_args", 0)),
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
        ("distinct (sink kind, sink callee) cond_A", len(_sink_pairs(ia))),
        ("distinct (sink kind, sink callee) cond_B", len(_sink_pairs(ib))),
    ]
    w = max(len(r[0]) for r in rows)
    for k, v in rows:
        print(f"  {k.ljust(w)}  {v}")
    new_codes = collections.Counter(d.get("code") for d in ib) - collections.Counter(d.get("code") for d in ia)
    if new_codes:
        print("  new issues by code: " + ", ".join(f"{c}={n}" for c, n in sorted(new_codes.items())))
    for k, callee in sorted(_sink_pairs(ib) - _sink_pairs(ia)):
        print(f"  newly reached sink: {k} via {callee}")


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
    else:
        sys.exit(f"unknown subcommand: {cmd!r}")
