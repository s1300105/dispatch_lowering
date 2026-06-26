"""Helpers for run_ablation.sh — invoked as subcommands (no heredocs needed).

    python3 ablation_helpers.py config <target_dir> <tp2x> <typeshed>
    python3 ablation_helpers.py lower  <ext_dir> <cand_dir> <spec_json> <wall_file>...
    python3 ablation_helpers.py count  <taint_output.json>
"""
import ast
import collections
import importlib.util
import json
import os
import sys


def _load_dl(ext_dir):
    path = os.path.join(ext_dir, "dispatch_lowering.py")
    spec = importlib.util.spec_from_file_location("dispatch_lowering", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dispatch_lowering"] = mod      # needed for dataclass type resolution
    spec.loader.exec_module(mod)
    return mod


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
    """Collect candidates, report detected walls, apply wall resolution in place."""
    dl = _load_dl(ext_dir)
    spec = {}
    if spec_json and os.path.exists(spec_json):
        spec = json.load(open(spec_json))
    cands = dl.collect_candidates(cand_dir, spec)
    print(f"[ctaudit] collected {len(cands)} candidate target(s) from {cand_dir}")
    if not cands:
        print("[ctaudit] WARNING: 0 candidates — check spec (tool_decorators / "
              "scan_all_callables) and CAND_DIR. Lowering will be a no-op.")
    for wf in wall_files:
        src = open(wf).read()
        walls = dl.describe_walls(src, spec)
        rel = os.path.relpath(wf)
        print(f"[ctaudit] {rel}: {len(walls)} wall(s) detected")
        for ln, idiom, callee in walls:
            print(f"           L{ln} [{idiom}] {callee}")
        open(wf, "w").write(dl.lower_wall_file(src, cands, spec))


def cmd_count(taint_output):
    """Count kind=='issue' records in pyre's taint-output.json (array, 1 obj/line)."""
    codes = collections.Counter()
    callables = collections.Counter()
    total = 0
    for line in open(taint_output):
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        if o.get("kind") == "issue":
            total += 1
            d = o.get("data", {})
            codes[d.get("code")] += 1
            callables[str(d.get("callable", ""))] += 1
    print(f"ISSUES={total}")
    for c, n in sorted(codes.items(), key=lambda kv: (kv[0] is None, kv[0])):
        print(f"  code {c}: {n}")
    for c, n in callables.items():
        print(f"  callable {c}: {n}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "config":
        cmd_config(*sys.argv[2:])
    elif cmd == "lower":
        cmd_lower(*sys.argv[2:])
    elif cmd == "count":
        cmd_count(*sys.argv[2:])
    else:
        sys.exit(f"unknown subcommand: {cmd!r}")
