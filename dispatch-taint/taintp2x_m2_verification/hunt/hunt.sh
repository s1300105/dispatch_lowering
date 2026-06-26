#!/usr/bin/env bash
# hunt.sh — run ctaudit/Pysa over a target MCP server in Mode 2 (tool-param sources).
#
# Sources every @tool function parameter as LLMControlled (via gen_tool_sources.py),
# then runs Pysa with the TaintP2X taint config (+ your ssrf_sinks_ext.pysa) and reports
# findings grouped by rule code and by tool. Framework-agnostic (mcp SDK or standalone fastmcp).
#
# PREREQS:
#   * analysis .venv active (pyre on PATH, VIRTUAL_ENV set)
#   * sink libs + the target's own deps installed in that venv so imports/sinks resolve, e.g.:
#       pip install mcp fastmcp requests pyyaml httpx aiohttp   # plus the target's requirements
#   * ssrf_sinks_ext.pysa already copied into  <Taint_Propagation>/taint/
#   * gen_tool_sources.py next to this script
#
# USAGE:
#   bash hunt.sh /abs/path/to/cloned/repo            # TARGET = import root (dir holding the server module/package)
#   TP2X=/abs/path/to/Taint_Propagation bash hunt.sh /abs/path/to/repo   # if auto-locate misses
set -euo pipefail

TARGET="${1:?usage: hunt.sh /abs/path/to/target/repo (the import root)}"
ROOT="${ROOT:-$HOME/Project/research/Master_Project/dispatch-taint-system}"
GEN="${GEN:-$(dirname "$0")/gen_tool_sources.py}"
WORK="${WORK:-/tmp/ctaudit_hunt}"

command -v pyre >/dev/null 2>&1 || { echo "ERROR: pyre not found — activate the analysis .venv"; exit 1; }
[ -n "${VIRTUAL_ENV:-}" ] || { echo "ERROR: VIRTUAL_ENV not set — activate the analysis .venv"; exit 1; }
[ -d "$TARGET" ] || { echo "ERROR: TARGET not a directory: $TARGET"; exit 1; }
[ -f "$GEN" ] || { echo "ERROR: gen_tool_sources.py not found at $GEN (set GEN=...)"; exit 1; }

# typeshed from the active venv
TYPESHED="${TYPESHED:-$VIRTUAL_ENV/lib/pyre_check/typeshed}"
[ -d "$TYPESHED" ] || TYPESHED="$(find "$VIRTUAL_ENV" -type d -path '*pyre_check/typeshed' 2>/dev/null | head -1)"
[ -d "$TYPESHED" ] || { echo "ERROR: typeshed not found under venv (set TYPESHED=...)"; exit 1; }

# TaintP2X Taint_Propagation (auto-locate by taint.config if not valid)
if [ -z "${TP2X:-}" ] || [ ! -d "$TP2X/taint" ]; then
  for sr in "$ROOT" "$(dirname "$ROOT")" "$HOME/Project/research/Master_Project"; do
    cfg="$(find "$sr" -type f -path '*Taint_Propagation/taint/taint.config' 2>/dev/null | head -1)"
    [ -n "$cfg" ] && { TP2X="$(dirname "$(dirname "$cfg")")"; break; }
  done
fi
[ -d "${TP2X:-}/taint" ] || { echo "ERROR: locate Taint_Propagation and pass TP2X=..."; exit 1; }
[ -f "$TP2X/taint/ssrf_sinks_ext.pysa" ] || echo "WARN: ssrf_sinks_ext.pysa not in $TP2X/taint — urllib/httpx SSRF will be missed."
echo "[hunt] TARGET=$TARGET"
echo "[hunt] TP2X=$TP2X"

# 1) build project (copy target so generated module paths match source_directories)
rm -rf "$WORK"; mkdir -p "$WORK/src" "$WORK/source"
cp -r "$TARGET/." "$WORK/src/"

# 2) generate tool-param source models from the copied src
python3 "$GEN" "$WORK/src" > "$WORK/source/tool_sources.pysa" 2> "$WORK/tools_found.txt"
cat "$WORK/tools_found.txt"
grep -q "def " "$WORK/source/tool_sources.pysa" || { echo "ERROR: no tool sources generated — see warning above. Add manual models to $WORK/source/ and re-run pyre."; exit 1; }

# 3) pyre configuration (same shape as the ablation harness)
python3 - "$WORK" "$TP2X" "$TYPESHED" <<'PY'
import json, os, sys, glob
target, tp2x, typeshed = sys.argv[1:4]
search = [os.path.join(tp2x, "stubs")]
venv = os.environ.get("VIRTUAL_ENV")
if venv:
    search += glob.glob(os.path.join(venv, "lib", "python*", "site-packages"))
cfg = {
    "source_directories": [os.path.join(target, "src")],
    "taint_models_path": [os.path.join(tp2x, "taint"), os.path.join(target, "source")],
    "search_path": search,
    "typeshed": typeshed,
    "strict": False,
}
json.dump(cfg, open(os.path.join(target, ".pyre_configuration"), "w"), indent=2)
print("[hunt] wrote", os.path.join(target, ".pyre_configuration"))
PY

# 4) analyze
( cd "$WORK" && rm -rf r && pyre analyze --no-verify --save-results-to ./r >/dev/null 2>&1 ) \
  || { echo "ERROR: pyre analyze failed. Re-run to see why:  ( cd $WORK && pyre analyze --no-verify --save-results-to ./r )"; exit 1; }

# 5) report — group by (code, tool/callable) and list detail
python3 - "$WORK/r/taint-output.json" <<'PY'
import json, sys, collections
CODES = {5001:"RCE/eval", 5002:"import", 5003:"deserialize", 5004:"file-deser",
         5005:"cmd-arg", 5006:"cmd-env", 5008:"SQL", 5010:"file-write/traversal",
         5012:"format-str", 5015:"SSRF"}
issues = []
for line in open(sys.argv[1]):
    line = line.strip().rstrip(",")
    if not line or line in ("[", "]"): continue
    try: o = json.loads(line)
    except Exception: continue
    if o.get("kind") == "issue":
        d = o.get("data", {})
        issues.append((d.get("code"), str(d.get("callable", "")), d.get("message", "")))
if not issues:
    print("=== no findings ===  (no tool-arg -> sink flow surfaced)")
    sys.exit(0)
by_ct = collections.Counter((c, who) for c, who, _ in issues)
print(f"=== {len(issues)} finding(s) — by (code, tool) ===")
for (c, who), n in sorted(by_ct.items(), key=lambda kv: (kv[0][0] is None, kv[0][0])):
    print(f"  [{c} {CODES.get(c,'?')}]  {who}   x{n}")
print("=== detail ===")
for c, who, msg in issues:
    print(f"  [{c} {CODES.get(c,'?')}] {who}")
    if msg: print(f"        {msg[:160]}")
print("\nNEXT: for each finding, confirm (1) the param is attacker-reachable, (2) the sink is")
print("unguarded as reached, (3) write a minimal local PoC, (4) check it's unreported, then report via Huntr.")
PY
