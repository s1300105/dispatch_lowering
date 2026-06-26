#!/usr/bin/env bash
# run_sink_probes.sh — confirm which sink CLASSES fire end-to-end under the TaintP2X config.
#
# Direct source->sink probes (no dispatch wall, no lowering): isolates "does each sink
# class fire" from the (already-validated) dispatch resolution. Prints the rule codes and
# an OK/MISSING check for SSRF / deserialize / file-write / SQL (+ RCE as a positive control).
#
# PREREQS (do these first):
#   1) Activate the analysis venv so `pyre` is on PATH and VIRTUAL_ENV is set
#      (VIRTUAL_ENV makes site-packages get added to search_path -> requests/yaml resolve):
#        source "$ROOT/.venv/bin/activate"
#   2) Install the HTTP/deser libs in that venv so the sink models bind and imports resolve:
#        pip install requests pyyaml httpx aiohttp
#   3) Put ssrf_sinks_ext.pysa into  $TP2X/taint/   (so urllib/httpx/aiohttp SSRF fire)
#
# RUN (from a dir containing sink_probes.py and sink_probes.pysa):
#   bash run_sink_probes.sh
set -euo pipefail

# ---- paths (override via env; defaults match the known layout) ----
ROOT="${ROOT:-$HOME/Project/research/Master_Project/dispatch-taint-system/dispatch-taint}"
TP2X="${TP2X:-$ROOT/TaintP2X/Taint_Propagation}"
TYPESHED="${TYPESHED:-$ROOT/.venv/lib/pyre_check/typeshed}"
PROBE_PY="${PROBE_PY:-./sink_probes.py}"
PROBE_PYSA="${PROBE_PYSA:-./sink_probes.pysa}"
WORK="${WORK:-/tmp/ctaudit_sink_probes}"

command -v pyre >/dev/null 2>&1 || { echo "ERROR: pyre not found — activate the analysis .venv first"; exit 1; }
[ -n "${VIRTUAL_ENV:-}" ] || echo "WARN: VIRTUAL_ENV not set — site-packages won't be added; requests/yaml may not resolve."
[ -d "$TP2X/taint" ] || { echo "ERROR: TP2X taint dir missing: $TP2X/taint"; exit 1; }
[ -f "$PROBE_PY" ]   || { echo "ERROR: missing $PROBE_PY"; exit 1; }
[ -f "$PROBE_PYSA" ] || { echo "ERROR: missing $PROBE_PYSA"; exit 1; }
[ -f "$TP2X/taint/ssrf_sinks_ext.pysa" ] || echo "WARN: ssrf_sinks_ext.pysa not in $TP2X/taint — urllib/httpx SSRF probes may be MISSING."

# ---- build the project ----
rm -rf "$WORK"; mkdir -p "$WORK/src" "$WORK/source"
cp "$PROBE_PY"   "$WORK/src/"
cp "$PROBE_PYSA" "$WORK/source/"

# ---- write .pyre_configuration (same shape as the ablation harness) ----
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
print("[probe] wrote", os.path.join(target, ".pyre_configuration"))
PY

# ---- run Pysa ----
( cd "$WORK" && rm -rf r && pyre analyze --no-verify --save-results-to ./r >/dev/null 2>&1 ) \
  || { echo "ERROR: pyre analyze failed. Re-run without redirection to see why:"; echo "  ( cd $WORK && pyre analyze --no-verify --save-results-to ./r )"; exit 1; }

# ---- report codes + class check ----
python3 - "$WORK/r/taint-output.json" <<'PY'
import json, sys, collections
codes = collections.Counter()
for line in open(sys.argv[1]):
    line = line.strip().rstrip(",")
    if not line or line in ("[", "]"): continue
    try: o = json.loads(line)
    except Exception: continue
    if o.get("kind") == "issue":
        codes[o.get("data", {}).get("code")] += 1
print("=== codes fired ===")
for c, n in sorted(codes.items(), key=lambda kv: (kv[0] is None, kv[0])):
    print(f"  code {c}: {n}")
want = {5001: "RCE (control)", 5015: "SSRF", 5003: "deserialize", 5010: "file-write", 5008: "SQL"}
print("=== class check ===")
ok = True
for c, name in want.items():
    hit = codes.get(c, 0)
    if not hit and c != 5001: ok = False
    print(f"  [{'OK' if hit else 'MISSING'}] {c} {name}: {hit}")
print("=== verdict:", "ALL TARGET CLASSES ARMED" if ok else "SOME CLASSES MISSING (see above)", "===")
PY
