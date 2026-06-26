#!/usr/bin/env bash
# =============================================================================
# run_ablation.sh — generic dynamic-dispatch wall-resolution ablation
#
#   Measures the DELTA that wall resolution adds to the host analyzer
#   (TaintP2X / Pysa) on an arbitrary target:
#       cond_A = host alone (baseline)
#       cond_B = host + wall resolution (dispatch_lowering applied to WALL_FILES)
#   The only difference between the two conditions is the lowering insertion;
#   taint defs, source/sink declaration and analysis config are identical.
#
#   Generalised from reproduce_m2.sh (AutoGPT-specific) — config-driven, no
#   hardcoded spec or target. Python steps are in ablation_helpers.py (no heredocs).
#
#   Place this script and ablation_helpers.py together (e.g. in
#   taintp2x_m2_verification/). Set the REQUIRED env vars below, then run it.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- environment (override as needed) ---------------------------------------
ROOT="${ROOT:-$(cd "$HERE/../.." && pwd)}"                 # dispatch-taint-system/
TP2X="${TP2X:-$ROOT/TaintP2X/Taint_Propagation}"           # host taint defs + stubs
TYPESHED="${TYPESHED:-$ROOT/dispatch-taint/.venv/lib/pyre_check/typeshed}"
EXT="${EXT:-$ROOT/dispatch-taint/taintp2x_extension}"    # dispatch_lowering.py lives here
HELP="${HELP:-$HERE/ablation_helpers.py}"

# ---- target-specific (REQUIRED) ---------------------------------------------
#   TARGET_SRC : dir whose contents Pysa analyzes (the source subset). Copied to cond/src.
#   WALL_FILES : space-separated paths RELATIVE to TARGET_SRC, to apply lowering to.
#   PYSA_MODELS: a .pysa file declaring the SOURCE (and any sinks not in the host catalog).
#   SPEC_JSON  : lowering spec (legacy keys reproduce the original exactly; new keys = general).
#   CAND_DIR   : dir scanned for resolved-target callables (default: TARGET_SRC).
TARGET_SRC="${TARGET_SRC:?set TARGET_SRC=/abs/path/to/source/subset}"
WALL_FILES="${WALL_FILES:?set WALL_FILES='relpath_under_TARGET_SRC ...'}"
PYSA_MODELS="${PYSA_MODELS:?set PYSA_MODELS=/abs/path/to/target.pysa}"
SPEC_JSON="${SPEC_JSON:?set SPEC_JSON=/abs/path/to/spec.json}"
CAND_DIR="${CAND_DIR:-$TARGET_SRC}"

WORK="${WORK:-$HERE/ablation_out}"
EXPECT_A="${EXPECT_A:-}"     # optional regression assertions
EXPECT_B="${EXPECT_B:-}"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

run_pyre() { ( cd "$1" && rm -rf r && pyre analyze --no-verify --save-results-to ./r >/dev/null 2>&1 ); }
issues()   { python3 "$HELP" count "$1/r/taint-output.json" | sed -n 's/^ISSUES=//p'; }

# ---- 0. preflight -----------------------------------------------------------
say "=== 0. preflight ==="
command -v pyre >/dev/null 2>&1 || die "pyre not found (activate the .venv)"
[ -d "$TP2X/taint" ]  || die "host taint defs missing: $TP2X/taint"
[ -d "$TP2X/stubs" ]  || die "host stubs missing: $TP2X/stubs"
[ -d "$TYPESHED" ]    || die "typeshed missing: $TYPESHED"
[ -f "$EXT/dispatch_lowering.py" ] || die "dispatch_lowering.py missing: $EXT"
[ -f "$HELP" ]        || die "ablation_helpers.py missing: $HELP"
[ -d "$TARGET_SRC" ]  || die "TARGET_SRC missing: $TARGET_SRC"
[ -d "$CAND_DIR" ]    || die "CAND_DIR missing: $CAND_DIR"
[ -f "$PYSA_MODELS" ] || die "PYSA_MODELS missing: $PYSA_MODELS"
[ -f "$SPEC_JSON" ]   || die "SPEC_JSON missing: $SPEC_JSON"
echo "OK"

# ---- 1. cond_A (baseline) ---------------------------------------------------
say "=== 1. build cond_A (host alone) ==="
rm -rf "$WORK/cond_A"
mkdir -p "$WORK/cond_A/src" "$WORK/cond_A/source"
cp -r "$TARGET_SRC/." "$WORK/cond_A/src/"
cp "$PYSA_MODELS" "$WORK/cond_A/source/"
python3 "$HELP" config "$WORK/cond_A" "$TP2X" "$TYPESHED"

say "=== 2. analyze cond_A ==="
run_pyre "$WORK/cond_A"
A="$(issues "$WORK/cond_A")"; echo "cond_A issues = $A"

# ---- 3. cond_B (+ wall resolution) ------------------------------------------
say "=== 3. build cond_B (+ wall resolution) ==="
rm -rf "$WORK/cond_B"; cp -r "$WORK/cond_A" "$WORK/cond_B"; rm -rf "$WORK/cond_B/r"
WF_ABS=(); for wf in $WALL_FILES; do WF_ABS+=("$WORK/cond_B/src/$wf"); done
python3 "$HELP" lower "$EXT" "$CAND_DIR" "$SPEC_JSON" "${WF_ABS[@]}"
python3 "$HELP" config "$WORK/cond_B" "$TP2X" "$TYPESHED"

say "=== 4. cond_A vs cond_B diff (expect only the wall file(s)) ==="
diff -rq "$WORK/cond_A/src" "$WORK/cond_B/src" || true

say "=== 5. analyze cond_B ==="
run_pyre "$WORK/cond_B"
B="$(issues "$WORK/cond_B")"; echo "cond_B issues = $B"

# ---- 6. breakdown + delta ---------------------------------------------------
say "=== 6. cond_B issue breakdown ==="
python3 "$HELP" count "$WORK/cond_B/r/taint-output.json"

say "=== RESULT ==="
echo "host alone            (cond_A): $A issues"
echo "host + wall resolution(cond_B): $B issues"
echo "delta from wall resolution    : $(( B - A ))"
echo "outputs: $WORK/cond_{A,B}/r/taint-output.json"

[ -n "$EXPECT_A" ] && { [ "$A" = "$EXPECT_A" ] || die "regression: cond_A expected $EXPECT_A, got $A"; }
[ -n "$EXPECT_B" ] && { [ "$B" = "$EXPECT_B" ] || die "regression: cond_B expected $EXPECT_B, got $B"; }
[ -n "$EXPECT_A$EXPECT_B" ] && echo "regression OK"
exit 0
