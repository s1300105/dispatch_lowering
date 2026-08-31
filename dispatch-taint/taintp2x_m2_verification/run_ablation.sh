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
TYPESHED="${TYPESHED:-$ROOT/.venv/lib/pyre_check/typeshed}"
EXT="${EXT:-$ROOT/dispatch-taint/taintp2x_extension}"    # dispatch_lowering.py lives here
HELP="${HELP:-$HERE/ablation_helpers.py}"

# ---- target-specific (REQUIRED) ---------------------------------------------
#   TARGET_SRC : dir whose contents Pysa analyzes (the source subset). Copied to cond/src.
#   WALL_FILES : space-separated paths RELATIVE to TARGET_SRC, to apply lowering to.
#   PYSA_MODELS: a .pysa file declaring the SOURCE (and any sinks not in the host catalog).
#   SPEC_JSON  : lowering spec (legacy keys = original detection/candidate rules; new keys = general).
#   CAND_DIR   : dir scanned for resolved-target callables. Default: the wall tree itself,
#                $WORK/cond_B/src (review C4 / K6 — scanning TARGET_SRC *and* its cond_B copy
#                saw every registry literal twice, untrusted it and silently dropped the
#                narrowing that the draft's dry run had applied).
TARGET_SRC="${TARGET_SRC:?set TARGET_SRC=/abs/path/to/source/subset}"
PYSA_MODELS="${PYSA_MODELS:?set PYSA_MODELS=/abs/path/to/target.pysa}"
CAND_DIR="${CAND_DIR:-}"
#   EMIT       : inline (default) | redirector  — generated-code form (overrides spec.emit)
#   LINKS_IN   : optional hand-written / saved links.json (skips automatic resolution)
EMIT="${EMIT:-}"
LINKS_IN="${LINKS_IN:-}"
#   Engine-driven workflow (docs/SCALE_OUT_DESIGN.md) — WALL_FILES / SPEC_JSON become optional:
#   DRAFT=1        : build + analyse cond_A, write the review bundle to $WORK/draft and STOP
#                    (exit = draft outcome: 0 ok, 2 no surface, 4 no sources, 5 nothing accepted);
#                    $WORK/draft also holds plan.draft.json, the read-only original that cmd_row
#                    diffs against the reviewed plan.json (review C7) — edit plan.json only, never
#                    copy plan.draft.json anywhere
#   PLAN_JSON=path : cond_B is lowered from a reviewed plan.json (pipeline.run_plan)
#   ACCEPT_DRAFT=1 : unattended — draft, then use $WORK/draft/plan.json as PLAN_JSON
#   DRAFT_ARGS     : extra draft.py options (e.g. "--preset langchain --include-proposed")
#   FORCE_DRAFT=1  : let a DRAFT=1 / ACCEPT_DRAFT=1 re-run discard a REVIEWED $WORK/draft/plan.json
#                    (one that differs from the read-only plan.draft.json); default: it is kept
DRAFT="${DRAFT:-}"
PLAN_JSON="${PLAN_JSON:-}"
ACCEPT_DRAFT="${ACCEPT_DRAFT:-}"
DRAFT_ARGS="${DRAFT_ARGS:-}"
FORCE_DRAFT="${FORCE_DRAFT:-}"
WALL_FILES="${WALL_FILES:-}"
SPEC_JSON="${SPEC_JSON:-}"
if [ -z "$DRAFT$PLAN_JSON$ACCEPT_DRAFT" ]; then
  : "${WALL_FILES:?set WALL_FILES='relpath_under_TARGET_SRC ...' (or use DRAFT=1 / PLAN_JSON / ACCEPT_DRAFT=1)}"
  : "${SPEC_JSON:?set SPEC_JSON=/abs/path/to/spec.json (or use DRAFT=1 / PLAN_JSON / ACCEPT_DRAFT=1)}"
fi

WORK="${WORK:-$HERE/ablation_out}"
EXPECT_A="${EXPECT_A:-}"     # optional regression assertions (raw issue counts)
EXPECT_B="${EXPECT_B:-}"
EXPECT_SINKS_B="${EXPECT_SINKS_B:-}"   # optional: distinct (sink kind, first hop) pairs in cond_B (legacy gate, SINK_FIRST_HOPS;
                                       # row.json / summary use the K5 key (sink kind, issue callable) = SINK_PAIRS)

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

PYRE_TIMEOUT="${PYRE_TIMEOUT:-1200}"   # seconds per pyre run (TaintP2X's budget); 0 = no limit
REUSE_COND_A="${REUSE_COND_A:-}"       # 1: keep an existing $WORK/cond_A (+ its r/) instead of rebuilding
run_pyre() {
  local t0 t1 rc
  t0=$(date +%s)
  rc=0
  if [ "$PYRE_TIMEOUT" != "0" ]; then
    ( cd "$1" && rm -rf r && timeout "$PYRE_TIMEOUT" pyre analyze --no-verify --save-results-to ./r >"$1/pyre.log" 2>&1 ) || rc=$?
  else
    ( cd "$1" && rm -rf r && pyre analyze --no-verify --save-results-to ./r >"$1/pyre.log" 2>&1 ) || rc=$?
  fi
  t1=$(date +%s)
  # review M5: the wall-clock seconds reach row.json (pyre_seconds) even when pyre
  # timed out or failed; the exit status (124 = timeout) is kept beside them
  echo $(( t1 - t0 )) > "$1/pyre_seconds"
  echo "$rc" > "$1/pyre_rc"
}
issues()   { python3 "$HELP" count "$1/r/taint-output.json" | sed -n 's/^ISSUES=//p'; }
# review M5: no taint-output.json after a pyre run means the analysis failed or
# timed out. Write the row (env_failed, with the pyre seconds) and stop with a
# clear message — never let ``issues()`` count it as 0 (cond_B "issues = 0",
# delta -1289) and exit 0. Args: cond dir, label.
require_output() {
  [ -f "$1/r/taint-output.json" ] && return 0
  local rc secs why
  rc="$(cat "$1/pyre_rc" 2>/dev/null || echo '?')"
  secs="$(cat "$1/pyre_seconds" 2>/dev/null || echo '?')"
  why="pyre rc=$rc"; [ "$rc" = 124 ] && why="pyre timed out (PYRE_TIMEOUT=${PYRE_TIMEOUT}s)"
  EXT="$EXT" python3 "$HELP" row "$WORK" "$WORK/row.json" || true
  die "$2 analysis produced no taint-output.json ($why, ${secs}s; env_failed) — see $1/pyre.log; row written to $WORK/row.json"
}

# ---- 0. preflight -----------------------------------------------------------
say "=== 0. preflight ==="
command -v pyre >/dev/null 2>&1 || die "pyre not found (activate the .venv)"
[ -d "$TP2X/taint" ]  || die "host taint defs missing: $TP2X/taint"
[ -d "$TP2X/stubs" ]  || die "host stubs missing: $TP2X/stubs"
[ -d "$TYPESHED" ]    || die "typeshed missing: $TYPESHED"
[ -f "$EXT/dispatch_lowering.py" ] || die "dispatch_lowering.py missing: $EXT"
[ -f "$HELP" ]        || die "ablation_helpers.py missing: $HELP"
[ -d "$TARGET_SRC" ]  || die "TARGET_SRC missing: $TARGET_SRC"
[ -z "$CAND_DIR" ] || [ -d "$CAND_DIR" ] || die "CAND_DIR missing: $CAND_DIR"
[ -z "$PLAN_JSON" ] || [ "$(basename "$PLAN_JSON")" != "plan.draft.json" ] \
  || die "PLAN_JSON must be the reviewed plan.json, not the read-only plan.draft.json (review C7: review_edits diffs the two)"
[ -f "$PYSA_MODELS" ] || die "PYSA_MODELS missing: $PYSA_MODELS"
[ -z "$SPEC_JSON" ] || [ -f "$SPEC_JSON" ] || die "SPEC_JSON missing: $SPEC_JSON"
[ -z "$PLAN_JSON" ] || [ -f "$PLAN_JSON" ] || die "PLAN_JSON missing: $PLAN_JSON"
[ -f "$EXT/engine_walls.py" ] || die "engine_walls.py missing: $EXT"
echo "OK"

# ---- 1. cond_A (baseline) ---------------------------------------------------
if [ -n "$REUSE_COND_A" ] && [ -f "$WORK/cond_A/r/taint-output.json" ]; then
  say "=== 1-2. reusing $WORK/cond_A (REUSE_COND_A=1) ==="
else
say "=== 1. build cond_A (host alone) ==="
rm -rf "$WORK/cond_A"
mkdir -p "$WORK/cond_A/src" "$WORK/cond_A/source"
cp -r "$TARGET_SRC/." "$WORK/cond_A/src/"
cp "$PYSA_MODELS" "$WORK/cond_A/source/"
python3 "$HELP" config "$WORK/cond_A" "$TP2X" "$TYPESHED"

say "=== 2. analyze cond_A ==="
run_pyre "$WORK/cond_A"
fi
require_output "$WORK/cond_A" "cond_A"
A="$(issues "$WORK/cond_A")"; echo "cond_A issues = $A  (pyre $(cat "$WORK/cond_A/pyre_seconds")s)"

# ---- 2b. engine-driven draft (no extra pyre run) ----------------------------
if [ -n "$DRAFT$ACCEPT_DRAFT" ]; then
  say "=== 2b. draft the lowering plan from cond_A's results ==="
  # review C7: $WORK/draft/plan.json is the plan the reviewer edits in place;
  # draft.write_bundle keeps the untouched original as the read-only
  # plan.draft.json (cmd_row diffs the two for review_edits). A plan.json that
  # differs from its plan.draft.json carries review work: a re-run keeps it
  # unless FORCE_DRAFT=1 says to throw it away.
  if [ -z "$FORCE_DRAFT" ] && [ -f "$WORK/draft/plan.json" ] && [ -f "$WORK/draft/plan.draft.json" ] \
     && ! cmp -s "$WORK/draft/plan.json" "$WORK/draft/plan.draft.json"; then
    echo "kept reviewed plan: $WORK/draft/plan.json differs from plan.draft.json (not re-drafted; FORCE_DRAFT=1 to discard it)"
    DCODE=0
  else
    rm -rf "$WORK/draft"
    set +e
    # shellcheck disable=SC2086
    python3 "$HELP" draft "$EXT" "$WORK/cond_A" "$WORK/draft" $DRAFT_ARGS
    DCODE=$?
    set -e
    echo "draft exit = $DCODE  (0 ok, 2 no surface, 4 no sources, 5 nothing accepted)"
  fi
  if [ -n "$DRAFT" ]; then
    echo "review: $WORK/draft/walls.md  and  $WORK/draft/plan.json"
    echo "then:   PLAN_JSON=$WORK/draft/plan.json $(basename "$0")"
    python3 "$HELP" row "$WORK" "$WORK/row.json" || true
    exit "$DCODE"
  fi
  [ "$DCODE" = 0 ] || die "ACCEPT_DRAFT: draft outcome $DCODE — nothing to lower unattended"
  PLAN_JSON="$WORK/draft/plan.json"
fi

# ---- 3. cond_B (+ wall resolution) ------------------------------------------
say "=== 3. build cond_B (+ wall resolution) ==="
rm -rf "$WORK/cond_B"; cp -r "$WORK/cond_A" "$WORK/cond_B"; rm -rf "$WORK/cond_B/r"
# review C4 (K6): candidates and registries are recovered from the wall tree itself
CAND_DIR="${CAND_DIR:-$WORK/cond_B/src}"
WF_ABS=(); for wf in $WALL_FILES; do WF_ABS+=("$WORK/cond_B/src/$wf"); done
# review C7: cond_B/plan.json is the plan that was actually lowered (the reviewed
# one) — only that file is copied; plan.draft.json stays in $WORK/draft
[ -z "$PLAN_JSON" ] || cp "$PLAN_JSON" "$WORK/cond_B/plan.json"
SRC_ROOT="$WORK/cond_B/src" EMIT="$EMIT" LINKS_IN="$LINKS_IN" PLAN_JSON="$PLAN_JSON" \
  LINKS_OUT="$WORK/cond_B/links.json" STATS_OUT="$WORK/cond_B/stats.json" \
  python3 "$HELP" lower "$EXT" "$CAND_DIR" "$SPEC_JSON" ${WF_ABS[@]+"${WF_ABS[@]}"}
python3 "$HELP" config "$WORK/cond_B" "$TP2X" "$TYPESHED"

say "=== 4. cond_A vs cond_B diff (expect only the wall file(s) [+ __ctaudit_redirect.py]) ==="
diff -rq "$WORK/cond_A/src" "$WORK/cond_B/src" || true

say "=== 5. analyze cond_B ==="
run_pyre "$WORK/cond_B"
require_output "$WORK/cond_B" "cond_B"     # review M5: mirrors the cond_A guard
B="$(issues "$WORK/cond_B")"; echo "cond_B issues = $B  (pyre $(cat "$WORK/cond_B/pyre_seconds")s)"

# ---- 6. breakdown + delta ---------------------------------------------------
say "=== 6. cond_B issue breakdown ==="
python3 "$HELP" count "$WORK/cond_B/r/taint-output.json"

say "=== 7. lowering statistics + A/B table ==="
python3 "$HELP" table "$WORK/cond_A/r/taint-output.json" "$WORK/cond_B/r/taint-output.json" "$WORK/cond_B/stats.json" \
  "$WORK/cond_B/links.json" "$WORK/cond_B"

say "=== 8. row.json (one target = one row) ==="
EXT="$EXT" python3 "$HELP" row "$WORK" "$WORK/row.json"

say "=== RESULT ==="
echo "host alone            (cond_A): $A issues"
echo "host + wall resolution(cond_B): $B issues"
echo "delta from wall resolution    : $(( B - A ))"
echo "outputs: $WORK/cond_{A,B}/r/taint-output.json  links: $WORK/cond_B/links.json  stats: $WORK/cond_B/stats.json"

# review C2 / K5: ``count`` prints SINK_PAIRS (K5 key) and SINK_FIRST_HOPS (legacy first-hop key);
# the AutoGPT regression (EXPECT_SINKS_B=5) is defined on the legacy key
SB="$(python3 "$HELP" count "$WORK/cond_B/r/taint-output.json" | sed -n 's/^SINK_FIRST_HOPS=//p')"
[ -n "$EXPECT_A" ] && { [ "$A" = "$EXPECT_A" ] || die "regression: cond_A expected $EXPECT_A, got $A"; }
[ -n "$EXPECT_B" ] && { [ "$B" = "$EXPECT_B" ] || die "regression: cond_B expected $EXPECT_B, got $B"; }
[ -n "$EXPECT_SINKS_B" ] && { [ "$SB" = "$EXPECT_SINKS_B" ] || die "regression: cond_B expected $EXPECT_SINKS_B distinct sink pairs, got $SB"; }
[ -n "$EXPECT_A$EXPECT_B$EXPECT_SINKS_B" ] && echo "regression OK"
exit 0
