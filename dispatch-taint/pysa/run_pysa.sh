#!/usr/bin/env bash
# One-shot: validate models -> run Pysa -> post-process into ctaudit findings.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
RESULTS="${1:-./pysa-results}"

echo "[1/3] validating taint models (syntax)..."
pyre validate-models || echo "  (validate-models not available in this pyre version; continuing)"

echo "[2/3] running Pysa  ->  $RESULTS"
pyre analyze --save-results-to "$RESULTS"

echo "[3/3] post-processing Pysa output into ctaudit cross-tool findings"
python3 postprocess.py "$RESULTS" --implicit-only "${@:2}"
