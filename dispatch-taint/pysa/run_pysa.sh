#!/usr/bin/env bash
# One-shot: validate models -> run Pysa.
# Results are written as raw JSON to $RESULTS; inspect with jq or pyre's own viewer.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
RESULTS="${1:-./pysa-results}"

echo "[1/2] validating taint models (syntax)..."
pyre validate-models || echo "  (validate-models not available in this pyre version; continuing)"

echo "[2/2] running Pysa  ->  $RESULTS"
pyre analyze --save-results-to "$RESULTS"
