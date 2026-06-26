#!/usr/bin/env bash
# Fetch the in-scope (multi-tool-agent / dynamic-dispatch) CVE repos for the TaintP2X
# comparison into ./cve_corpus/<name>. Run on YOUR machine (not the sandbox).
#
#   bash scripts/fetch_cve_corpus.sh [TARGET_DIR]   # default ./cve_corpus
#
# VERIFY each checkout: tags move and some repos are commit-versioned. Where a tag is
# wrong, find the vulnerable ref from the NVD/huntr advisory and `git checkout` it by hand.
set -u
DEST="${1:-./cve_corpus}"
mkdir -p "$DEST"

clone() {  # clone <owner/name> <ref> [shallow-ok]
  local slug="$1" ref="$2" name dir
  name="$(basename "$slug")"; dir="$DEST/$name"
  if [ -d "$dir/.git" ]; then echo "== $name: already present ($dir)"; return; fi
  echo "== $name: cloning $slug @ $ref"
  git clone --quiet "https://github.com/$slug.git" "$dir" || { echo "  !! clone failed"; return; }
  ( cd "$dir" && git checkout --quiet "$ref" 2>/dev/null \
      && echo "  checked out $ref" \
      || echo "  !! ref '$ref' not found — checkout the advisory's tag/commit manually in $dir" )
}

# CVE-2024-1881  (TaintP2X MISSED) — command registry / dynamic dispatch
clone "Significant-Gravitas/AutoGPT" "v0.5.0"
#   NOTE: the package may live under autogpts/autogpt/ — set src_rel accordingly in cve_cases.py.

# CVE-2024-23750 — multi-agent framework
clone "geekan/MetaGPT" "v0.6.3"

# CVE-2025-2733 — tool-using agent (both dynamic baselines failed to run it)
clone "FoundationAgents/OpenManus" "main"
#   NOTE: pin to the advisory's commit (~2025.3.13). Repo formerly mannaandpoem/OpenManus.

# HUNTR (no CVE) — agent file-write tool
clone "TransformerOptimus/SuperAGI" "v0.0.14"

# CVE-2024-5927 / 5821 / 6331 — agentic SWE assistant (commit-versioned)
clone "stitionai/devika" "main"
#   NOTE: Devika has no release tags — checkout the commit referenced by each advisory.

echo
echo "Done. Repos are in $DEST — inspect each checkout, then run dispatch_lowering"
echo "on the target and pyre analyze to detect taint flows."
