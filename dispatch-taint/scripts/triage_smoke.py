#!/usr/bin/env python3
"""Live smoke test for the LLM-triage backend (§4.6).

Runs the *real* AnthropicTriage path end-to-end on a file's findings and prints
the verdicts plus a diagnosis of whether the live API was actually reached.

Usage
-----
    # genuine end-to-end live call (needs a real key):
    ANTHROPIC_API_KEY=sk-ant-... python scripts/triage_smoke.py
    ANTHROPIC_API_KEY=sk-ant-... python scripts/triage_smoke.py path/to/agent.py
    CTAUDIT_TRIAGE_MODEL=claude-sonnet-4-5-20250929 ANTHROPIC_API_KEY=... \
        python scripts/triage_smoke.py

Without a key (or without the `anthropic` SDK) the backend degrades gracefully to
the offline mock; this script detects and reports that rather than failing, so it
is safe to run in any environment.

Exit code is 0 on a clean run (live or fallback), 2 if the target produced no
findings to triage.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# allow running from a source checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctaudit import analyze_path                       # noqa: E402
from ctaudit.triage.llm_triage import AnthropicTriage  # noqa: E402

_DEFAULT = Path(__file__).resolve().parent.parent / "fixtures" / "langchain_2tool_vuln.py"


def _sdk_present() -> bool:
    try:
        import anthropic  # noqa: F401
        return True
    except Exception:
        return False


def main(argv) -> int:
    target = argv[1] if len(argv) > 1 else str(_DEFAULT)

    print("=" * 70)
    print("ctaudit — LLM-triage live smoke test (§4.6)")
    print("=" * 70)
    print(f"target            : {target}")
    print(f"anthropic SDK     : {'installed' if _sdk_present() else 'NOT installed'}")
    print(f"ANTHROPIC_API_KEY : {'set' if os.environ.get('ANTHROPIC_API_KEY') else 'NOT set'}")

    # 1. collect findings WITHOUT triage.
    result = analyze_path(target, do_triage=False)
    findings = [f for f in result.findings if not f.pruned]
    print(f"findings to triage: {len(findings)}")
    if not findings:
        print("\nno (kept) findings to triage — pick a target with a cross-tool flow.")
        return 2

    # 2. run the real AnthropicTriage backend.
    triager = AnthropicTriage()
    model = triager.model
    live_client = triager._client is not None
    print(f"triage model      : {model}")
    print(f"live client built : {live_client}")

    t0 = time.time()
    triager.triage(findings, source=_read(target))
    dt = time.time() - t0
    print(f"triage wall time  : {dt:.2f}s")

    # 3. diagnose: did we actually reach the API, or fall back?
    rationales = [f.triage_rationale or "" for f in findings]
    fell_back = any(r.startswith("[anthropic") for r in rationales)
    if not live_client:
        mode = "FALLBACK (no key/SDK) — offline mock was used"
    elif fell_back:
        mode = "LIVE PATH REACHED, but the call did not complete (see annotation) — fell back per finding"
    else:
        mode = "LIVE — a real model verdict was returned"
    print(f"\nresult mode       : {mode}\n")

    for i, f in enumerate(findings, 1):
        print(f"[{i}] {f.sink_name}  ({f.severity})  <- {', '.join(f.source_tools)}")
        print(f"    verdict   : {f.triage_verdict}  (confidence {f.triage_confidence})")
        print(f"    rationale : {(f.triage_rationale or '')[:200]}")

    print("\ndone.")
    return 0


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
