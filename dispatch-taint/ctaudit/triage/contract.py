"""Structured finding contract for LLM triage (§4.6).

The borrowed precision-recovery technique (ZeroFalse / BugLens / IRIS) works by
handing the LLM the static finding as a *structured contract* — flow-sensitive
trace, sink signature, the tainted argument expression, surrounding code context
— rather than a bare warning.  This module builds that contract.  The proposal
claims **no novelty** here; it is the practical "shrink the candidate set to a
human-auditable number" stage.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List, Optional

from ..report import Finding


@dataclass
class TriageContract:
    """Everything the triager needs about one finding, framework-agnostic."""

    flow_kind: str                  # "implicit" | "explicit" | "dispatch"
    cwe: str
    sink: str
    sink_category: str
    sink_param_type: str
    severity: str
    tainted_argument: str
    location: str
    source_tools: List[str]
    frameworks: List[str]
    llm_nodes: List[str]
    trace: str
    code_context: str

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, ensure_ascii=False)


_CWE = {
    "implicit": "CWE-1426 (Improper Validation of Generative AI Output)",
    "explicit": "CWE-77/CWE-78 (data-layer command/argument injection)",
    "dispatch": "CWE-1426 (LLM-controlled tool dispatch)",
}


def _context_lines(source: Optional[str], site: str, radius: int = 3) -> str:
    if not source:
        return ""
    try:
        line = int(site.split(":")[0])
    except (ValueError, IndexError):
        return ""
    lines = source.splitlines()
    lo = max(0, line - radius - 1)
    hi = min(len(lines), line + radius)
    out = []
    for i in range(lo, hi):
        marker = ">>" if (i + 1) == line else "  "
        out.append(f"{marker} {i + 1:4d} | {lines[i]}")
    return "\n".join(out)


def build_contract(f: Finding, source: Optional[str] = None) -> TriageContract:
    return TriageContract(
        flow_kind=f.kind,
        cwe=_CWE.get(f.kind, "CWE-1426"),
        sink=f.sink_name,
        sink_category=f.sink_category,
        sink_param_type=f.param_type,
        severity=f.severity,
        tainted_argument=f.arg_expr,
        location=f"{f.file}:{f.sink_site}",
        source_tools=list(f.source_tools),
        frameworks=list(f.frameworks),
        llm_nodes=list(f.exit_sites),
        trace=f.trace(),
        code_context=_context_lines(source, f.sink_site),
    )
