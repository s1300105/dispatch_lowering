"""Findings and report rendering."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .labels import SourceMark


@dataclass
class Finding:
    """One vulnerable wiring, before or after triage."""

    kind: str                       # "implicit" | "explicit" | "dispatch"
    sink_name: str
    sink_category: str
    severity: str
    sink_site: str                  # "path:line:col"
    arg_expr: str                   # source text of the tainted argument
    param_type: str
    source_marks: Tuple[SourceMark, ...]
    exit_sites: Tuple[str, ...] = ()    # LLM nodes the control taint passed through
    file: str = ""
    reachable: bool = True              # CFG reachability of the sink (§4.5(1))
    guard: Optional[str] = None         # in-function guard preceding the sink (mitigating; never prunes)
    via_dispatch: Optional[str] = None  # set when a dispatch wall was resolved to this concrete sink
                                        # via the shared tool model (fusion #4); holds the dispatch expr
    # 項目1: for a framework-managed dispatch wall (create_react_agent(tools=[...]) +
    # .invoke), the registered candidate tool names.  Empty for syntactic walls.
    framework_candidates: Tuple[str, ...] = ()

    # filled in by pruning / triage (Stage 3)
    pruned: bool = False
    prune_reason: Optional[str] = None
    triage_verdict: Optional[str] = None     # "true-positive" | "false-positive" | "uncertain"
    triage_confidence: Optional[float] = None
    triage_rationale: Optional[str] = None

    # ---- derived ----------------------------------------------------------- #
    @property
    def source_tools(self) -> Tuple[str, ...]:
        return tuple(sorted({m.tool for m in self.source_marks}))

    @property
    def frameworks(self) -> Tuple[str, ...]:
        return tuple(sorted({m.framework for m in self.source_marks}))

    def trace(self) -> str:
        srcs = "; ".join(str(m) for m in self.source_marks) or "<unknown>"
        via = " -> ".join(self.exit_sites) if self.exit_sites else "(no LLM node — data layer)"
        tail = f"  [resolved from dispatch {self.via_dispatch}]" if self.via_dispatch else ""
        return (f"source[{srcs}]  ==(history)==>  llm[{via}]  ==(tool_calls)==>  "
                f"{self.sink_name}@{self.sink_site}{tail}")

    def key(self) -> tuple:
        return (self.kind, self.sink_name, self.sink_site, self.arg_expr,
                tuple(sorted(str(m) for m in self.source_marks)))


KIND_LABEL = {
    "implicit": "CROSS-TOOL IMPLICIT FLOW (control dependency, CWE-1426)",
    "explicit": "data-layer flow (verbatim, TITO)",
    "dispatch": "LLM-controlled tool dispatch",
}


def render_findings(findings: List[Finding], show_pruned: bool = False) -> str:
    lines: List[str] = []
    shown = [f for f in findings if show_pruned or not f.pruned]
    kept = [f for f in findings if not f.pruned]
    lines.append("=" * 78)
    lines.append(f"cross-tool audit — {len(kept)} finding(s) after pruning"
                 f"  ({len(findings)} raw)")
    lines.append("=" * 78)
    if not shown:
        lines.append("  (no findings)")
        return "\n".join(lines)

    for i, f in enumerate(shown, 1):
        tag = "PRUNED " if f.pruned else ""
        verdict = ""
        if f.triage_verdict:
            c = f" {f.triage_confidence:.2f}" if f.triage_confidence is not None else ""
            verdict = f"  [triage: {f.triage_verdict}{c}]"
        lines.append("")
        lines.append(f"[{i}] {tag}{KIND_LABEL.get(f.kind, f.kind)}  ({f.severity}){verdict}")
        lines.append(f"    sink     : {f.sink_name}  ({f.sink_category})  param={f.param_type}")
        lines.append(f"    at       : {f.file}:{f.sink_site}")
        lines.append(f"    tainted  : {f.arg_expr}")
        lines.append(f"    from tool: {', '.join(f.source_tools)}")
        lines.append(f"    trace    : {f.trace()}")
        if f.pruned:
            lines.append(f"    pruned   : {f.prune_reason}")
        if f.triage_rationale:
            lines.append(f"    rationale: {f.triage_rationale}")
    return "\n".join(lines)
