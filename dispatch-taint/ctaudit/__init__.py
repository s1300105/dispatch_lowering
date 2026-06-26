"""ctaudit — pre-deployment static audit for cross-tool implicit flows in LLM agents.

Implements Stages 1–3 of the research proposal "クロスツール暗黙的フローの
デプロイ前静的監査": a static analyzer that enumerates, *without executing the
agent*, every wiring where one tool's attacker-influenceable output reaches
another tool's dangerous sink through the model's reasoning — the implicit /
control-dependency flow of CWE-1426 that classic data-flow (TITO) cannot see.

Public entry points:

    analyze_source(text, filename, registry) -> [Finding]   # raw, pre-pruning
    analyze_path(path, ...) -> AuditResult                   # full pipeline
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

from .analysis.pruning import PruneConfig, RolePolicy, kept, prune
from .analysis.taint_engine import analyze_source
from .labels import Kind, Label, SourceMark
from .models import default_registry
from .models.base import ModelRegistry
from .report import Finding, render_findings
from .triage import get_triager

__version__ = "0.3.0"  # Stages 1-3

__all__ = [
    "analyze_source",
    "analyze_path",
    "AuditResult",
    "default_registry",
    "Finding",
    "render_findings",
    "PruneConfig",
    "RolePolicy",
]


@dataclass
class AuditResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def kept(self) -> List[Finding]:
        return kept(self.findings)

    def render(self, show_pruned: bool = False) -> str:
        return render_findings(self.findings, show_pruned=show_pruned)


def _iter_py_files(path: str):
    if os.path.isfile(path):
        yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", ".venv", "node_modules")]
        for fn in sorted(files):
            if fn.endswith(".py"):
                yield os.path.join(root, fn)


def analyze_path(
    path: str,
    registry: Optional[ModelRegistry] = None,
    do_prune: bool = True,
    prune_config: Optional[PruneConfig] = None,
    do_triage: bool = True,
    triage_backend: str = "mock",
    triage_model: Optional[str] = None,
    role_policy: Optional[RolePolicy] = None,
) -> AuditResult:
    """Run the full Stage 1–3 pipeline over a file or directory."""
    reg = registry or default_registry()
    result = AuditResult()
    triager = get_triager(triage_backend, triage_model) if do_triage else None

    for fp in _iter_py_files(path):
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                source = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            result.errors.append(f"{fp}: {exc}")
            continue
        try:
            file_findings = analyze_source(source, fp, reg)
        except SyntaxError as exc:
            result.errors.append(f"{fp}: syntax error: {exc}")
            continue
        result.files_scanned += 1

        if do_prune:
            prune(file_findings, prune_config, role_policy)
        if triager is not None:
            triager.triage(file_findings, source)

        result.findings.extend(file_findings)

    return result
