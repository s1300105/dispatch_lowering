"""Stage-4 evaluation harness for ctaudit (§5, RQ1–RQ4)."""

from .harness import (
    AblationRow,
    CaseResult,
    Counts,
    FrameworkCost,
    StageMetrics,
    ablation,
    evaluate,
    format_report,
    framework_cost,
    run_report,
)
from .labels import BENCHMARK, ExpectedFinding, LabeledCase

__all__ = [
    "evaluate",
    "ablation",
    "framework_cost",
    "run_report",
    "format_report",
    "Counts",
    "StageMetrics",
    "CaseResult",
    "AblationRow",
    "FrameworkCost",
    "BENCHMARK",
    "LabeledCase",
    "ExpectedFinding",
]
