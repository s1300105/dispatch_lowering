"""Shared pytest fixtures and helpers for the ctaudit test suite.

The tests drive the *public* pipeline (``analyze_path`` / ``analyze_source``)
against the checked-in analysis-target fixtures under ``fixtures/``.  Those
fixtures are never executed — they are read as source text and analysed
statically, which is the whole point of a pre-deployment audit.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from ctaudit import Finding, analyze_path
from ctaudit.analysis.pruning import PruneConfig

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def fixture_path(name: str) -> str:
    p = FIXTURES / name
    assert p.exists(), f"missing fixture: {p}"
    return str(p)


def run(name: str, **kwargs) -> List[Finding]:
    """Analyse one fixture through the full pipeline; return *all* findings.

    ``do_triage`` defaults to the offline MockTriage so the suite is
    deterministic and needs no network or API key.
    """
    kwargs.setdefault("do_triage", True)
    kwargs.setdefault("triage_backend", "mock")
    result = analyze_path(fixture_path(name), **kwargs)
    return result.findings


def kept(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if not f.pruned]


def implicit(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if f.kind == "implicit"]


@pytest.fixture
def no_prune_cfg() -> PruneConfig:
    """A PruneConfig with every reducer switched off (pure recall)."""
    return PruneConfig(
        schema=False,
        selective_hiding=False,
        reachability=False,
        role=False,
    )
