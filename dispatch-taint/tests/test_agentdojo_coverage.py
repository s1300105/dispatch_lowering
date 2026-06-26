"""Tests for the AgentDojo coverage benchmark (static, no model run).

Skips when agentdojo is not installed.  When installed, asserts the soundness
relation (S_static covers every defined-attack sink) and that the comparison is
non-trivial (S_dyn is a strict subset, so coverage is meaningful, not automatic).
"""
from __future__ import annotations

import importlib.util

import pytest

_HAVE_AGENTDOJO = importlib.util.find_spec("agentdojo") is not None


@pytest.mark.skipif(not _HAVE_AGENTDOJO, reason="agentdojo not installed")
def test_agentdojo_banking_coverage_sound_and_nontrivial():
    from benchmark.agentdojo_coverage import run
    S_dyn, S_static, gt = run()

    assert gt, "should parse some injection tasks"
    assert S_dyn, "S_dyn (defined-attack sinks) should be non-empty"

    # soundness: every sink a defined attack uses is flagged by ctaudit (R ⊇ R*).
    assert S_dyn <= S_static, f"missed attack sink(s): {sorted(S_dyn - S_static)}"

    # non-trivial: S_dyn is a STRICT subset, so coverage is meaningful (not the
    # degenerate "both are the full sink set" case that would make (C) vacuous).
    assert S_dyn < S_static, "coverage would be trivial if S_dyn == S_static"


@pytest.mark.skipif(not _HAVE_AGENTDOJO, reason="agentdojo not installed")
def test_agentdojo_s_dyn_extracted_statically_without_execution():
    # S_dyn must be derivable purely by AST-reading ground_truth (no model, no run).
    import os
    from pathlib import Path

    import agentdojo
    from benchmark.agentdojo_coverage import _ground_truth_sinks, _s_dyn

    inj = (Path(os.path.dirname(agentdojo.__file__))
           / "default_suites" / "v1" / "banking" / "injection_tasks.py")
    gt = _ground_truth_sinks(inj)
    S_dyn = _s_dyn(gt)
    # banking's defined attacks use exactly these three domain sinks.
    assert S_dyn == {"send_money", "update_password", "update_scheduled_transaction"}
