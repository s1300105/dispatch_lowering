"""Tests for the Stage-4 evaluation harness (mechanics + soundness)."""

from __future__ import annotations

from ctaudit.eval import ablation, evaluate, framework_cost, run_report


def test_pruned_stage_is_clean_on_benchmark():
    overall, _ = evaluate()
    # the 6 expected positives (5 implicit + 1 explicit) are all detected ...
    assert overall.pruned.tp == 6
    # ... with nothing spurious surviving and nothing missed.
    assert overall.pruned.fp == 0
    assert overall.pruned.fn == 0
    assert overall.pruned.precision == 1.0
    assert overall.pruned.recall == 1.0


def test_raw_stage_shows_pruners_have_work_to_do():
    overall, _ = evaluate()
    # recall is already perfect at raw (the detector finds everything) ...
    assert overall.raw.tp == 6
    assert overall.raw.fn == 0
    # ... but two should-be-pruned candidates are present, so precision < 1.
    assert overall.raw.fp == 2
    assert overall.raw.precision < 1.0


def test_triaged_stage_keeps_true_positives():
    overall, _ = evaluate(triage_backend="mock")
    assert overall.triaged.tp == 6
    assert overall.triaged.fp == 0


def test_ablation_is_sound_and_attributes_removals():
    rows = {r.prune: r for r in ablation()}
    # no prune ever removes a true positive on the benchmark.
    assert all(r.tp_removed == 0 for r in rows.values())
    # reachability and schema each remove exactly the false positive they target.
    assert rows["reachability"].fp_removed >= 1
    assert rows["schema"].fp_removed >= 1
    # role needs a policy (none supplied) and hiding is subsumed by the join.
    assert rows["role"].fp_removed == 0
    assert rows["selective_hiding"].fp_removed == 0


def test_framework_cost_reports_specs_and_recall():
    _, per_case = evaluate()
    costs = {fc.framework: fc for fc in framework_cost(per_case)}
    for fw in ("langchain", "langgraph", "mcp", "openai-agents"):
        assert costs[fw].specs >= 1
        assert costs[fw].recall == 1.0
    # case counts add up to the benchmark size.
    assert sum(fc.cases for fc in costs.values()) == 9
    assert costs["langchain"].cases == 4
    assert costs["langgraph"].cases == 2


def test_run_report_renders_text():
    text = run_report()
    assert "Stage 4 evaluation" in text
    assert "framework cost" in text
    assert "self-authored" in text   # the honesty caveat is printed
