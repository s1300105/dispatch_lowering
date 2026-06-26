"""Guards the 項目1 effect demonstration (benchmark/framework_dispatch_bench.py).

Ensures the by-construction framework-dispatch cases keep their headline result:
all framework shapes are detected & resolved via the DispatchSpec, the safe agent
yields no false flow, and the manual-loop baseline still works.
"""
from __future__ import annotations

import sys
from pathlib import Path

# the benchmark lives at <repo>/benchmark; make it importable.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "benchmark"))

import framework_dispatch_bench as fdb  # noqa: E402


def test_all_cases_correct():
    results = fdb.evaluate()
    assert results, "no cases evaluated"
    for r in results:
        assert r.correct, (
            f"{r.case.fixture} ({r.case.kind}): expected "
            f"{r.case.expect_sink!r}, got resolved sink {r.resolved_sink!r}")


def test_framework_shapes_recovered_via_dispatchspec():
    results = fdb.evaluate()
    fw = [r for r in results if r.case.kind == "framework"]
    assert len(fw) >= 3                      # create_react_agent / AgentExecutor / create_agent
    # every framework case must be recovered THROUGH the framework DispatchSpec
    # (its wall carried framework_candidates), not by a syntactic wall.
    assert all(r.via_framework and r.correct for r in fw)


def test_safe_framework_agent_yields_no_flow():
    results = fdb.evaluate()
    safe = [r for r in results if r.case.kind == "safe"]
    assert safe and all(r.resolved_sink is None and r.correct for r in safe)


def test_manual_baseline_uses_syntactic_wall():
    results = fdb.evaluate()
    manual = [r for r in results if r.case.kind == "manual"]
    assert manual and all(r.correct for r in manual)
    # the manual loop's wall is visible in user code -> NOT a framework wall.
    assert all(not r.via_framework for r in manual)
