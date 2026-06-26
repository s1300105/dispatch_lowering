"""Tests for the flow-level benchmark (benchmark/flow_bench.py)."""
from benchmark.flow_bench import Flow, evaluate, run_fixture


def _cats(flows):
    return sorted((f.sink, f.category) for f in flows)


def test_overall_flow_recall_precision_and_guard_accuracy():
    r = evaluate()
    assert r["overall"]["recall"] == 1.0
    assert r["overall"]["precision"] == 1.0
    assert r["implicit_only"]["recall"] == 1.0
    assert r["implicit_only"]["precision"] == 1.0
    assert r["guard_accuracy"] == 1.0
    assert r["guard_matched"] >= 10          # all by-construction flows matched


def test_dispatch_resolves_to_two_flows_including_network():
    flows = run_fixture("dynamic_dispatch_agent.py")
    assert all(f.kind == "implicit" for f in flows)
    assert _cats(flows) == [("fetch_url", "network"), ("run_cmd", "code_execution")]


def test_phase_gate_drops_never_allowed_sink():
    # run_cmd is registered in TOOL_MAP but appears in no PHASE_TOOLS list -> dropped soundly.
    flows = run_fixture("phase_gated_agent.py")
    assert _cats(flows) == [("write_file", "file_write")]
    assert "run_cmd" not in {f.sink for f in flows}


def test_guarded_flow_is_reported_with_guard():
    flows = run_fixture("guarded_agent_app.py")
    assert len(flows) == 1
    assert flows[0].guarded is True
    assert flows[0].category == "code_execution"


def test_negatives_yield_no_flow():
    for name in ("langchain_2tool_safe.py", "schema_pruned_app.py", "unreachable_sink_app.py"):
        assert run_fixture(name) == [], name


def test_verbatim_is_explicit_not_implicit():
    flows = run_fixture("data_layer_verbatim.py")
    assert len(flows) == 1 and flows[0].kind == "explicit"
