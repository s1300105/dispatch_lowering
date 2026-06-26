"""Logic tests for benchmark/cve_bench.py using bundled fixtures as stand-in repos.

These validate the runner's detection-matching end to end (build pipeline -> flows ->
category match -> verdict) WITHOUT real CVE repos or an LLM, by injecting a model and
pointing at a single fixture file.
"""
from pathlib import Path

from benchmark.cve_bench import run_case
from benchmark.cve_cases import CVECase
from benchmark.flow_bench import FIXTURES, _gold_models
from ctaudit.toolmodel.schema import RepoToolModel


def _empty(path):
    return RepoToolModel(repo=path, src_root=path, tools=[])


def _case(cat, scope="cross_tool", taintp2x="N"):
    return CVECase("CVE-TEST", "owner/x", "ref", "t", cat, scope, True, taintp2x, "", None, "")


def test_direct_sink_detected_with_empty_model():
    # os.system is a direct sink: detected even without a tool model.
    f = str(FIXTURES / "openai_agents_app.py")
    res = run_case(_case("code_execution"), f, model=_empty(f))
    assert res["verdict"] == "DETECTED"
    assert "code_execution" in res["hit_categories"]


def test_dispatch_detected_with_gold_model():
    f = str(FIXTURES / "dynamic_dispatch_agent.py")
    mdl = _gold_models()["dynamic_dispatch_agent.py"]
    res = run_case(_case("code_execution", scope="dynamic_dispatch"), f, model=mdl)
    assert res["verdict"] == "DETECTED"


def test_wrong_category_is_not_detected():
    # the fixture has a code_execution flow; asking about sql must not match.
    f = str(FIXTURES / "openai_agents_app.py")
    res = run_case(_case("sql"), f, model=_empty(f))
    assert res["verdict"] != "DETECTED"


def test_guarded_flow_flagged_guarded():
    f = str(FIXTURES / "guarded_agent_app.py")
    res = run_case(_case("code_execution"), f, model=_empty(f))
    assert res["verdict"] == "DETECTED"
    assert res["guarded"] is True


def test_safe_fixture_missed():
    f = str(FIXTURES / "langchain_2tool_safe.py")
    res = run_case(_case("code_execution"), f, model=_empty(f))
    assert res["verdict"] == "missed"
