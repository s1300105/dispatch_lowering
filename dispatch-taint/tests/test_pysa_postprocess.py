"""Tests for the Pysa post-processor (pysa/postprocess.py).

These run WITHOUT Pyre/Pysa: they feed the post-processor a synthetic
taint-output.json shape and check that it (a) recognizes implicit flows by the
`llm_node` feature, (b) rebuilds ctaudit findings, and (c) reuses the §4.5 prune
(here: schema/channel-capacity) on Pysa output.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_PP = Path(__file__).resolve().parents[1] / "pysa" / "postprocess.py"


def _load():
    if not _PP.exists():
        pytest.skip("pysa/postprocess.py not present")
    spec = importlib.util.spec_from_file_location("ctaudit_pysa_postprocess", _PP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_iter_issues_handles_wrapped_and_bare():
    pp = _load()
    wrapped = {"issues": [{"kind": "issue", "code": 9001}]}
    bare = [{"kind": "issue", "code": 9002}, {"kind": "model"}]
    assert len(list(pp._iter_issues(wrapped))) == 1
    assert len(list(pp._iter_issues(bare))) == 1


def test_llm_node_feature_makes_finding_implicit():
    pp = _load()
    issue = {
        "kind": "issue", "code": 9001,
        "message": "Tool output reaches subprocess.run",
        "callable": "app.run_command", "path": "app/agent.py", "line": 55,
        "features": [{"always-via": "llm_node"}, {"via": "cap_string"}],
    }
    f = pp._to_finding(issue)
    assert f is not None
    assert f.kind == "implicit"
    assert f.sink_category == "exec"
    assert f.source_marks[0].out_type == "string"


def test_no_llm_node_is_explicit():
    pp = _load()
    issue = {"kind": "issue", "code": 9001, "path": "x.py", "line": 1,
             "features": [{"via": "cap_string"}]}
    f = pp._to_finding(issue)
    assert f.kind == "explicit"


def test_capacity_feature_drives_schema_prune():
    pp = _load()
    from ctaudit.analysis.pruning import PruneConfig, prune
    # a bool-capacity source into an exec (string) sink must be pruned (§4.5(2)).
    issue = {"kind": "issue", "code": 9001, "path": "x.py", "line": 1,
             "features": [{"always-via": "llm_node"}, {"via": "cap_bool"}]}
    f = pp._to_finding(issue)
    assert f.source_marks[0].out_type == "bool"
    prune([f], PruneConfig())
    assert f.pruned
    assert "narrower" in (f.prune_reason or "")


def test_non_matching_code_is_ignored():
    pp = _load()
    assert pp._to_finding({"kind": "issue", "code": 1234}) is None


def test_wrapped_issue_envelope_is_unwrapped():
    # Pyre's real output wraps each issue as {"kind":"issue","data":{...}} in a
    # JSON-lines file; _to_finding must read fields from under "data".
    pp = _load()
    issue = {"kind": "issue", "data": {
        "code": 9001, "line": 58, "filename": "example/agent.py",
        "features": [{"via": "llm_node"}, {"always-via": "cap_string"}],
        "traces": [{"name": "backward", "roots": [
            {"kinds": [{"leaves": [{"name": "agent.run_command"}]}]},
            {"kinds": [{"leaves": [{"name": "subprocess.run"}]}]},
        ]}],
    }}
    f = pp._to_finding(issue)
    assert f is not None
    assert f.kind == "implicit"            # llm_node feature found under data
    assert f.sink_name == "subprocess.run"  # picked from the backward trace leaf
    assert f.file == "example/agent.py"
    assert f.sink_site == "58"


def test_sink_from_backward_trace_picks_leaf():
    pp = _load()
    data = {"traces": [{"name": "backward", "roots": [
        {"kinds": [{"leaves": [{"name": "agent.run_command"}, {"name": "subprocess.run"}]}]}
    ]}]}
    assert pp._sink_from_traces(data) == "subprocess.run"


def test_load_json_handles_json_lines(tmp_path):
    pp = _load()
    d = tmp_path / "pysa-results"
    d.mkdir()
    (d / "taint-output.json").write_text(
        '{"file_version":3,"config":{}}\n'
        '{"kind":"model","data":{"callable":"x"}}\n'
        '{"kind":"issue","data":{"code":9001,"line":1,"filename":"a.py",'
        '"features":[{"via":"llm_node"}]}}\n'
    )
    doc = pp._load_json(str(d))
    issues = list(pp._iter_issues(doc))
    findings = [pp._to_finding(i) for i in issues]
    findings = [f for f in findings if f is not None]
    assert len(findings) == 1
    assert findings[0].kind == "implicit"
