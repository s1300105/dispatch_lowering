"""方向C — intra-tool argument reachability (precision, recall-safe).

A tool body containing a dangerous call is flagged as a sink by the body scan even
when the dispatched argument cannot actually reach that call.  方向C adds an
intra-function taint check that classifies the dangerous argument as:

  * "reaches"  — a parameter provably flows to the dangerous call,
  * "not"      — no parameter reaches it (provably clean), or
  * "unknown"  — undecidable (kept conservatively).

The sink is NEVER dropped (recall-first); a "not" verdict only LOWERS severity.
These tests pin both the classifier verdicts and the end-to-end severity effect.
"""
from __future__ import annotations

import ast
from pathlib import Path

from ctaudit import analyze_path
from ctaudit.analysis import resolve_dispatch
from ctaudit.toolmodel import get_classifier
from ctaudit.toolmodel.classify import HeuristicClassifier

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _sig(src: str):
    fn = [n for n in ast.parse(src).body
          if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))][0]
    return HeuristicClassifier()._signals(fn)


def test_direct_argument_reaches():
    sig = _sig("import subprocess\n"
               "def f(command):\n"
               "    return subprocess.run(command, shell=True)\n")
    assert sig["sink_cat"] == "code_execution"
    assert sig["sink_arg_reaches"] == "reaches"


def test_argument_reaches_through_assignment():
    sig = _sig("import subprocess\n"
               "def f(command):\n"
               "    x = command\n"
               "    return subprocess.run(x, shell=True)\n")
    assert sig["sink_arg_reaches"] == "reaches"


def test_argument_reaches_through_fstring():
    sig = _sig("import subprocess\n"
               "def f(arg):\n"
               "    cmd = f'ls {arg}'\n"
               "    return subprocess.run(cmd, shell=True)\n")
    assert sig["sink_arg_reaches"] == "reaches"


def test_argument_provably_does_not_reach():
    # parameter used only as a dict KEY; the value reaching the sink is fixed.
    sig = _sig("import subprocess\n"
               "ALLOWED = {}\n"
               "def f(name):\n"
               "    validated = ALLOWED[name]\n"
               "    return subprocess.run(['echo', validated], shell=False)\n")
    assert sig["sink_cat"] == "code_execution"
    assert sig["sink_arg_reaches"] == "not"


def test_unknown_when_value_passes_through_call():
    # value flows through a helper call -> cannot decide cheaply -> unknown (kept).
    sig = _sig("import subprocess\n"
               "def f(arg):\n"
               "    cmd = transform(arg)\n"
               "    return subprocess.run(cmd, shell=True)\n")
    assert sig["sink_arg_reaches"] == "unknown"


def test_sink_is_never_dropped_only_downgraded():
    # reachability_demo registers run_cmd (reaches -> high) and lookup (not -> low);
    # BOTH must still be reported (recall-first), with differing severity.
    path = str(FIXTURES / "reachability_demo.py")
    findings = analyze_path(path).findings
    mdl = get_classifier("heuristic").classify(path)
    resolved = [f for f in resolve_dispatch(findings, mdl, repo=path) if f.via_dispatch]
    by = {f.sink_name: f for f in resolved}
    assert {"run_cmd", "lookup"} <= set(by)          # neither dropped
    assert by["run_cmd"].severity == "high"
    assert by["lookup"].severity == "low"            # downgraded, not removed


def test_genuine_sinks_keep_high_severity():
    # the existing vulnerable fixtures must not be downgraded.
    for fx in ("langchain_2tool_vuln.py", "guarded_agent_app.py"):
        mdl = get_classifier("heuristic").classify(str(FIXTURES / fx))
        for t in mdl.tools:
            if t.sink and t.sink.category == "code_execution":
                assert t.sink.arg_reaches == "reaches"
