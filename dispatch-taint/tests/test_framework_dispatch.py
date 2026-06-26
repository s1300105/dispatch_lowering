"""項目1 — framework-managed dispatch (create_react_agent(tools=[...]) + .invoke).

The dispatch wall lives *inside* the framework (LangGraph's ToolNode), so it is
invisible to a syntactic scan of user code.  ctaudit recovers it from the
declarative DispatchSpec: the registration call's tool list is the candidate set,
and the launch method is the wall.  These tests check (1) the wall is detected
with its registered candidate set, and (2) resolve_dispatch maps it to the
concrete dangerous sink, with the conservative-vs-trust flag behaving correctly.
"""
from __future__ import annotations

from pathlib import Path

from ctaudit import analyze_path
from ctaudit.analysis.dispatch_resolution import resolve_dispatch
from ctaudit.toolmodel.schema import RepoToolModel, SinkSpec, SourceSpec, ToolSpec

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
FIXTURE = FIXTURES / "langgraph_react_agent.py"


def _findings():
    return analyze_path(str(FIXTURE)).findings


def _model(extra_sink: bool = False):
    tools = [
        ToolSpec(name="run_cmd", roles=["sink"],
                 sink=SinkSpec(category="code_execution", arg="command", guard=None)),
        ToolSpec(name="fetch_url", roles=["source"],
                 source=SourceSpec(capacity="string", attacker=True)),
    ]
    if extra_sink:
        # a dangerous tool the model knows about but that is NOT in tools=[...].
        tools.append(ToolSpec(name="delete_db", roles=["sink"],
                              sink=SinkSpec(category="sql", arg="q", guard=None)))
    return RepoToolModel(repo=str(FIXTURE), src_root="fixtures", tools=tools)


def test_framework_dispatch_wall_detected_with_candidates():
    disp = [f for f in _findings() if f.kind == "dispatch"]
    assert len(disp) == 1
    f = disp[0]
    assert f.sink_category == "dispatch"
    assert "invoke" in f.sink_name                       # the launch is the wall
    # the registered tool set is captured as the candidate set
    assert set(f.framework_candidates) == {"fetch_url", "run_cmd"}
    assert f.source_marks and f.exit_sites               # path context present


def test_framework_dispatch_resolves_to_sink():
    resolved = resolve_dispatch(_findings(), _model())
    assert not any(f.kind == "dispatch" for f in resolved)
    by_name = {f.sink_name: f for f in resolved if f.via_dispatch}
    assert "run_cmd" in by_name
    rc = by_name["run_cmd"]
    assert rc.kind == "implicit"
    assert rc.sink_category == "code_execution" and rc.severity == "high"
    assert set(rc.framework_candidates) == {"fetch_url", "run_cmd"}


def test_conservative_default_does_not_narrow():
    # default (framework_registry_trust=False): a known sink outside tools=[...]
    # is still kept (recall-first) — registration alone must not drop it.
    resolved = resolve_dispatch(_findings(), _model(extra_sink=True))
    names = {f.sink_name for f in resolved if f.via_dispatch}
    assert names == {"run_cmd", "delete_db"}


def test_trust_flag_narrows_to_registered_set():
    # framework_registry_trust=True: trust the registration as complete membership,
    # so delete_db (not registered) is narrowed out.
    resolved = resolve_dispatch(_findings(), _model(extra_sink=True),
                                framework_registry_trust=True)
    names = {f.sink_name for f in resolved if f.via_dispatch}
    assert names == {"run_cmd"}


def test_end_to_end_hybrid_resolves_framework_dispatch():
    # the full pipeline (heuristic classifier builds the model from the single
    # file, then resolve_dispatch maps the framework wall) recovers run_cmd.
    import hybrid
    findings = hybrid.run(str(FIXTURE), None, "mock")
    resolved = [f for f in findings if getattr(f, "via_dispatch", None)]
    names = {f.sink_name for f in resolved}
    assert "run_cmd" in names
    rc = next(f for f in resolved if f.sink_name == "run_cmd")
    assert rc.kind == "implicit" and rc.sink_category == "code_execution"
    assert "invoke" in (rc.via_dispatch or "")


# ---- 1-hop cross-method dispatch (項目1, recall-safe) ------------------------- #
def test_instance_attribute_agent_launched_in_other_method():
    # self.agent = create_react_agent(...) in __init__, self.agent.invoke(...) in a
    # different method.  The module-scoped self-agent registry lets the launch in
    # handle() resolve to the registration in __init__().
    import hybrid
    fx = str(FIXTURE.parent / "method_split_framework.py")
    findings = hybrid.run(fx, None, "mock")
    resolved = [f for f in findings if getattr(f, "via_dispatch", None)]
    names = {f.sink_name for f in resolved}
    assert "run_cmd" in names
    rc = next(f for f in resolved if f.sink_name == "run_cmd")
    assert rc.kind == "implicit" and rc.sink_category == "code_execution"
    assert "self.agent.invoke" in (rc.via_dispatch or "")


def test_manual_dispatch_split_across_methods_is_detected():
    # LLM call in run(), manual TOOL_MAP[name](...) wall in a helper method that
    # receives the control-tainted tool-call object.  1-hop control seeding connects
    # them so the wall is detected (the fixture's tools are @tool, so it resolves).
    import hybrid
    fx = str(FIXTURE.parent / "method_split_manual.py")
    findings = hybrid.run(fx, None, "mock")
    walls = [f for f in findings if f.kind == "dispatch"]
    # the manual wall in the helper method is recorded via cross-method seeding.
    assert any("tool_map" in (w.sink_name or "").lower()
               or "TOOL_MAP" in (w.sink_name or "") for w in walls) or \
        any(getattr(f, "via_dispatch", None) for f in findings)


# ---- AgentDojo applicability (項目1 declarative support; opt-in) ------------- #
def test_agentdojo_fixture_resolves_only_with_flag():
    # The AgentDojo-style runtime fixture (dict-registry run_function wall + a TOOLS
    # list of plain functions; danger is domain-semantic, no syntactic sink).
    # WITHOUT the flag it is invisible (matching the real AgentDojo zero baseline);
    # WITH --agentdojo the wall is detected and resolved to the domain sink send_money.
    import hybrid
    fx = str(FIXTURE.parent / "agentdojo_banking_runtime.py")

    off = hybrid.run(fx, None, "mock", agentdojo=False)
    assert not [f for f in off if getattr(f, "via_dispatch", None)]

    on = hybrid.run(fx, None, "mock", agentdojo=True)
    resolved = {f.sink_name for f in on if getattr(f, "via_dispatch", None)}
    assert "send_money" in resolved
    sm = next(f for f in on if f.sink_name == "send_money")
    assert sm.kind == "implicit" and sm.sink_category == "transaction"


def test_agentdojo_flag_is_isolated_from_default():
    # The opt-in must not change default behaviour: the same fixture under the default
    # registry (no flag) yields no resolved dispatch, and the core flow benchmark stays
    # intact (checked separately).  Here we just assert the flag gates the behaviour.
    import hybrid
    fx = str(FIXTURE.parent / "agentdojo_banking_runtime.py")
    off = hybrid.run(fx, None, "mock", agentdojo=False)
    assert all(f.sink_category != "transaction" for f in off)
