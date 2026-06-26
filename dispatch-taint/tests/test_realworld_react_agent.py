"""Real-repository check (方向A) — transcribed public LangChain ReAct agent.

Target: ``realworld/botextract_react_agent.py`` (transcribed from the public
github.com/botextractai/ai-langchain-react-agent).  This pins the *observed*
behaviour of 項目1 on real third-party code:

  * The framework-managed dispatch wall IS detected, and its candidate set is
    recovered even though the tool list is bound to a variable first
    (``tools = [python_repl_tool, duckduckgo_tool]``; ``create_react_agent(llm,
    tools, prompt)``) — the syntactic-only path would miss this dispatch entirely.

  * The wall is reported UNRESOLVED end-to-end, because the dangerous tool
    (``PythonAstREPLTool``) is a *library* component whose body is not in the
    analysed file, so the per-tool sink judgement cannot ground it.  This is the
    documented grounding limitation, cleanly localised to per-tool sink judgement
    (recognising known dangerous library tools is future work, not 項目1).

These assertions encode "what the tool actually does today" so a regression in the
framework-dispatch detection (or an unexpected change in grounding) is caught.
"""
from __future__ import annotations

from pathlib import Path

from ctaudit import analyze_path
from ctaudit.analysis.dispatch_resolution import resolve_dispatch
from ctaudit.toolmodel import get_classifier

FIXTURE = Path(__file__).resolve().parent.parent / "realworld" / "botextract_react_agent.py"


def test_framework_wall_detected_on_real_agent():
    findings = analyze_path(str(FIXTURE)).findings
    walls = [f for f in findings if f.kind == "dispatch"]
    assert len(walls) == 1
    w = walls[0]
    assert "invoke" in w.sink_name                      # AgentExecutor launch is the wall
    # candidate set recovered from the VARIABLE-bound tool list (not a literal).
    assert set(w.framework_candidates) == {"python_repl_tool", "duckduckgo_tool"}


def test_known_library_tool_now_resolves():
    # 方向B: PythonAstREPLTool is a KNOWN dangerous library tool. Even though its
    # exec lives in the library (not user code), the known-tool registry grounds it,
    # so the wall resolves to python_repl_tool (code_execution) end-to-end.
    findings = analyze_path(str(FIXTURE)).findings
    mdl = get_classifier("heuristic").classify(str(FIXTURE))
    sinks = [t for t in mdl.tools if t.sink]
    assert any(t.name == "python_repl_tool" and t.sink.category == "code_execution"
               and t.callable == "PythonAstREPLTool" for t in sinks)
    resolved = resolve_dispatch(findings, mdl, repo=str(FIXTURE))
    by_name = {f.sink_name: f for f in resolved if f.via_dispatch}
    assert "python_repl_tool" in by_name
    assert by_name["python_repl_tool"].sink_category == "code_execution"
    assert by_name["python_repl_tool"].kind == "implicit"


# ---- additional real-repo patterns (方向A, more cases) ------------------------ #
REALWORLD = Path(__file__).resolve().parent.parent / "realworld"


def _resolve(path: str):
    findings = analyze_path(path).findings
    mdl = get_classifier("heuristic").classify(path)
    resolved = [f for f in resolve_dispatch(findings, mdl, repo=path)
                if f.kind in ("implicit", "explicit") and f.via_dispatch]
    walls = [f for f in findings if f.kind == "dispatch"]
    return walls, resolved


def test_user_code_exec_sink_resolves_fully():
    # dylancastillo: @tool run_python_code with exec() IN user code -> groundable.
    path = str(REALWORLD / "dylancastillo_react_exec.py")
    walls, resolved = _resolve(path)
    assert walls and set(walls[0].framework_candidates) == {"run_python_code"}
    names = {(f.sink_name, f.sink_category) for f in resolved}
    assert ("run_python_code", "code_execution") in names


def test_undecorated_framework_tool_resolves():
    # langgraph-supervisor style: PLAIN (undecorated) functions registered with
    # create_react_agent; run_command has os.popen in user code.  The framework
    # registration is the tool-ness signal, so it is captured and resolved.
    path = str(REALWORLD / "langgraph_supervisor_style.py")
    walls, resolved = _resolve(path)
    assert walls and set(walls[0].framework_candidates) == {"web_search", "run_command"}
    names = {(f.sink_name, f.sink_category) for f in resolved}
    assert ("run_command", "code_execution") in names


def test_class_based_basetool_resolves_once():
    # python-a2a style: a BaseTool SUBCLASS with eval(query) in _run (user code),
    # plus an async _arun that calls _run.  The class is ONE tool -> exactly ONE
    # finding (no _run/_arun duplicate), resolved to calculator (code_execution),
    # and 方向C marks the argument as reaching (eval(query) passes it directly).
    path = str(REALWORLD / "a2a_calculator_basetool.py")
    mdl = get_classifier("heuristic").classify(path)
    calc = [t for t in mdl.tools if t.name == "calculator"]
    assert len(calc) == 1                              # not duplicated by _run/_arun
    assert calc[0].sink and calc[0].sink.category == "code_execution"
    assert calc[0].sink.arg_reaches == "reaches"
    walls, resolved = _resolve(path)
    assert walls and set(walls[0].framework_candidates) == {"calculator_tool", "search_tool"}
    findings = [f for f in resolved if f.sink_name == "calculator"]
    assert len(findings) == 1 and findings[0].sink_category == "code_execution"


def test_dict_registry_openai_sdk_wall_detected_but_unresolved():
    # maxscheijen: a hand-written (no-framework) agent on the raw OpenAI SDK, with a
    # dict-registry dispatch `tool_mapping[name](...)` split across run()/call_tool().
    # 1-hop cross-method control seeding now CONNECTS the LLM call in run() to the
    # manual wall in call_tool(), so the dispatch wall IS detected.  It stays
    # UNRESOLVED, though: the tools are plain functions registered via a hand-written
    # `Agent(tools=[...])` dataclass (not @tool / BaseTool / a framework factory), so
    # the classifier recognises no sink tool to resolve the wall against.  This pins
    # the partial progress and the remaining (separate) tool-recognition limitation.
    path = str(REALWORLD / "maxscheijen_dict_registry.py")
    findings = analyze_path(path).findings
    walls = [f for f in findings if f.kind == "dispatch"]
    assert walls, "method-split manual dispatch wall should now be detected"
    assert any("tool_mapping" in w.sink_name for w in walls)
    mdl = get_classifier("heuristic").classify(path)
    assert mdl.llm_call is not None
    assert [t.name for t in mdl.tools] == []          # hand-written registration not captured
    # because no sink tool is known, nothing resolves to a concrete dangerous flow.
    resolved = resolve_dispatch(findings, mdl, repo=path)
    assert not [f for f in resolved if f.kind in ("implicit", "explicit") and f.via_dispatch]


def test_known_library_tool_variants(tmp_path):
    # 方向B: the known-tool registry resolves the common construction chains, but
    # only when the tool is actually registered with an agent.
    from ctaudit.toolmodel import get_classifier
    src = (
        "from langgraph.prebuilt import create_react_agent\n"
        "from langchain_experimental.tools import PythonREPLTool, ShellTool\n"
        "from langchain.tools import Tool\n"
        "llm = object()\n"
        "direct = PythonREPLTool()\n"                       # direct constructor
        "shell = ShellTool()\n"                             # registered below
        "wrapped = Tool(func=ShellTool().run)\n"            # inline-ctor wrapper
        "never = PythonREPLTool()\n"                        # constructed but NOT registered
        "agent = create_react_agent(llm, tools=[direct, wrapped])\n"
        "agent2 = create_react_agent(llm, tools=[shell])\n"
        "agent.invoke({'messages': []})\n"
    )
    p = tmp_path / "known.py"
    p.write_text(src)
    mdl = get_classifier("heuristic").classify(str(p))
    sinks = {t.name: t for t in mdl.tools if t.sink}
    assert "direct" in sinks and sinks["direct"].sink.category == "code_execution"
    assert "wrapped" in sinks and sinks["wrapped"].sink.category == "code_execution"
    assert "shell" in sinks and sinks["shell"].sink.category == "code_execution"
    assert "never" not in sinks            # constructed but never registered -> not flagged
