"""Fusion #4 — resolving the dataflow leg's dispatch wall with the shared tool model."""
from __future__ import annotations

from pathlib import Path

from ctaudit import analyze_path
from ctaudit.analysis.dispatch_resolution import resolve_dispatch
from ctaudit.report import Finding
from ctaudit.toolmodel.schema import RepoToolModel, SinkSpec, SourceSpec, ToolSpec

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _leg_a_dispatch_findings():
    res = analyze_path(str(FIXTURES / "dynamic_dispatch_agent.py"))
    return res.findings


def _model():
    # the shared tool model the #5 classifier auto-generates for this repo
    return RepoToolModel(repo="dynamic_dispatch_agent.py", src_root="fixtures", tools=[
        ToolSpec(name="run_cmd", roles=["sink"],
                 sink=SinkSpec(category="code_execution", arg="cmd", guard=None), site="r.py:34"),
        ToolSpec(name="fetch_url", roles=["sink"],
                 sink=SinkSpec(category="network", arg="url", guard=None), site="r.py:29"),
        ToolSpec(name="echo", roles=["source"],
                 source=SourceSpec(capacity="string", attacker=True), site="r.py:39"),
    ])


def test_leg_a_localises_the_dispatch_wall():
    # the dataflow leg cannot resolve the dynamic callee, so it records exactly one
    # dispatch finding (carrying the path's source marks + LLM node), not a concrete sink.
    disp = [f for f in _leg_a_dispatch_findings() if f.kind == "dispatch"]
    assert len(disp) == 1
    f = disp[0]
    assert f.sink_category == "dispatch"
    assert f.source_marks            # the path context is present
    assert f.exit_sites              # passed through an LLM node


def test_fusion4_resolves_wall_to_concrete_sinks():
    fs = _leg_a_dispatch_findings()
    resolved = resolve_dispatch(fs, _model())

    # no dispatch findings remain; they became concrete resolved sinks
    assert not any(f.kind == "dispatch" for f in resolved)
    res_by_name = {f.sink_name: f for f in resolved if f.via_dispatch}
    assert set(res_by_name) == {"run_cmd", "fetch_url"}     # echo (no sink) excluded

    rc = res_by_name["run_cmd"]
    assert rc.kind == "implicit"                            # control-dependency flow
    assert rc.sink_category == "code_execution" and rc.severity == "high"
    assert rc.via_dispatch and "TOOL_MAP" in rc.via_dispatch
    # the dataflow path context is preserved through resolution
    orig = next(f for f in fs if f.kind == "dispatch")
    assert rc.source_marks == orig.source_marks
    assert rc.exit_sites == orig.exit_sites
    assert rc.reachable == orig.reachable

    assert res_by_name["fetch_url"].sink_category == "network"


def test_fusion4_preserves_and_never_invents_guards():
    fs = _leg_a_dispatch_findings()
    model = _model()
    model.tools[0].sink.guard = "confirm_action"            # run_cmd is guarded in the model
    resolved = resolve_dispatch(fs, model)
    by = {f.sink_name: f for f in resolved if f.via_dispatch}
    assert by["run_cmd"].guard == "confirm_action"          # model guard preserved
    assert by["fetch_url"].guard is None                    # unguarded stays unguarded (high priority)


def test_fusion4_recall_first_keeps_wall_when_model_has_no_sinks():
    fs = _leg_a_dispatch_findings()
    empty = RepoToolModel(repo="x", src_root="x", tools=[
        ToolSpec(name="echo", roles=["source"], source=SourceSpec(capacity="string", attacker=True)),
    ])
    resolved = resolve_dispatch(fs, empty)                  # nothing to resolve to
    assert any(f.kind == "dispatch" for f in resolved)      # the wall is still reported


def test_fusion4_passes_non_dispatch_findings_through():
    other = Finding(kind="implicit", sink_name="requests.get", sink_category="network",
                    severity="high", sink_site="a.py:1:1", arg_expr="url", param_type="string",
                    source_marks=())
    out = resolve_dispatch([other], _model())
    assert out == [other]


# ---- #4 narrowing: resolve a dispatch only to the sinks in ITS registry ---- #
import tempfile

_REGISTRIES = (
    "SAFE_TOOLS = {'read_file': read_file, 'list_files': list_files}\n"   # no sinks
    "ADMIN_TOOLS = {'write_file': write_file, 'run_cmd': run_cmd}\n"      # 2 sinks
    "DYN_TOOLS = {}\n"
    "DYN_TOOLS['db_query'] = db_query        # mutation -> untrusted, must fall back\n"
)


def _multi_model():
    return RepoToolModel(repo="x", src_root="x", tools=[
        ToolSpec(name="read_file", roles=["source"], source=SourceSpec(capacity="string", attacker=True)),
        ToolSpec(name="list_files", roles=["source"], source=SourceSpec(capacity="string", attacker=True)),
        ToolSpec(name="write_file", roles=["sink"], sink=SinkSpec(category="file_write", arg="content")),
        ToolSpec(name="run_cmd", roles=["sink"], sink=SinkSpec(category="code_execution", arg="cmd")),
        ToolSpec(name="db_query", roles=["sink"], sink=SinkSpec(category="sql", arg="q")),
    ])


def _disp(sink_name):
    return Finding(kind="dispatch", sink_name=sink_name, sink_category="dispatch",
                   severity="high", sink_site="d.py:1:1", arg_expr=sink_name,
                   param_type="object", source_marks=())


def _repo_with_registries():
    d = tempfile.mkdtemp(prefix="ctaudit_narrow_test_")
    (Path(d) / "registries.py").write_text(_REGISTRIES)
    return d


def _resolved_names(findings):
    return sorted(f.sink_name for f in findings if f.via_dispatch)


def test_narrowing_restricts_to_the_dispatch_registry():
    d, model = _repo_with_registries(), _multi_model()

    # dispatch over a SOURCE-only registry -> reaches NO sink (nothing emitted)
    assert _resolved_names(resolve_dispatch([_disp("SAFE_TOOLS[name]")], model, repo=d)) == []

    # dispatch over the sink registry -> ONLY its sinks (NOT db_query, which lives elsewhere)
    assert _resolved_names(resolve_dispatch([_disp("ADMIN_TOOLS[name]")], model, repo=d)) \
        == ["run_cmd", "write_file"]


def test_narrowing_falls_back_to_repo_global_when_unsure():
    d, model = _repo_with_registries(), _multi_model()

    # a mutated (dynamic) registry is not trusted -> conservative repo-global (all sinks)
    assert _resolved_names(resolve_dispatch([_disp("DYN_TOOLS[name]")], model, repo=d)) \
        == ["db_query", "run_cmd", "write_file"]

    # a higher-order callee has no statically-named registry -> repo-global
    assert _resolved_names(resolve_dispatch([_disp("get_function(name)")], model, repo=d)) \
        == ["db_query", "run_cmd", "write_file"]

    # no repo given at all -> repo-global (backward compatible, recall-first)
    assert _resolved_names(resolve_dispatch([_disp("ADMIN_TOOLS[name]")], model)) \
        == ["db_query", "run_cmd", "write_file"]


# ---- (P) phase / tool-name whitelist gate narrowing ------------------------ #
import tempfile as _tf

_PHASE_FIX = FIXTURES / "phase_gated_agent.py"


def _phase_model():
    return RepoToolModel(repo=str(_PHASE_FIX), src_root=str(FIXTURES), tools=[
        ToolSpec(name="write_file", roles=["sink"], sink=SinkSpec(category="file_write",     arg="content")),
        ToolSpec(name="run_cmd",    roles=["sink"], sink=SinkSpec(category="code_execution", arg="cmd")),
    ])


def test_phase_gate_drops_never_whitelisted_sink():
    fs = analyze_path(str(_PHASE_FIX)).findings
    model = _phase_model()
    # repo-global: both sinks; with repo: registry keeps both (both in TOOL_MAP), then the
    # phase gate drops run_cmd (registered but in NO phase whitelist), keeping write_file.
    assert _resolved_names(resolve_dispatch(fs, model)) == ["run_cmd", "write_file"]
    assert _resolved_names(resolve_dispatch(fs, model, repo=str(_PHASE_FIX))) == ["write_file"]


def test_phase_gate_recall_safe_when_whitelist_mutated():
    # a mutated whitelist is untrusted (its static union may under-count) -> no phase
    # narrowing; run_cmd is NOT dropped (recall-first).
    src = _PHASE_FIX.read_text() + '\nPHASE_TOOLS["admin"] = ["run_cmd"]\n'
    d = _tf.mkdtemp(prefix="ctaudit_phase_test_")
    p = Path(d) / "agent.py"
    p.write_text(src)
    fs = analyze_path(str(p)).findings
    model = RepoToolModel(repo=str(p), src_root=d, tools=[
        ToolSpec(name="write_file", roles=["sink"], sink=SinkSpec(category="file_write",     arg="content")),
        ToolSpec(name="run_cmd",    roles=["sink"], sink=SinkSpec(category="code_execution", arg="cmd")),
    ])
    assert _resolved_names(resolve_dispatch(fs, model, repo=str(p))) == ["run_cmd", "write_file"]


def test_resolved_site_does_not_double_the_path():
    # a classifier-provided site is "path.py:line"; the resolved finding must split it into
    # file + line so the renderer (file + ":" + sink_site) doesn't double the path.
    disp = _disp("REGISTRY[name]")
    disp.file = "pkg/app/dispatchy.py"
    model = RepoToolModel(repo="pkg", src_root="pkg", tools=[
        ToolSpec(name="execute_shell_command", roles=["sink"],
                 sink=SinkSpec(category="code_execution", arg="cmd"),
                 callable="app.dispatchy.ExecuteShell.execute",
                 site="pkg/app/dispatchy.py:9"),
    ])
    out = [f for f in resolve_dispatch([disp], model) if f.via_dispatch]
    assert len(out) == 1
    assert out[0].file == "pkg/app/dispatchy.py"
    assert out[0].sink_site == "9"
