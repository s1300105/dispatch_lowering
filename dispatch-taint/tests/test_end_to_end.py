"""End-to-end tests: each fixture must produce exactly the wiring it was
designed to exhibit.

The fixtures map 1:1 onto the proposal's stages:

* ``langchain_2tool_vuln``  — Stage 1 canonical: tool output -> ToolMessage ->
  history -> llm.invoke -> tool_calls -> subprocess.run  (the implicit /
  control-dependency flow that TITO cannot see).
* ``langchain_2tool_safe``  — same shape but the bridge HIDEs the output, so the
  control edge is cut and nothing should fire (§4.5(4)).
* ``langgraph_state_app``   — Stage 2: add_messages reducer + MessagesState in a
  while-loop (collection propagation + loop fixpoint, §4.3).
* ``mcp_sdk_app``           — Stage 2: CallToolResult -> SamplingMessage ->
  create_message (MCP conversion layer + constructor projection).
* ``openai_agents_app``     — Stage 2: ToolCallOutputItem -> to_input_list() ->
  Runner.run_sync (runner executes tools internally).
* ``data_layer_verbatim``   — §4.1 data layer: tool output reaches the sink
  *verbatim*, so it is an explicit TITO flow, not an implicit one.
* ``schema_pruned_app``     — Stage 3: a bool-returning tool cannot drive a
  free-form string sink, so the candidate is pruned (§4.5(2)/§4.6).
"""

from __future__ import annotations

from conftest import implicit, kept, run


# --------------------------------------------------------------------------- #
# Stage 1 — the canonical cross-tool implicit flow and its safe twin
# --------------------------------------------------------------------------- #
def test_langchain_vuln_fires_one_implicit_flow():
    findings = run("langchain_2tool_vuln.py")
    keep = kept(findings)
    assert len(keep) == 1
    f = keep[0]
    assert f.kind == "implicit"
    assert f.sink_name == "subprocess.run"
    assert f.sink_category == "exec"
    assert f.severity == "high"
    # the source must be attributed to the real, locally-defined tool
    assert "read_webpage" in f.source_tools
    # an implicit flow must pass through at least one LLM node
    assert f.exit_sites, "implicit flow must record the llm.invoke node it joined at"
    # offline triage should not discard the canonical true positive
    assert f.triage_verdict == "true-positive"


def test_langchain_safe_fires_nothing():
    # selective hiding (HIDE) cuts the control edge: no CTL finding at all.
    findings = run("langchain_2tool_safe.py")
    assert kept(findings) == []
    assert implicit(findings) == []


# --------------------------------------------------------------------------- #
# Stage 2 — the three frameworks
# --------------------------------------------------------------------------- #
def test_langgraph_state_app_fires_through_reducer_and_loop():
    findings = run("langgraph_state_app.py")
    keep = kept(findings)
    assert len(keep) == 1
    f = keep[0]
    assert f.kind == "implicit"
    assert f.sink_name == "requests.get"
    assert f.sink_category == "network"
    assert f.exit_sites


def test_mcp_sdk_app_fires_through_conversion_layer():
    findings = run("mcp_sdk_app.py")
    keep = kept(findings)
    assert len(keep) == 1
    f = keep[0]
    assert f.kind == "implicit"
    assert f.sink_name == "cursor.execute"
    assert f.sink_category == "sql"
    assert f.exit_sites


def test_openai_agents_app_fires_through_runner():
    findings = run("openai_agents_app.py")
    keep = kept(findings)
    assert len(keep) == 1
    f = keep[0]
    assert f.kind == "implicit"
    assert f.sink_name == "os.system"
    assert f.sink_category == "exec"
    assert f.exit_sites


# --------------------------------------------------------------------------- #
# §4.1 — the data layer stays explicit (TITO), not implicit
# --------------------------------------------------------------------------- #
def test_data_layer_is_explicit_not_implicit():
    findings = run("data_layer_verbatim.py")
    keep = kept(findings)
    assert len(keep) == 1
    f = keep[0]
    # bytes flow verbatim into the sink => this is classic data flow
    assert f.kind == "explicit"
    assert f.sink_name == "subprocess.run"
    assert "get_filename" in f.source_tools
    # a data-layer flow does not go through an LLM node
    assert not f.exit_sites


# --------------------------------------------------------------------------- #
# Stage 3 — schema / channel-capacity pruning
# --------------------------------------------------------------------------- #
def test_schema_pruned_app_is_pruned_by_channel_capacity():
    findings = run("schema_pruned_app.py")
    # the raw candidate exists ...
    assert any(f.kind == "implicit" for f in findings)
    # ... but nothing survives pruning ...
    assert kept(findings) == []
    # ... and the reason is the narrow (bool) channel.
    pruned = [f for f in findings if f.pruned]
    assert pruned
    assert any("narrower" in (f.prune_reason or "") for f in pruned)


def test_schema_pruned_app_survives_without_schema_prune(no_prune_cfg):
    # ablation: turn the schema reducer off and the candidate should reappear,
    # demonstrating the prune (not the detector) is what removed it.
    findings = run("schema_pruned_app.py", prune_config=no_prune_cfg)
    assert any(f.kind == "implicit" and not f.pruned for f in findings)


# --------------------------------------------------------------------------- #
# Stage 3 — §4.5(1) reachability prune (real prune, fires on a real fixture)
# --------------------------------------------------------------------------- #
from conftest import fixture_path                      # noqa: E402
from ctaudit import RolePolicy, analyze_path, default_registry  # noqa: E402
from ctaudit.analysis.pruning import PruneConfig       # noqa: E402


def test_unreachable_sink_is_pruned_by_reachability():
    findings = run("unreachable_sink_app.py")
    # the candidate exists (the wiring is real) ...
    assert any(f.kind == "implicit" for f in findings)
    # ... but nothing survives, because the sink is dead code ...
    assert kept(findings) == []
    pruned = [f for f in findings if f.pruned]
    assert any("unreachable" in (f.prune_reason or "") for f in pruned)


def test_unreachable_sink_survives_without_reachability_prune():
    # ablation: turn the reachability prune off and the candidate reappears,
    # proving it is the prune (not the detector) that removed it.
    findings = run("unreachable_sink_app.py",
                   prune_config=PruneConfig(reachability=False))
    assert any(f.kind == "implicit" and not f.pruned for f in findings)


# --------------------------------------------------------------------------- #
# Stage 3 — §4.5(3) role prune (real prune, driven by a supplied policy)
# --------------------------------------------------------------------------- #
def _role_setup():
    reg = default_registry()
    reg.roles["read_webpage"] = "fetch-readonly"     # tag the source tool
    policy = RolePolicy(forbidden={"exec": frozenset({"fetch-readonly"})})
    return reg, policy


def test_role_policy_prunes_incompatible_source():
    reg, policy = _role_setup()
    result = analyze_path(fixture_path("langchain_2tool_vuln.py"),
                          registry=reg, role_policy=policy)
    assert result.kept == []
    pruned = [f for f in result.findings if f.pruned]
    assert any("cannot influence" in (f.prune_reason or "") for f in pruned)
    # the role really flowed from the tool, through the wrapper, to the sink mark
    assert any(m.role == "fetch-readonly"
               for f in result.findings for m in f.source_marks)


def test_role_policy_is_ablatable():
    reg, policy = _role_setup()
    result = analyze_path(fixture_path("langchain_2tool_vuln.py"),
                          registry=reg, role_policy=policy,
                          prune_config=PruneConfig(role=False))
    # with role pruning off, the canonical implicit finding is back.
    assert any(f.kind == "implicit" and not f.pruned for f in result.findings)


def test_role_prune_inactive_without_policy():
    # the same fixture through the default pipeline (no role policy) still fires:
    # role assignment is opt-in, so default behaviour is unchanged.
    findings = run("langchain_2tool_vuln.py")
    assert any(f.kind == "implicit" and not f.pruned for f in findings)


# --------------------------------------------------------------------------- #
# §4.3 rule 3 — cross-node (inter-procedural) reducer
# --------------------------------------------------------------------------- #
def test_langgraph_multinode_cross_node_reducer_fires():
    # The tool output, the LLM node, and the sink live in THREE separate node
    # functions wired only by add_messages/add_node. The implicit flow exists
    # solely across node boundaries, so it is found only by the cross-node pass.
    findings = run("langgraph_multinode_app.py")
    keep = kept(findings)
    assert len(keep) == 1
    f = keep[0]
    assert f.kind == "implicit"
    assert f.sink_name == "subprocess.run"
    assert "fetch_url" in f.source_tools          # tool output sourced in tools_node
    assert f.exit_sites                            # the LLM node (in model_node)

    # the LLM node and the sink are in different functions: their lines differ.
    sink_line = int(f.sink_site.split(":")[0])
    exit_lines = [int(s.split(":")[-2]) for s in f.exit_sites]
    assert all(el != sink_line for el in exit_lines)


def test_single_function_langgraph_is_not_disturbed_by_cross_node_pass():
    # the >=2-participant gate keeps the single-function reducer fixture on its
    # precise intra-procedural result (exactly one finding, requests.get sink).
    keep = kept(run("langgraph_state_app.py"))
    assert len(keep) == 1
    assert keep[0].sink_name == "requests.get"
