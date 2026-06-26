"""Unit tests for the Stage-3 reducers (§4.5) and offline triage (§4.6).

These exercise pruning and triage on hand-built :class:`Finding` objects so the
logic is tested independently of the AST front-end.
"""

from __future__ import annotations

from ctaudit.analysis.pruning import PruneConfig, RolePolicy, kept, prune
from ctaudit.labels import SourceMark
from ctaudit.models.base import unreachable_nodes
from ctaudit.report import Finding
from ctaudit.triage.llm_triage import MockTriage

import ast


def make_finding(kind="implicit", param_type="string", marks=()):
    return Finding(
        kind=kind,
        sink_name="subprocess.run",
        sink_category="exec",
        severity="high",
        sink_site="10:4",
        arg_expr="cmd",
        param_type=param_type,
        source_marks=tuple(marks),
        exit_sites=("f.py:5:1",),
        file="f.py",
    )


def mark(tool="web", hidden=False, out_type=None, role=None):
    return SourceMark(tool=tool, framework="langchain", site="f.py:1",
                      hidden=hidden, out_type=out_type, role=role)


# --------------------------------------------------------------------------- #
# §4.5(2) schema / channel-capacity
# --------------------------------------------------------------------------- #
def test_bool_source_into_string_sink_is_pruned():
    f = make_finding(marks=[mark(out_type="bool")])
    prune([f])
    assert f.pruned
    assert "narrower" in f.prune_reason


def test_string_source_into_string_sink_survives():
    f = make_finding(marks=[mark(out_type="string")])
    prune([f])
    assert not f.pruned


def test_one_wide_source_among_narrow_ones_survives():
    # rule fires only if *every* contributing source is too narrow.
    f = make_finding(marks=[mark("a", out_type="bool"), mark("b", out_type="string")])
    prune([f])
    assert not f.pruned


def test_unknown_out_type_does_not_prune():
    # no declared channel => cannot claim it is too narrow (stay conservative).
    f = make_finding(marks=[mark(out_type=None)])
    prune([f])
    assert not f.pruned


def test_schema_prune_is_ablatable():
    f = make_finding(marks=[mark(out_type="bool")])
    prune([f], PruneConfig(schema=False))
    assert not f.pruned


# --------------------------------------------------------------------------- #
# §4.5(4) selective hiding backstop
# --------------------------------------------------------------------------- #
def test_all_hidden_marks_are_pruned():
    f = make_finding(marks=[mark(hidden=True)])
    prune([f])
    assert f.pruned
    assert "hiding" in f.prune_reason


def test_partially_hidden_survives():
    f = make_finding(marks=[mark("a", hidden=True), mark("b", hidden=False)])
    prune([f])
    assert not f.pruned


def test_hiding_prune_is_ablatable():
    f = make_finding(marks=[mark(hidden=True)])
    prune([f], PruneConfig(selective_hiding=False))
    assert not f.pruned


def test_kept_filters_pruned():
    a = make_finding(marks=[mark(out_type="string")])
    b = make_finding(marks=[mark(out_type="bool")])
    prune([a, b])
    assert kept([a, b]) == [a]


# --------------------------------------------------------------------------- #
# §4.6 offline triage (deterministic mock)
# --------------------------------------------------------------------------- #
def test_mock_triage_keeps_high_sev_free_form_implicit_as_true_positive():
    f = make_finding(marks=[mark(out_type="string")])
    MockTriage().triage([f], source="x = 1\n")
    assert f.triage_verdict == "true-positive"
    assert f.triage_confidence is not None


def test_mock_triage_is_deterministic():
    f1 = make_finding(marks=[mark(out_type="string")])
    f2 = make_finding(marks=[mark(out_type="string")])
    t = MockTriage()
    t.triage([f1], source="x = 1\n")
    t.triage([f2], source="x = 1\n")
    assert f1.triage_verdict == f2.triage_verdict
    assert f1.triage_confidence == f2.triage_confidence


# --------------------------------------------------------------------------- #
# §4.5(1) reachability
# --------------------------------------------------------------------------- #
def test_unreachable_finding_is_pruned():
    f = make_finding(marks=[mark(out_type="string")])
    f.reachable = False
    prune([f])
    assert f.pruned
    assert "unreachable" in f.prune_reason


def test_reachable_finding_survives():
    f = make_finding(marks=[mark(out_type="string")])
    assert f.reachable is True
    prune([f])
    assert not f.pruned


def test_reachability_prune_is_ablatable():
    f = make_finding(marks=[mark(out_type="string")])
    f.reachable = False
    prune([f], PruneConfig(reachability=False))
    assert not f.pruned


def test_unreachable_nodes_marks_dead_code_after_return():
    src = (
        "def f(x):\n"
        "    a = x\n"
        "    return a\n"
        "    dangerous(a)\n"   # dead
    )
    tree = ast.parse(src)
    dead = unreachable_nodes(tree)
    # locate the dangerous(...) call
    danger = [n for n in ast.walk(tree)
              if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "dangerous"][0]
    live = [n for n in ast.walk(tree)
            if isinstance(n, ast.Name) and n.id == "x"][0]
    assert id(danger) in dead
    assert id(live) not in dead


def test_unreachable_nodes_keeps_conditional_return_live():
    # a return inside an if-arm does NOT kill the following sibling statement.
    src = (
        "def f(x, c):\n"
        "    if c:\n"
        "        return x\n"
        "    dangerous(x)\n"   # still reachable when c is false
    )
    tree = ast.parse(src)
    dead = unreachable_nodes(tree)
    danger = [n for n in ast.walk(tree)
              if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "dangerous"][0]
    assert id(danger) not in dead


# --------------------------------------------------------------------------- #
# §4.5(3) role constraints
# --------------------------------------------------------------------------- #
def test_role_incompatible_source_is_pruned():
    f = make_finding(marks=[mark(role="label-only")])   # sink_category == "exec"
    pol = RolePolicy(forbidden={"exec": frozenset({"label-only"})})
    prune([f], role_policy=pol)
    assert f.pruned
    assert "label-only" in f.prune_reason


def test_role_unknown_keeps_finding():
    f = make_finding(marks=[mark(role=None)])
    pol = RolePolicy(forbidden={"exec": frozenset({"label-only"})})
    prune([f], role_policy=pol)
    assert not f.pruned


def test_role_one_allowed_among_forbidden_keeps_finding():
    # rule fires only if EVERY contributing role is forbidden.
    f = make_finding(marks=[mark("a", role="label-only"), mark("b", role="fetch")])
    pol = RolePolicy(forbidden={"exec": frozenset({"label-only"})})
    prune([f], role_policy=pol)
    assert not f.pruned


def test_role_no_policy_is_noop():
    f = make_finding(marks=[mark(role="label-only")])
    prune([f])  # no role_policy
    assert not f.pruned


def test_role_prune_is_ablatable():
    f = make_finding(marks=[mark(role="label-only")])
    pol = RolePolicy(forbidden={"exec": frozenset({"label-only"})})
    prune([f], PruneConfig(role=False), role_policy=pol)
    assert not f.pruned


def test_role_wrong_category_keeps_finding():
    # policy forbids the role for sql, but the sink is exec -> not pruned.
    f = make_finding(marks=[mark(role="label-only")])
    pol = RolePolicy(forbidden={"sql": frozenset({"label-only"})})
    prune([f], role_policy=pol)
    assert not f.pruned
