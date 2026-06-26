"""Unit tests for collection propagation (§4.3).

These three rules are the static-specific difficulty the proposal calls out: a
dynamic planner-following analysis never has to reason about "insert into a
collection now, read the whole collection later", but a static lift does.  The
loop fixpoint in the engine relies on :meth:`Env.signature` converging.
"""

from __future__ import annotations

from ctaudit.analysis.collections import (
    ELEM,
    Env,
    aggregate_read,
    insert_element,
    reducer_merge,
)
from ctaudit.labels import Kind, Label, SourceMark


def _taint(tool: str) -> set:
    m = SourceMark(tool=tool, framework="langgraph", site="f.py:1")
    return {Label(Kind.DATA, frozenset({m}))}


def test_rule1_insert_element_taints_the_collection():
    env = Env()
    insert_element(env, "messages", _taint("web"))
    # the element slot carries the taint ...
    assert env.get("messages" + ELEM)
    # ... and an aggregate read of the collection now sees it.
    assert aggregate_read(env, "messages")


def test_rule2_aggregate_read_joins_own_and_element_taint():
    env = Env()
    env.set("messages", _taint("own"))
    insert_element(env, "messages", _taint("elem"))
    out = aggregate_read(env, "messages")
    tools = {m.tool for lab in out for m in lab.marks}
    assert tools == {"own", "elem"}


def test_rule2_read_var_joins_var_with_element():
    env = Env()
    insert_element(env, "history", _taint("elem"))
    out = env.read_var("history")
    assert {m.tool for lab in out for m in lab.marks} == {"elem"}


def test_rule3_reducer_merge_joins_operands():
    new = _taint("new")
    existing = _taint("existing")
    merged = reducer_merge([new, existing])
    assert {m.tool for lab in merged for m in lab.marks} == {"new", "existing"}


def test_reducer_merge_of_empty_is_empty():
    assert reducer_merge([]) == set()
    assert reducer_merge([set(), set()]) == set()


def test_env_set_empty_clears_path():
    env = Env()
    env.set("x", _taint("a"))
    assert env.get("x")
    env.set("x", set())
    assert env.get("x") == set()


def test_env_copy_is_isolated():
    env = Env()
    env.set("x", _taint("a"))
    clone = env.copy()
    clone.add("x", _taint("b"))
    # mutating the clone must not leak back into the original
    assert {m.tool for lab in env.get("x") for m in lab.marks} == {"a"}
    assert {m.tool for lab in clone.get("x") for m in lab.marks} == {"a", "b"}


def test_env_join_in_unions_environments():
    a = Env()
    a.set("x", _taint("a"))
    b = Env()
    b.set("x", _taint("b"))
    b.set("y", _taint("c"))
    a.join_in(b)
    assert {m.tool for lab in a.get("x") for m in lab.marks} == {"a", "b"}
    assert {m.tool for lab in a.get("y") for m in lab.marks} == {"c"}


def test_signature_converges_for_fixpoint_detection():
    # the loop fixpoint stops when the signature stops changing.
    env = Env()
    env.set("x", _taint("a"))
    sig1 = env.signature()
    # re-adding the same taint must not change the signature (=> fixpoint)
    env.add("x", _taint("a"))
    assert env.signature() == sig1
    # adding genuinely new taint must change it (=> keep iterating)
    env.add("x", _taint("b"))
    assert env.signature() != sig1
