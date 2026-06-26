"""Unit tests for the two-layer taint domain (§4.1 / §4.4).

The single most important operation in the whole analysis is
:func:`~ctaudit.labels.join_to_ctl` — the program-counter join performed at an
``llm.invoke`` node.  It is what turns "bytes of a tool output sitting in the
prompt history" (DATA) into "the model's next tool choice is attacker-influenced"
(CTL), and it is where selective hiding (§4.5(4)) takes effect.
"""

from __future__ import annotations

from ctaudit.labels import (
    Kind,
    Label,
    SourceMark,
    has_kind,
    join_to_ctl,
    marks_of,
    union,
)


def _mark(tool: str, hidden: bool = False, out_type=None) -> SourceMark:
    return SourceMark(
        tool=tool,
        framework="langchain",
        site=f"f.py:{len(tool)}",
        hidden=hidden,
        out_type=out_type,
    )


def test_join_lifts_data_marks_into_a_single_ctl_label():
    data = {Label(Kind.DATA, frozenset({_mark("web")}))}
    out = join_to_ctl(data)
    assert len(out) == 1
    (label,) = out
    assert label.kind is Kind.CTL
    assert {m.tool for m in label.marks} == {"web"}


def test_join_unions_marks_from_several_prompt_messages():
    prompt = {
        Label(Kind.DATA, frozenset({_mark("web")})),
        Label(Kind.CTL, frozenset({_mark("db")})),
    }
    out = join_to_ctl(prompt)
    assert len(out) == 1
    (label,) = out
    # the join is the union of every prompt mark, regardless of incoming kind
    assert {m.tool for m in label.marks} == {"web", "db"}
    assert label.kind is Kind.CTL


def test_join_drops_hidden_marks_selective_hiding():
    # a single hidden source contributes nothing => the control edge is cut.
    hidden_only = {Label(Kind.DATA, frozenset({_mark("secret", hidden=True)}))}
    assert join_to_ctl(hidden_only) == set()


def test_join_keeps_visible_drops_hidden_in_mixed_prompt():
    mixed = {
        Label(Kind.DATA, frozenset({_mark("web"), _mark("secret", hidden=True)})),
    }
    out = join_to_ctl(mixed)
    (label,) = out
    assert {m.tool for m in label.marks} == {"web"}  # secret was hidden


def test_join_of_empty_is_empty():
    assert join_to_ctl(set()) == set()


def test_marks_of_filters_by_kind():
    labels = {
        Label(Kind.DATA, frozenset({_mark("web")})),
        Label(Kind.CTL, frozenset({_mark("db")})),
    }
    assert {m.tool for m in marks_of(labels, Kind.DATA)} == {"web"}
    assert {m.tool for m in marks_of(labels, Kind.CTL)} == {"db"}
    assert {m.tool for m in marks_of(labels)} == {"web", "db"}


def test_has_kind():
    labels = {Label(Kind.CTL, frozenset({_mark("db")}))}
    assert has_kind(labels, Kind.CTL)
    assert not has_kind(labels, Kind.DATA)


def test_union_merges_label_sets():
    a = {Label(Kind.DATA, frozenset({_mark("web")}))}
    b = {Label(Kind.CTL, frozenset({_mark("db")}))}
    assert union(a, b) == a | b


def test_with_kind_preserves_marks():
    m = frozenset({_mark("web")})
    data = Label(Kind.DATA, m)
    ctl = data.with_kind(Kind.CTL)
    assert ctl.kind is Kind.CTL
    assert ctl.marks == m


def test_labels_are_hashable_and_value_equal():
    # frozen dataclasses: two structurally-equal labels collapse in a set.
    m = _mark("web")
    s = {Label(Kind.DATA, frozenset({m})), Label(Kind.DATA, frozenset({m}))}
    assert len(s) == 1
