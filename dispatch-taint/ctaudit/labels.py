"""Two-layer taint domain.

This module encodes the abstract domain for the proposal's *two cooperating
taint regions* (§4):

* ``Kind.DATA`` — the **data layer** (§4.1).  Classic taint-in-taint-out (TITO):
  the *bytes* of a tool output flow into a sink.  Explicit flow / data
  dependency.  This is what TaintP2X already captures.

* ``Kind.CTL``  — the **control / influence layer** (§4.4).  Implicit flow /
  control dependency: a tool output does not necessarily copy any byte into a
  sink argument, but *selects* which sink is invoked, via the LLM's reasoning.
  This is the CWE-1426 phenomenon the proposal targets and which TITO cannot
  see.

A taint value is a *set* of :class:`Label` objects.  The lattice join used at an
``llm.invoke`` node (the program-counter / pc label of §2.2.2) is simply the
set union of the marks carried by the prompt's messages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Iterable, Optional, Set


class Kind(str, Enum):
    """Which information-flow channel a label rides on."""

    DATA = "data-taint"   # explicit flow, data dependency (§4.1)
    CTL = "ctl-taint"     # implicit flow, control dependency (§4.4)


@dataclass(frozen=True)
class SourceMark:
    """Provenance of a piece of attacker-influenceable data.

    A *tool output* is the canonical attacker-influenceable source: a tool may
    fetch a web page, read a file, or query a database, any of which can carry
    injected instructions.  ``tool`` records *which* tool produced the value so
    that schema-based pruning (§4.5(2)) can reason about (source -> sink) pairs.
    """

    tool: str                       # name of the originating tool ("<tool-output>" if unknown)
    framework: str                  # langchain | langgraph | mcp | openai-agents | generic
    site: str                       # "path:line" where the value entered the analysis
    hidden: bool = False            # selective hiding / FIDES HIDE (§4.5(4)): passed by
                                    # reference, never expanded into the prompt text.
    out_type: Optional[str] = None  # declared output type of the source tool (schema pruning, §4.5(2))
    role: Optional[str] = None      # declared role/permission of the source tool (role pruning, §4.5(3))

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        h = " (hidden)" if self.hidden else ""
        r = f"<{self.role}>" if self.role else ""
        return f"{self.tool}@{self.site}[{self.framework}]{r}{h}"


@dataclass(frozen=True)
class Label:
    """A single taint fact: a channel (:class:`Kind`) plus its provenance set."""

    kind: Kind
    marks: FrozenSet[SourceMark] = field(default_factory=frozenset)

    def with_kind(self, kind: Kind) -> "Label":
        return Label(kind=kind, marks=self.marks)


# A taint value attached to an access path is a set of labels.
TaintSet = Set[Label]


def empty() -> TaintSet:
    return set()


def union(*sets: Iterable[Label]) -> TaintSet:
    out: TaintSet = set()
    for s in sets:
        out |= set(s)
    return out


def marks_of(labels: Iterable[Label], kind: Kind | None = None) -> FrozenSet[SourceMark]:
    """Collect (optionally kind-filtered) provenance marks from a taint set."""
    acc: Set[SourceMark] = set()
    for lab in labels:
        if kind is None or lab.kind == kind:
            acc |= set(lab.marks)
    return frozenset(acc)


def has_kind(labels: Iterable[Label], kind: Kind) -> bool:
    return any(lab.kind == kind for lab in labels)


def join_to_ctl(labels: Iterable[Label]) -> TaintSet:
    """The pc-label join performed at an LLM node (§4.4(2)).

    Every mark carried by the prompt — whether it arrived as DATA (bytes wired
    into the history) or CTL (already control-tainted from an earlier turn) —
    is lifted into a single CTL label on the LLM response.  Marks flagged
    ``hidden`` are dropped: selectively hidden outputs do not influence the
    model's choice, so they cut the control edge (§4.5(4)).
    """
    joined: Set[SourceMark] = set()
    for lab in labels:
        for m in lab.marks:
            if not m.hidden:
                joined.add(m)
    if not joined:
        return set()
    return {Label(kind=Kind.CTL, marks=frozenset(joined))}
