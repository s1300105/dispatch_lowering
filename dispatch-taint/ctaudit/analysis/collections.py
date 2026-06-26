"""Collection propagation — the static-specific difficulty of §4.3.

The bridge operations of every framework (``add_messages``, ``to_input_list()``,
appends to a state dict) all *put a tainted value into a collection and later
take the whole collection out*.  This is exactly where ordinary data-flow
tracking tends to break, and — as the proposal notes — it is a difficulty that a
*dynamic* planner-following analysis (FIDES) never faces, because it carries
labels along a concrete run.  A static lift has to model it explicitly.

This module owns the taint environment and the three rules of §4.3:

  Rule 1 (element insert) : tainting an element taints the collection.
  Rule 2 (aggregate read) : reading the collection yields the join of element
                            taints (this is why an LLM node sees a tool output
                            no matter how it was inserted).
  Rule 3 (reducer merge)  : a declarative state merge (LangGraph ``add_messages``)
                            joins the new-message labels with the existing
                            history labels.

Access paths are kept as canonical strings (``"messages"``, ``"messages[*]"``,
``'state["messages"]'``).  Element taint of a collection ``c`` lives under the
``"[*]"`` suffix; rule 2 unions a path with its ``[*]`` child on every read.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Iterable, Tuple

from ..labels import Label, TaintSet

ELEM = "[*]"


class Env:
    """A flow-sensitive taint environment: access-path string -> taint set."""

    def __init__(self) -> None:
        self.m: Dict[str, set] = {}

    def get(self, path: str) -> TaintSet:
        return set(self.m.get(path, ()))

    def set(self, path: str, taints: Iterable[Label]) -> None:
        t = set(taints)
        if t:
            self.m[path] = t
        else:
            self.m.pop(path, None)

    def add(self, path: str, taints: Iterable[Label]) -> None:
        t = set(taints)
        if not t:
            return
        self.m.setdefault(path, set()).update(t)

    def read_var(self, name: str) -> TaintSet:
        """Rule 2 for a plain variable: own taint joined with element taint."""
        return self.get(name) | self.get(name + ELEM)

    def copy(self) -> "Env":
        e = Env()
        e.m = {k: set(v) for k, v in self.m.items()}
        return e

    def join_in(self, other: "Env") -> None:
        for k, v in other.m.items():
            self.add(k, v)

    def signature(self) -> FrozenSet[Tuple[str, FrozenSet[Label]]]:
        """Hashable snapshot, used to detect loop fixpoint."""
        return frozenset((k, frozenset(v)) for k, v in self.m.items() if v)


# --------------------------------------------------------------------------- #
# The three rules (pure helpers over an Env)
# --------------------------------------------------------------------------- #

def insert_element(env: Env, coll_path: str, value_taint: TaintSet) -> None:
    """Rule 1: ``coll.append(x)`` / ``coll += [x]`` -> taint ``coll[*]``."""
    env.add(coll_path + ELEM, value_taint)


def aggregate_read(env: Env, coll_path: str) -> TaintSet:
    """Rule 2: reading a collection yields own-taint joined with element-taint."""
    return env.get(coll_path) | env.get(coll_path + ELEM)


def reducer_merge(arg_taints: Iterable[TaintSet]) -> TaintSet:
    """Rule 3: a declarative reducer (``add_messages(a, b)``) joins its operands.

    Both operands are message collections; reading each aggregates its elements,
    and the merged result carries the union — exactly the "join the new-message
    labels with the existing-history labels" semantics of §4.3 rule 3.
    """
    out: set = set()
    for t in arg_taints:
        out |= set(t)
    return out
