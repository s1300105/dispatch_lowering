"""Emit a shared :class:`RepoToolModel` to each leg's native input:

  * to_pysa(model)        -> Pysa ``.pysa`` model text  (leg a, data-flow)
  * to_enumeration(model) -> (SOURCES, SINKS) dicts      (leg b, registry enumeration)

Both are pure functions of the same model, so the two legs are guaranteed
consistent (proposal §6 fusion #5).
"""
from __future__ import annotations

from typing import Dict, Tuple

from .schema import CATEGORY_TO_KIND, RepoToolModel


# --------------------------------------------------------------------------- #
# leg (a): Pysa models
# --------------------------------------------------------------------------- #
def to_pysa(model: RepoToolModel) -> str:
    lines = ["# AUTO-GENERATED from the shared tool model (ctaudit.toolmodel). Do not edit by hand.",
             "# Edit the tool model / re-run the classifier instead."]
    if model.llm_call:
        lc = model.llm_call
        lines.append(
            f"def {lc.callable}(self, {lc.prompt_arg}: TaintInTaintOut[Via[llm_node]], **kwargs): ..."
            f"   # join@LLM"
        )
    for t in model.tools:
        if not t.callable:
            continue
        params = []
        if t.recv in ("self", "cls"):
            params.append(t.recv)
        # sink: the dangerous parameter carries a TaintSink[<kind>]
        ret = ""
        if t.sink and t.sink.arg:
            kind = CATEGORY_TO_KIND.get(t.sink.category, "CodeExecution")
            params.append(f"{t.sink.arg}: TaintSink[{kind}]")
        elif "source" in t.roles:
            # source-only tool: still needs a parameter list; keep it generic
            params.append("*args")
        # source: the return value is attacker-influenceable ToolOutput
        if t.source:
            via = f", Via[cap_{t.source.capacity}]"
            ret = f" -> TaintSource[ToolOutput{via}]"
        sig = ", ".join(params) if params else ""
        lines.append(f"def {t.callable}({sig}){ret}: ...   # {t.name} [{','.join(t.roles)}]")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# leg (b): enumeration SOURCES / SINKS dicts (consumed by corpus.agentdojo._common._flows)
# --------------------------------------------------------------------------- #
def to_enumeration(model: RepoToolModel) -> Tuple[Dict[str, dict], Dict[str, dict]]:
    SOURCES: Dict[str, dict] = {}
    SINKS: Dict[str, dict] = {}
    for t in model.tools:
        if t.source and "source" in t.roles:
            SOURCES[f"{t.name}:out"] = dict(
                reachable=t.reachable, capacity=t.source.capacity,
                attacker=t.source.attacker, sensitive=False, hidden=t.source.hidden,
            )
        if t.sink and "sink" in t.roles:
            SINKS[t.name] = dict(
                reachable=t.reachable, sensitive=True, capacity=t.sink.capacity,
                category=t.sink.category, guard=t.sink.guard, arg=t.sink.arg,
            )
    return SOURCES, SINKS
