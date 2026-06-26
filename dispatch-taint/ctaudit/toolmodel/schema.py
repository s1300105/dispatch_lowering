"""Shared tool model (proposal §6 fusion method #5): ONE structured description
of a repo's tools + LLM call, the single source of truth that feeds BOTH legs:

  * leg (a) data-flow  -> emitted as Pysa ``.pysa`` models (emit.to_pysa)
  * leg (b) enumeration -> emitted as SOURCES/SINKS dicts (emit.to_enumeration)

so the source/sink/guard facts are authored (or LLM-classified) ONCE and the two
legs can never drift. Adding a new framework/repo is "produce one ToolModel",
which is the RQ4 portability cost made concrete.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import List, Optional

# tool-output capacity lattice label (must match corpus.agentdojo._common.CAP keys)
CAPACITIES = ("bool", "enum", "numeric", "date", "string")


def _norm_capacity(c) -> str:
    """Clamp a capacity to the known lattice. An LLM may emit a free-form value
    (e.g. ``"filesystem_read"``); map anything unknown to ``string`` — the widest
    channel, so §4.5's schema prune never drops the flow (recall-safe)."""
    return c if c in CAPACITIES else "string"
# sink categories -> Pysa sink kind (must match pysa/models/taint.config)
CATEGORY_TO_KIND = {
    "code_execution": "CodeExecution",
    "sql": "SQL",
    "network": "SSRF",
    "file_write": "FileSystem",
    "file": "FileSystem",
    "deserialize": "Deserialization",
}
CATEGORY_TO_SEVERITY = {
    "code_execution": "high", "sql": "high", "deserialize": "high",
    "network": "medium", "file_write": "medium", "file": "medium",
}


@dataclass
class SinkSpec:
    category: str                         # code_execution / sql / network / file_write / deserialize
    arg: Optional[str] = None             # dangerous parameter name (for the Pysa model)
    capacity: str = "string"
    guard: Optional[str] = None           # in-function guard name, or None (mitigating; never prunes)
    # 方向C: intra-tool reachability of the dangerous argument.
    #   "reaches"  — a parameter provably flows to the dangerous call
    #   "not"      — no parameter reaches it (provably clean; over-approximation case)
    #   "unknown"  — could not decide (kept as a sink, recall-first)
    #   None       — not analysed
    arg_reaches: Optional[str] = None

    def __post_init__(self):
        self.capacity = _norm_capacity(self.capacity)


@dataclass
class SourceSpec:
    capacity: str = "string"              # bandwidth of the tool's OUTPUT
    attacker: bool = True                 # is the output attacker-influenceable?
    hidden: bool = False                  # sanitised / FIDES-HIDE

    def __post_init__(self):
        self.capacity = _norm_capacity(self.capacity)


@dataclass
class ToolSpec:
    name: str                             # LLM-facing tool name (e.g. execute_shell_command)
    callable: Optional[str] = None        # qualified callable for Pysa (module.Class.method)
    recv: Optional[str] = None            # "self" | "cls" | None (leading receiver param)
    roles: List[str] = field(default_factory=list)   # subset of {"source","sink"}
    sink: Optional[SinkSpec] = None
    source: Optional[SourceSpec] = None
    reachable: bool = True
    site: str = ""                        # file:line provenance
    classifier: str = ""                  # which backend produced this ("heuristic"/"anthropic"/...)


@dataclass
class LLMCallSpec:
    callable: str                         # LIBRARY callee to model as the join@LLM node
    prompt_arg: str = "messages"          # kwarg carrying the prompt
    note: str = ""


@dataclass
class RepoToolModel:
    repo: str = ""
    src_root: str = ""
    tools: List[ToolSpec] = field(default_factory=list)
    llm_call: Optional[LLMCallSpec] = None

    # ---- (de)serialisation ------------------------------------------------ #
    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @staticmethod
    def from_json(text: str) -> "RepoToolModel":
        d = json.loads(text)
        tools = []
        for t in d.get("tools", []):
            sk = t.get("sink")
            sr = t.get("source")
            tools.append(ToolSpec(
                name=t["name"], callable=t.get("callable"), recv=t.get("recv"),
                roles=t.get("roles", []),
                sink=SinkSpec(**sk) if sk else None,
                source=SourceSpec(**sr) if sr else None,
                reachable=t.get("reachable", True), site=t.get("site", ""),
                classifier=t.get("classifier", ""),
            ))
        lc = d.get("llm_call")
        return RepoToolModel(
            repo=d.get("repo", ""), src_root=d.get("src_root", ""), tools=tools,
            llm_call=LLMCallSpec(**lc) if lc else None,
        )
