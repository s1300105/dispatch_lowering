"""Framework-wiring model abstraction (§4.2 / §4.4).

The proposal's first main contribution is that the tool-output -> prompt wiring
of the major agent frameworks collapses onto *one skeleton* — wrap a tool output
in a dedicated type, append it to a list/state, hand the list to the model — and
that this skeleton is captured by a *handful* of library models per framework.

This module defines the four model kinds.  They deliberately mirror the
source / propagator / sink models that Pysa (and CodeQL) already provide, so the
port back to a Pysa ``.pysa`` model file (the "implementation continuity with
TaintP2X" of §2.1) is mechanical:

    EntrySpec   ~ a Pysa *source* model        (§4.2(1))
    BridgeSpec  ~ a Pysa *propagator* / TITO    (§4.2(2), §4.3)
    ExitSpec    ~ the control-region start point (§4.2(3), §4.4(2))
    SinkSpec    ~ a Pysa *sink* model           (TaintP2X's 236 sinks, reused)
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


# --------------------------------------------------------------------------- #
# Callee matching helpers
# --------------------------------------------------------------------------- #

def dotted_name(node: ast.AST) -> Optional[str]:
    """Render ``a.b.c`` from a Name/Attribute chain, else ``None``."""
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    # Subscripted / called receivers (e.g. tools[name]) have no static dotted name.
    if isinstance(cur, (ast.Subscript, ast.Call)):
        parts.append("<dynamic>")
        return ".".join(reversed(parts))
    return None


@dataclass(frozen=True)
class CalleePattern:
    """Matches a call's callee by final attribute name + optional receiver hint."""

    attr: str                       # final segment, e.g. "invoke", "run", "system"
    recv_contains: Optional[str] = None  # substring that must appear in the receiver
    bare: bool = False              # match a bare Name() call, e.g. eval(...)

    def matches(self, call: ast.Call, resolved: Optional["Iterable[str]"] = None) -> bool:
        """Match a call, preferring binding-resolved canonical name(s).

        ``resolved`` is the set of fully-qualified callables the call site refers
        to (from :class:`~ctaudit.models.aliases.AliasResolver`), so an aliased
        call (``completion = client.chat.completions.create``; ``import x as y``)
        matches its model even though the surface syntax differs (§6.4 fix).  We
        match if *any* candidate matches, then fall back to raw-AST matching so
        dynamic/unresolved callees still work.
        """
        if resolved:
            if any(self._matches_dotted(d) for d in resolved):
                return True
        return self._matches_raw(call)

    def _matches_dotted(self, dotted: str) -> bool:
        """Match against a canonical dotted name, e.g. ``client...create``."""
        if not dotted:
            return False
        segs = dotted.split(".")
        last = segs[-1]
        if self.bare:
            return len(segs) == 1 and last == self.attr
        if last != self.attr:
            return False
        if self.recv_contains is None:
            return True
        recv = ".".join(segs[:-1])
        return self.recv_contains.lower() in recv.lower()

    def _matches_raw(self, call: ast.Call) -> bool:
        fn = call.func
        if self.bare:
            return isinstance(fn, ast.Name) and fn.id == self.attr
        if isinstance(fn, ast.Attribute):
            if fn.attr != self.attr:
                return False
            if self.recv_contains is None:
                return True
            recv = dotted_name(fn.value) or ""
            return self.recv_contains.lower() in recv.lower()
        if isinstance(fn, ast.Name):
            # allow bare-name match for patterns that also accept it
            return fn.id == self.attr and self.recv_contains is None
        return False


def matches_any(call: ast.Call, patterns: Sequence[CalleePattern],
                resolved: Optional[Iterable[str]] = None) -> bool:
    return any(p.matches(call, resolved) for p in patterns)


# --------------------------------------------------------------------------- #
# Type lattice for schema-based pruning (§4.5(2))
# --------------------------------------------------------------------------- #
# Constrained-decoding channel capacity (§4.6): bool <= enum <= string.  The
# wider the type the more attacker bits it can carry; free-form strings are the
# dangerous case.

CHANNEL_ORDER = {"bool": 0, "enum": 1, "int": 1, "number": 1, "string": 2, "object": 3, "any": 3}


def channel_capacity(t: Optional[str]) -> int:
    return CHANNEL_ORDER.get((t or "any").lower(), 3)


# --------------------------------------------------------------------------- #
# Model specifications
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ToolSpec:
    """A tool whose *return value* is attacker-influenceable (§4.2 source).

    Two ways to identify a tool:

    * ``decorators`` — a *local* function decorated with one of these names
      (``@tool``, ``@function_tool`` ...) is a tool; every call to it is a
      source.
    * ``callee`` — a generic dispatch whose result is attacker-controlled, e.g.
      the MCP client's ``session.call_tool(...)``; every matching call is a
      source.

    ``output_type`` (when declared) feeds the schema pruner; ``role`` (when
    declared) feeds the role pruner (§4.5(3)).
    """

    decorators: Tuple[str, ...] = ()      # decorator names that mark a function as a tool
    callee: Optional[CalleePattern] = None  # dispatch whose result is a source
    output_type: Optional[str] = None     # declared return type for schema pruning
    role: Optional[str] = None            # declared role/permission for role pruning (§4.5(3))
    framework: str = "generic"


@dataclass(frozen=True)
class EntrySpec:
    """A tool-output *wrapper* whose construction introduces taint (§4.2(1)).

    ``ctor`` is the wrapper callee (e.g. ``ToolMessage``); ``content_kwargs`` /
    ``content_positional`` name the argument(s) carrying the tool output.  The
    constructed object is tainted regardless (tool messages by definition carry
    tool output), and any taint already on the content argument is preserved.
    """

    ctor: CalleePattern
    content_kwargs: Tuple[str, ...] = ()
    content_positional: Tuple[int, ...] = (0,)
    framework: str = "generic"
    output_type: Optional[str] = "string"


@dataclass(frozen=True)
class BridgeSpec:
    """An append / extend / reducer step that carries taint into the history (§4.2(2), §4.3).

    ``kind`` selects the collection-propagation rule applied by the engine:

      * ``"append"``  — ``hist.append(x)``      : taint x -> taint hist[*]
      * ``"extend"``  — ``hist.extend(xs)`` / ``hist += xs`` : elements -> hist[*]
      * ``"aggregate"`` — ``xs.to_input_list()`` : taint xs -> taint result
      * ``"reducer"`` — declarative state merge (LangGraph ``add_messages``):
                        returning ``{key: [x]}`` merges into ``state[key]``.
    """

    callee: CalleePattern
    kind: str
    reducer_key: Optional[str] = None     # for kind == "reducer"
    framework: str = "generic"


@dataclass(frozen=True)
class ExitSpec:
    """An LLM invocation: the control-region start point (§4.2(3), §4.4(2)).

    ``prompt_kwargs`` / ``prompt_positional`` name the argument carrying the
    message collection.  The call's result is lifted to CTL = join of the marks
    on that collection.
    """

    callee: CalleePattern
    prompt_kwargs: Tuple[str, ...] = ()
    prompt_positional: Tuple[int, ...] = (0,)
    framework: str = "generic"
    taints_result: bool = False        # runner executes tools internally (e.g. OpenAI
                                       # Agents Runner.run): its result is control-tainted
                                       # even when the passed-in prompt is clean.


@dataclass(frozen=True)
class SinkSpec:
    """A dangerous callable (a TaintP2X sink, reused — §2.1).

    ``dangerous_params`` lists positional indices and/or keyword names whose
    tainted value triggers a finding.  ``param_type`` is the *expected* type of
    that parameter, used by the channel-capacity heuristic (§4.6).
    """

    callee: CalleePattern
    name: str                              # human-readable sink id, e.g. "subprocess.run"
    category: str                          # exec | file | sql | network | deserialize | ...
    severity: str = "high"                 # high | medium | low
    dangerous_positional: Tuple[int, ...] = (0,)
    dangerous_kwargs: Tuple[str, ...] = ()
    param_type: str = "string"             # expected type of the dangerous param


@dataclass(frozen=True)
class DispatchSpec:
    """A framework's *managed* tool dispatch (項目1 — declarative support part).

    Many real agents never write ``TOOL_MAP[name](...)`` themselves.  They hand a
    tool list to a framework factory and then call a launch method; the framework
    selects and invokes the chosen tool *internally* (e.g. LangGraph's ToolNode).
    The dispatch wall is therefore invisible to a syntactic scan of user code, and
    a general static analysis cannot follow it without penetrating the framework
    body (Pysa-scale, unrelated to our novelty).

    Instead we *declare* the known dispatch semantics of the framework:

    * ``factory``     — the registration call that defines the tool set
                        (e.g. ``create_react_agent``, ``create_agent``,
                        ``AgentExecutor``).
    * ``tools_kwarg`` / ``tools_positional`` — which argument of ``factory``
                        carries the registered tool list (the candidate set).
    * ``launch``      — the method on the returned object that triggers dispatch
                        (e.g. ``.invoke`` / ``.stream`` / ``.ainvoke``); this is
                        the *wall*.
    * ``prompt_kwargs`` / ``prompt_positional`` — which launch argument carries
                        the prompt/messages, used to test attacker influence.

    This is a declarative absorption of *known* dispatch semantics, deliberately
    NOT a general analysis of the framework internals, and is not claimed as a
    novelty — it is a support part that connects framework-managed dispatch to the
    existing wall-resolution machinery (resolve_dispatch).
    """

    factory: CalleePattern
    launch: CalleePattern
    tools_kwarg: Tuple[str, ...] = ("tools",)
    tools_positional: Tuple[int, ...] = ()
    prompt_kwargs: Tuple[str, ...] = ()
    prompt_positional: Tuple[int, ...] = (0,)
    framework: str = "generic"


@dataclass
class ModelRegistry:
    """Aggregates all framework models + the sink catalog."""

    tools: List[ToolSpec] = field(default_factory=list)
    entries: List[EntrySpec] = field(default_factory=list)
    bridges: List[BridgeSpec] = field(default_factory=list)
    exits: List[ExitSpec] = field(default_factory=list)
    sinks: List[SinkSpec] = field(default_factory=list)
    # Framework-managed dispatch specs (項目1): factory(...tools=[...]) + launch
    # (.invoke/.stream) where the framework selects+invokes the tool internally.
    dispatches: List["DispatchSpec"] = field(default_factory=list)
    # Optional tool-name -> role map (§4.5(3)).  Real agent code rarely annotates
    # tools with a role, so role assignment is a policy the auditor supplies; this
    # map lets a name be tagged without editing specs.  Empty by default, which
    # makes the role pruner a conservative no-op unless a policy is configured.
    roles: Dict[str, str] = field(default_factory=dict)

    def extend(self, other: "ModelRegistry") -> "ModelRegistry":
        self.tools += other.tools
        self.entries += other.entries
        self.bridges += other.bridges
        self.exits += other.exits
        self.sinks += other.sinks
        self.dispatches += other.dispatches
        self.roles.update(other.roles)
        return self

    def role_of(self, tool_name: Optional[str]) -> Optional[str]:
        if not tool_name:
            return None
        return self.roles.get(tool_name)

    # -- lookups used by the engine ------------------------------------------ #
    def tool_decorator_names(self) -> set:
        names = set()
        for t in self.tools:
            names |= set(t.decorators)
        return names

    def match_entry(self, call: ast.Call, resolved: Optional[Iterable[str]] = None) -> Optional[EntrySpec]:
        for e in self.entries:
            if e.ctor.matches(call, resolved):
                return e
        return None

    def match_result_source(self, call: ast.Call, resolved: Optional[Iterable[str]] = None) -> Optional[ToolSpec]:
        for t in self.tools:
            if t.callee is not None and t.callee.matches(call, resolved):
                return t
        return None

    def match_bridge(self, call: ast.Call, resolved: Optional[Iterable[str]] = None) -> Optional[BridgeSpec]:
        for b in self.bridges:
            if b.callee.matches(call, resolved):
                return b
        return None

    def match_exit(self, call: ast.Call, resolved: Optional[Iterable[str]] = None) -> Optional[ExitSpec]:
        for x in self.exits:
            if x.callee.matches(call, resolved):
                return x
        return None

    def match_sink(self, call: ast.Call, resolved: Optional[Iterable[str]] = None) -> Optional[SinkSpec]:
        for s in self.sinks:
            if s.callee.matches(call, resolved):
                return s
        return None

    def match_dispatch_factory(self, call: ast.Call, resolved: Optional[Iterable[str]] = None) -> Optional["DispatchSpec"]:
        """Match a framework registration call, e.g. ``create_react_agent(tools=[...])``."""
        for d in self.dispatches:
            if d.factory.matches(call, resolved):
                return d
        return None

    def match_dispatch_launch(self, call: ast.Call, resolved: Optional[Iterable[str]] = None) -> Optional["DispatchSpec"]:
        """Match a framework launch call (the wall), e.g. ``agent.invoke({...})``."""
        for d in self.dispatches:
            if d.launch.matches(call, resolved):
                return d
        return None

# --------------------------------------------------------------------------- #
# Control-flow reachability (§4.5(1))
# --------------------------------------------------------------------------- #
def unreachable_nodes(tree: ast.AST) -> Set[int]:
    """Return ``id()`` of every AST node that can never execute.

    This is the static, *prompt-construction reachability* fact of §4.5(1):
    after an unconditional terminator (``return`` / ``raise`` / ``break`` /
    ``continue``) inside a statement suite, all later sibling statements — and
    everything nested under them — are dead code and can never run.  A sink in
    dead code is unreachable, so any cross-tool candidate ending there is a
    static over-approximation the reachability pruner removes.

    The check is sound: a terminator inside a *nested* block (e.g. one arm of an
    ``if``) does not kill the enclosing suite, so only a terminator that is a
    *direct* statement of a suite ends that suite.
    """
    dead: Set[int] = set()
    _TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)

    def kill(node: ast.AST) -> None:
        for d in ast.walk(node):
            dead.add(id(d))

    def visit_suite(stmts: List[ast.stmt]) -> None:
        terminated = False
        for s in stmts:
            if terminated:
                kill(s)
                continue
            visit_stmt(s)
            if isinstance(s, _TERMINATORS):
                terminated = True

    def visit_stmt(s: ast.stmt) -> None:
        for fieldname in ("body", "orelse", "finalbody"):
            sub = getattr(s, fieldname, None)
            if isinstance(sub, list) and sub and isinstance(sub[0], ast.stmt):
                visit_suite(sub)
        for handler in getattr(s, "handlers", []) or []:
            visit_suite(handler.body)

    body = getattr(tree, "body", None)
    if isinstance(body, list):
        visit_suite(body)
    return dead
