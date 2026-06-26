"""The core static taint engine (§4.1–§4.4).

This is where the two cooperating taint regions of the proposal are actually
propagated over a Python AST *without executing it*:

* the **data layer** (``Kind.DATA``, §4.1) is kept precise — a generic call does
  *not* propagate DATA through it, so verbatim tool-output -> sink flows are the
  only DATA findings (TITO, what TaintP2X already does);

* the **control / influence layer** (``Kind.CTL``, §4.4) is the new, deliberately
  over-approximate region.  It is *born* at an LLM node: :func:`join_to_ctl`
  collapses the marks of every message in the prompt collection into a single CTL
  label on the model's response, and that label then rides along
  ``response.tool_calls[i].args`` into any sink — the implicit / control
  dependency of CWE-1426.

The static-specific difficulty (§4.3) is collection propagation: tool outputs are
*put into* a message list and the *whole list* is later handed to the model.
:class:`~ctaudit.analysis.collections.Env` owns the access-path lattice; this
module drives it and, crucially, runs loop bodies to a **fixpoint** so that an
output appended on one iteration is seen by an ``llm.invoke`` that textually
precedes the append (the canonical agent-loop shape, see ``analyze`` docstring).

Matching is name-based (mirroring Pysa's callee models); the known consequence —
import aliases such as ``import subprocess as sp`` are missed — is documented in
the README and avoided in the fixtures.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Set, Tuple

from ..labels import (
    Kind,
    Label,
    SourceMark,
    TaintSet,
    has_kind,
    join_to_ctl,
    marks_of,
)
from ..models.aliases import AliasResolver
from ..models.base import ModelRegistry, unreachable_nodes
from ..report import Finding
from .collections import ELEM, Env, aggregate_read, insert_element, reducer_merge

# Names treated as taint-transparent string transforms: ``str(x)``, ``x.strip()``,
# ``", ".join(parts)``, ``json.dumps(obj)`` ... — they carry their inputs' taint
# through unchanged (both kinds).  This keeps the data layer from dropping taint
# across the formatting that real agent code does to tool output.
_STRING_PROPAGATORS = frozenset({
    "str", "repr", "format", "format_map", "join", "strip", "lstrip", "rstrip",
    "lower", "upper", "title", "capitalize", "replace", "get", "dumps", "text",
    "json", "decode", "encode", "read", "getvalue", "to_string", "render",
    "strip_tags", "splitlines",
})

# Constructors of message wrappers / dispatch whose callee looks dynamic enough
# that a fetched value could *select* it (used by the dispatch heuristic).
_HIDE_CALLEES = frozenset({"hide", "by_ref", "byref", "reference", "redact", "seal"})

_COLLECTION_MUTATORS = frozenset({"append", "extend", "insert", "add", "update"})

# safety cap on loop unrolling iterations (fixpoint usually reached in 2)
_FIXPOINT_CAP = 8


def _const_key(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return f'["{node.value}"]'
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            return "[*]"  # an int index — treat as element access
    return None


class Analyzer:
    """Analyzes one module's AST and accumulates :class:`Finding` objects."""

    def __init__(self, source: str, filename: str, registry: ModelRegistry) -> None:
        self.source = source
        self.filename = filename
        self.reg = registry
        # binding/alias resolver (§6.4 fix): name -> {canonical callable}.
        self.aliases: AliasResolver = AliasResolver()
        self.local_tool_names: Set[str] = set()
        self.local_tool_types: Dict[str, Optional[str]] = {}
        self.findings: List[Finding] = []
        # LLM nodes encountered in the current scope, in textual order; attached
        # to every implicit finding as the control path it rode through.
        self.scope_exits: List[str] = []
        self._mark_serial = 0
        # ids of AST nodes that can never execute (§4.5(1)); filled per module.
        self._dead: Set[int] = set()
        # the function whose body is currently being analyzed (for guard
        # detection); None at module top level.
        self._cur_fn: Optional[ast.AST] = None
        # ---- cross-node reducer state (inter-procedural §4.3 rule 3) -------- #
        self.reducer_keys: Set[str] = set()        # state fields merged by a reducer
        self.state_channels: Dict[str, set] = {}   # reducer key -> accumulated taint
        self._in_reducer_pass = False              # are we in the cross-node pass?
        self._suppress = False                     # warmup: converge channels, don't record
        self._graph_exits: List[str] = []          # LLM nodes seen anywhere in the graph
        # ---- framework-managed dispatch (項目1) ---------------------------- #
        # name of a variable bound to a framework agent (create_react_agent(...)/
        # AgentExecutor(...)) -> {"spec": DispatchSpec, "candidates": [tool names],
        # "site": registration site}.  A later launch (.invoke/.stream) on that
        # name is the dispatch wall, whose candidate set is the registered tools.
        self.agent_registry: Dict[str, dict] = {}
        # id() of a factory call -> its extracted dispatch info, so the assignment
        # handler can bind the agent variable to the registration.
        self._pending_dispatch: Dict[int, dict] = {}
        # name -> [tool element identifiers] for ``tools = [..]`` style bindings.
        self._toollist_bindings: Dict[str, List[str]] = {}

    # ------------------------------------------------------------------ #
    # entry point
    # ------------------------------------------------------------------ #
    def analyze_module(self, tree: ast.Module) -> List[Finding]:
        # 0a. binding/alias map for the whole module: resolve aliased callees
        #     (completion = client.chat.completions.create; import x as y) before
        #     name-matching, so an aliased LLM node / sink is still recognized.
        self.aliases = AliasResolver.from_module(tree)
        # 0b. control-flow reachability fact for the whole module (§4.5(1)).
        self._dead = unreachable_nodes(tree)
        # 0c. tool-list variable bindings (項目1): real agents often bind the tool
        #     list to a variable first (``tools = [a, b]``; ``create_react_agent(
        #     llm, tools, prompt)``).  Record name -> [element identifiers] so a
        #     framework factory whose tools arg is a Name can still recover its
        #     candidate set.  Element identifiers also unwrap ``Tool(name=..,
        #     func=f)`` / ``Tool("n", f)`` to the wrapped callable's final name.
        self._toollist_bindings: Dict[str, List[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name) \
                    and isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                names = [n for n in (self._toollist_element(e) for e in node.value.elts) if n]
                if names:
                    self._toollist_bindings[node.targets[0].id] = names

        # 0d. instance-attribute agent bindings (項目1, cross-method, 1-hop): real
        #     agents commonly build the framework agent in ``__init__`` and launch it
        #     from another method:
        #         self.agent = create_react_agent(llm, tools=[...])   # __init__
        #         self.agent.invoke({...})                            # handle()
        #     Each method is analysed as its own scope, so a per-scope binding never
        #     crosses.  Record ``self.<attr>`` factory bindings module-wide (keyed by
        #     attribute name) so a launch on ``self.<attr>`` in any method resolves to
        #     the registration.  This only ADDS wall detection (recall-safe).
        self._self_agent_registry: Dict[str, dict] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Attribute) \
                    and isinstance(node.targets[0].value, ast.Name) \
                    and node.targets[0].value.id in ("self", "cls") \
                    and isinstance(node.value, ast.Call):
                dfac = self.reg.match_dispatch_factory(node.value, None)
                if dfac is not None:
                    cands = self._dispatch_candidates(node.value, dfac)
                    self._self_agent_registry[node.targets[0].attr] = {
                        "spec": dfac, "candidates": cands,
                        "site": f"{self.filename}:{self._site(node.value)}"}

        # 0e. 1-hop control-taint seeding (項目1, cross-method manual dispatch,
        #     recall-safe).  Real agents split the loop and the manual dispatch:
        #         def run(self): ... for call in resp...tool_calls: self._dispatch(call)
        #         def _dispatch(self, call): self.tool_map[call.name](call.args)  # wall
        #     The control mark born at the LLM call in run() never reaches the wall in
        #     _dispatch() under per-method analysis.  We conservatively seed a helper
        #     method's parameter with control taint when, inside a method that HAS an
        #     LLM exit, a call ``self._helper(v)`` passes an argument ``v`` that is
        #     derived from that method's control flow (a for-loop variable).  This
        #     only ADDS dispatch detection; it never removes or narrows a flow, and is
        #     limited to a single hop between methods of the same module.
        self._ctl_seed_params: Dict[str, set] = {}     # method name -> {param indices}
        for fn in [n for n in ast.walk(tree)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            if not self._fn_has_exit(fn):
                continue
            loopvars = {t.id for f in ast.walk(fn) if isinstance(f, ast.For)
                        for t in ast.walk(f.target) if isinstance(t, ast.Name)}
            for c in ast.walk(fn):
                if not isinstance(c, ast.Call):
                    continue
                f2 = c.func
                if isinstance(f2, ast.Attribute) and isinstance(f2.value, ast.Name) \
                        and f2.value.id in ("self", "cls"):
                    for idx, a in enumerate(c.args):
                        if isinstance(a, ast.Name) and a.id in loopvars:
                            self._ctl_seed_params.setdefault(f2.attr, set()).add(idx)

        # 1. discover local tools (decorator-identified) anywhere in the module.
        decorator_names = self.reg.tool_decorator_names()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if decorator_names & set(self._decorator_names(node)):
                    self.local_tool_names.add(node.name)
                    self.local_tool_types[node.name] = self._annotation_channel(
                        getattr(node, "returns", None))

        # 2. analyze the module top level as one scope (nested defs are opaque
        #    here and re-analyzed as their own scopes below).
        self._analyze_scope(tree.body)

        # 3. analyze every function/method body as its own scope with a fresh Env.
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._cur_fn = node
                self._analyze_scope(node.body, fn=node)
                self._cur_fn = None

        # 4. cross-node reducer pass (inter-procedural §4.3 rule 3): when the
        #    agent is built from *separate* node functions wired declaratively by
        #    a reducer (LangGraph add_messages / add_node), the tool output, the
        #    LLM node, and the dangerous sink can live in three different
        #    functions.  Thread a shared "state channel" between them and run to
        #    a fixpoint.  Gated on >=2 participating nodes so single-function
        #    apps keep their precise intra-procedural result.
        self.reducer_keys = self._collect_reducer_keys(tree)
        participants = self._collect_node_functions(tree)
        if self.reducer_keys and len(participants) >= 2:
            self._run_reducer_passes(participants)

        return self._dedup(self.findings)

    @staticmethod
    def _dedup(findings: List[Finding]) -> List[Finding]:
        seen = {}
        for f in findings:
            # keep the finding with the richest control trace for a given key.
            k = f.key()
            if k not in seen or len(f.exit_sites) > len(seen[k].exit_sites):
                seen[k] = f
        return list(seen.values())

    def _analyze_scope(self, body: List[ast.stmt], fn=None) -> None:
        self.scope_exits = []
        env = Env()
        # 1-hop control seeding: if this method receives an LLM-derived argument from
        # a sibling method (computed in prepass 0e), seed that parameter with a control
        # mark so a manual dispatch wall in this method is recorded.
        if fn is not None:
            idxs = getattr(self, "_ctl_seed_params", {}).get(fn.name)
            if idxs:
                args = list(getattr(fn.args, "args", []))
                # call sites pass positional args AFTER the implicit self/cls receiver,
                # so a call-site index i maps to definition parameter i+1 when the first
                # parameter is the receiver.
                recv_off = 1 if (args and args[0].arg in ("self", "cls")) else 0
                for i in idxs:
                    j = i + recv_off
                    if j < len(args):
                        seed = self._fresh_mark(
                            tool="<cross-method-llm>", framework="generic",
                            node=fn, out_type="object")
                        env.set(args[j].arg, {Label(Kind.CTL, frozenset({seed}))})
        self._run_stmts(body, env)

    def _fn_has_exit(self, fn) -> bool:
        """True if the function body contains an LLM exit call (an ExitSpec match)."""
        for n in ast.walk(fn):
            if isinstance(n, ast.Call):
                resolved = self.aliases.resolve_callee(n.func)
                if self.reg.match_exit(n, resolved) is not None:
                    return True
        return False

    # ------------------------------------------------------------------ #
    # source locations
    # ------------------------------------------------------------------ #
    def _site(self, node: ast.AST) -> str:
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        return f"{line}:{col}"

    def _src(self, node: ast.AST) -> str:
        seg = ast.get_source_segment(self.source, node)
        if seg is not None:
            return seg
        try:
            return ast.unparse(node)
        except Exception:  # pragma: no cover - very old python / odd nodes
            return "<expr>"

    def _decorator_names(self, fn) -> List[str]:
        out: List[str] = []
        for d in fn.decorator_list:
            n = d
            if isinstance(n, ast.Call):
                n = n.func
            if isinstance(n, ast.Attribute):
                out.append(n.attr)
            elif isinstance(n, ast.Name):
                out.append(n.id)
        return out

    def _annotation_channel(self, ann: Optional[ast.AST]) -> Optional[str]:
        """Map a return annotation to a constrained-decoding channel (§4.6).

        Used by the schema pruner (§4.5(2)): a tool declared to return ``bool``
        or ``Literal[...]`` is a narrow channel that cannot carry a free-form
        payload into a string sink.  Unknown / ``str`` annotations stay wide.
        """
        if ann is None:
            return None
        if isinstance(ann, ast.Name):
            return {
                "bool": "bool", "str": "string", "bytes": "string",
                "int": "int", "float": "number",
            }.get(ann.id)
        if isinstance(ann, ast.Subscript):
            head = ann.value
            name = head.id if isinstance(head, ast.Name) else getattr(head, "attr", "")
            if name == "Literal":
                return "enum"
        if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
            # string forward-ref annotation, e.g. -> "bool"
            return {"bool": "bool", "str": "string", "int": "int"}.get(ann.value)
        return None

    def _fresh_mark(self, tool: str, framework: str, node: ast.AST,
                    hidden: bool = False, out_type: Optional[str] = None,
                    role: Optional[str] = None) -> SourceMark:
        self._mark_serial += 1
        return SourceMark(
            tool=tool,
            framework=framework,
            site=f"{self.filename}:{self._site(node)}",
            hidden=hidden,
            out_type=out_type,
            role=role,
        )

    # ------------------------------------------------------------------ #
    # access paths
    # ------------------------------------------------------------------ #
    def _path_of(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._path_of(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Subscript):
            base = self._path_of(node.value)
            if base is None:
                return None
            key = _const_key(node.slice)
            if key == "[*]":
                return base + ELEM
            if key is not None:
                return base + key
            # non-constant subscript -> element access
            return base + ELEM
        return None

    # ------------------------------------------------------------------ #
    # expression evaluation  (node, env) -> TaintSet
    # ------------------------------------------------------------------ #
    def _eval(self, node: Optional[ast.AST], env: Env) -> TaintSet:
        if node is None:
            return set()
        m = getattr(self, "_eval_" + type(node).__name__, None)
        if m is None:
            # default: union of any taint reachable from child expressions, but
            # do NOT invent DATA; only carry what children already hold.
            acc: TaintSet = set()
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    acc |= self._eval(child, env)
            return acc
        return m(node, env)

    def _eval_Constant(self, node: ast.Constant, env: Env) -> TaintSet:
        return set()

    def _eval_Name(self, node: ast.Name, env: Env) -> TaintSet:
        return env.read_var(node.id)

    def _eval_Attribute(self, node: ast.Attribute, env: Env) -> TaintSet:
        # projection: attribute access carries the receiver's taint through, and
        # also picks up anything stored directly under the dotted path
        # (e.g. response.tool_calls inherits the CTL label put on `response`).
        out = self._eval(node.value, env)
        p = self._path_of(node)
        if p:
            out |= env.get(p)
            out |= env.get(p + ELEM)
        return out

    def _eval_Subscript(self, node: ast.Subscript, env: Env) -> TaintSet:
        out = self._eval(node.value, env)
        base = self._path_of(node.value)
        if base:
            out |= env.get(base + ELEM)
        p = self._path_of(node)
        if p:
            out |= env.get(p)
        return out

    def _eval_Starred(self, node: ast.Starred, env: Env) -> TaintSet:
        return self._eval(node.value, env)

    def _eval_Await(self, node: ast.Await, env: Env) -> TaintSet:
        return self._eval(node.value, env)

    def _eval_BinOp(self, node: ast.BinOp, env: Env) -> TaintSet:
        return self._eval(node.left, env) | self._eval(node.right, env)

    def _eval_BoolOp(self, node: ast.BoolOp, env: Env) -> TaintSet:
        out: TaintSet = set()
        for v in node.values:
            out |= self._eval(v, env)
        return out

    def _eval_UnaryOp(self, node: ast.UnaryOp, env: Env) -> TaintSet:
        return self._eval(node.operand, env)

    def _eval_Compare(self, node: ast.Compare, env: Env) -> TaintSet:
        # a comparison's *value* is a bool; it carries no string taint onward.
        return set()

    def _eval_IfExp(self, node: ast.IfExp, env: Env) -> TaintSet:
        return self._eval(node.body, env) | self._eval(node.orelse, env)

    def _eval_JoinedStr(self, node: ast.JoinedStr, env: Env) -> TaintSet:
        out: TaintSet = set()
        for v in node.values:
            out |= self._eval(v, env)
        return out

    def _eval_FormattedValue(self, node: ast.FormattedValue, env: Env) -> TaintSet:
        return self._eval(node.value, env)

    def _eval_List(self, node, env: Env) -> TaintSet:
        out: TaintSet = set()
        for e in node.elts:
            out |= self._eval(e, env)
        return out

    _eval_Tuple = _eval_List
    _eval_Set = _eval_List

    def _eval_Dict(self, node: ast.Dict, env: Env) -> TaintSet:
        out: TaintSet = set()
        for v in node.values:
            if v is not None:
                out |= self._eval(v, env)
        return out

    def _eval_ListComp(self, node, env: Env) -> TaintSet:
        out: TaintSet = set()
        for gen in node.generators:
            out |= self._eval(gen.iter, env)
        out |= self._eval(node.elt, env)
        return out

    _eval_SetComp = _eval_ListComp

    def _eval_GeneratorExp(self, node, env: Env) -> TaintSet:
        return self._eval_ListComp(node, env)

    def _eval_DictComp(self, node, env: Env) -> TaintSet:
        out: TaintSet = set()
        for gen in node.generators:
            out |= self._eval(gen.iter, env)
        out |= self._eval(node.value, env)
        return out

    def _eval_Lambda(self, node, env: Env) -> TaintSet:
        return set()

    def _eval_Call(self, node: ast.Call, env: Env) -> TaintSet:
        return self._eval_call(node, env)

    # ------------------------------------------------------------------ #
    # the heart: call evaluation
    # ------------------------------------------------------------------ #
    def _eval_call(self, call: ast.Call, env: Env) -> TaintSet:
        # (0) evaluate operands once.
        pos_taints: List[TaintSet] = [self._eval(a, env) for a in call.args]
        kw_taints: Dict[Optional[str], TaintSet] = {}
        for kw in call.keywords:
            kw_taints[kw.arg] = self._eval(kw.value, env)  # kw.arg is None for **kwargs
        recv_taint: TaintSet = set()
        if isinstance(call.func, ast.Attribute):
            recv_taint = self._eval(call.func.value, env)

        def all_input_taints() -> TaintSet:
            acc: TaintSet = set(recv_taint)
            for t in pos_taints:
                acc |= t
            for t in kw_taints.values():
                acc |= t
            return acc

        inputs = all_input_taints()
        any_ctl = has_kind(inputs, Kind.CTL)

        # binding-resolved canonical callee name(s) for this call site (§6.4).
        resolved = self.aliases.resolve_callee(call.func)

        # (1) SINK ---------------------------------------------------------- #
        sink = self.reg.match_sink(call, resolved)
        if sink is not None:
            self._record_sink(call, sink, pos_taints, kw_taints)
            return set()

        # (1.5) LOCAL TOOL invocation -------------------------------------- #
        # A decorated tool can be called directly (``read_webpage(...)``) or via
        # its runnable interface (``read_webpage.invoke(args)`` / ``.run(...)``).
        # The latter collides by *name* with the LLM exit ``.invoke``; we
        # disambiguate by the receiver being a known local tool, and must do so
        # BEFORE the exit check so ``llm.invoke`` (receiver not a tool) still
        # reads as the LLM node.
        tool_name = self._local_tool_call(call)
        if tool_name is not None:
            out_type = self.local_tool_types.get(tool_name) or "string"
            mark = self._fresh_mark(
                tool=tool_name, framework="local", node=call, out_type=out_type,
                role=self.reg.role_of(tool_name))
            out: TaintSet = {Label(Kind.DATA, frozenset({mark}))}
            if any_ctl:
                out |= {Label(Kind.CTL, marks_of(inputs, Kind.CTL))}
            return out

        # (1.6) FRAMEWORK DISPATCH FACTORY (項目1) ------------------------- #
        # e.g. g = create_react_agent(model, tools=[a, b, c]).  Record the
        # registered tool list as the candidate set; the assignment handler binds
        # the agent variable to it.  This does NOT penetrate the framework body —
        # it absorbs the known registration semantics declaratively.
        dfac = self.reg.match_dispatch_factory(call, resolved)
        if dfac is not None:
            cands = self._dispatch_candidates(call, dfac)
            self._pending_dispatch[id(call)] = {
                "spec": dfac, "candidates": cands,
                "site": f"{self.filename}:{self._site(call)}",
            }
            # the factory's return value is the agent object; no taint of its own.
            return set()

        # (1.7) FRAMEWORK DISPATCH LAUNCH (項目1, the wall) ----------------- #
        # e.g. g.invoke({"messages": [...]}) where g was bound to a factory above.
        # The framework selects+runs the chosen tool internally, so this launch is
        # the dispatch wall.  Its candidate set is the registered tools.  We record
        # it on the existing dispatch path, then fall through to the EXIT handling
        # so the launch still behaves as the LLM control-region start for taint.
        dl = self._dispatch_launch_info(call, resolved)
        if dl is not None:
            prompt_l: TaintSet = set()
            for i in dl["spec"].prompt_positional:
                if i < len(pos_taints):
                    prompt_l |= pos_taints[i]
            for name in dl["spec"].prompt_kwargs:
                prompt_l |= kw_taints.get(name, set())
            # The framework selects+runs tools internally (like OpenAI Agents'
            # Runner): attacker-influenceable tool outputs are fed to the model
            # inside the framework, so the wall is genuine whenever the agent has a
            # registered tool set, even if no user-code taint reaches .invoke.
            self._record_framework_dispatch(call, prompt_l, dl)

        # (2) EXIT (LLM node) ---------------------------------------------- #
        exit_spec = self.reg.match_exit(call, resolved)
        if exit_spec is not None:
            prompt: TaintSet = set()
            for i in exit_spec.prompt_positional:
                if i < len(pos_taints):
                    prompt |= pos_taints[i]
            for name in exit_spec.prompt_kwargs:
                prompt |= kw_taints.get(name, set())
            # if nothing matched positions/kwargs, fall back to any argument:
            if not prompt:
                prompt = inputs
            site = f"{self.filename}:{self._site(call)}"
            if site not in self.scope_exits:   # distinct LLM nodes, first-seen order
                self.scope_exits.append(site)
            if self._in_reducer_pass and site not in self._graph_exits:
                # the LLM node may be in a different node-function than the sink.
                self._graph_exits.append(site)
            # join-at-LLM (§4.4(2)): collapse all prompt marks into one CTL label.
            result = join_to_ctl(prompt)
            if exit_spec.taints_result and not result:
                # the runner executed its tools internally; its output reflects
                # attacker-influenceable tool outputs even with a clean prompt.
                seed = self._fresh_mark(
                    tool=f"<{exit_spec.framework}-tools>",
                    framework=exit_spec.framework, node=call, out_type="string")
                result = {Label(Kind.CTL, frozenset({seed}))}
            return result

        # (3) RESULT SOURCE (generic tool dispatch, e.g. session.call_tool) - #
        tool = self.reg.match_result_source(call, resolved)
        if tool is not None:
            mark = self._fresh_mark(
                tool="<tool-output>", framework=tool.framework, node=call,
                out_type=tool.output_type, role=tool.role or self.reg.role_of(self._callee_final_name(call)))
            out: TaintSet = {Label(Kind.DATA, frozenset({mark}))}
            if any_ctl:  # sticky control taint from arguments
                out |= {Label(Kind.CTL, marks_of(inputs, Kind.CTL))}
            return out

        # (3b) [removed] direct local-tool calls are handled by rule (1.5).
        callee_name = self._callee_final_name(call)

        # (4) ENTRY (tool-output wrapper, e.g. ToolMessage(content=...)) ---- #
        entry = self.reg.match_entry(call, resolved)
        if entry is not None:
            content: TaintSet = set()
            for i in entry.content_positional:
                if i < len(pos_taints):
                    content |= pos_taints[i]
            for name in entry.content_kwargs:
                content |= kw_taints.get(name, set())
            # provenance: prefer a concrete tool name already on the content,
            # and inherit its declared channel width so a narrow source (bool /
            # enum) is not silently re-widened to string by the wrapper (§4.6).
            prov = "<tool-output>"
            prov_type = entry.output_type
            prov_role = None
            for mk in marks_of(content, Kind.DATA):
                if not mk.tool.startswith("<"):
                    prov = mk.tool
                    prov_type = mk.out_type or entry.output_type
                    prov_role = mk.role
                    break
            if prov_role is None:
                prov_role = self.reg.role_of(prov)
            hidden = self._detect_hidden(call, entry)
            mark = self._fresh_mark(
                tool=prov, framework=entry.framework, node=call,
                hidden=hidden, out_type=prov_type, role=prov_role)
            return {Label(Kind.DATA, frozenset({mark}))} | content

        # (5) BRIDGE -------------------------------------------------------- #
        bridge = self.reg.match_bridge(call, resolved)
        if bridge is not None:
            if bridge.kind == "aggregate":
                # result.to_input_list(): aggregate-read the receiver collection.
                if isinstance(call.func, ast.Attribute):
                    return self._eval(call.func.value, env)
                return recv_taint
            if bridge.kind == "reducer":
                # add_messages(existing, new): join operands (§4.3 rule 3).
                return reducer_merge(pos_taints + list(kw_taints.values()))
            if bridge.kind in ("append", "extend"):
                return inputs

        # (6) DYNAMIC DISPATCH --------------------------------------------- #
        if self._is_dynamic_callee(call):
            if any_ctl:
                self._record_dispatch(call, inputs)
            mark = self._fresh_mark(
                tool="<dynamic>", framework="generic", node=call, out_type="object")
            out = {Label(Kind.DATA, frozenset({mark}))}
            if any_ctl:
                out |= {Label(Kind.CTL, marks_of(inputs, Kind.CTL))}
            return out

        # (7) STRING PROPAGATOR -------------------------------------------- #
        if callee_name in _STRING_PROPAGATORS:
            return inputs

        # (7.5) CONSTRUCTOR PROJECTION ------------------------------------- #
        # A PascalCase callee is, by convention, a class constructor.  Wrapping a
        # tainted value in an object (a message type, a dataclass, ``Path(...)``)
        # keeps the taint: the wrapper *carries* its arguments.  This is what
        # lets unmodelled message types (e.g. MCP ``SamplingMessage``,
        # ``TextContent``) on the path from tool output to the LLM node still
        # propagate, without enumerating every wrapper as an explicit entry.
        if callee_name and callee_name[:1].isupper() and callee_name.isidentifier():
            return inputs

        # (8) GENERIC ------------------------------------------------------- #
        # Precise data layer: a generic, unmodelled call does NOT propagate DATA
        # (no TITO assumed).  But control taint is *sticky* — once the reasoning
        # is attacker-influenced, wrapping/transforming it keeps the CTL mark.
        if any_ctl:
            return {Label(Kind.CTL, marks_of(inputs, Kind.CTL))}
        return set()

    # ------------------------------------------------------------------ #
    # call helpers
    # ------------------------------------------------------------------ #
    _TOOL_RUN_METHODS = frozenset({"invoke", "ainvoke", "run", "arun", "call", "acall"})

    def _local_tool_call(self, call: ast.Call) -> Optional[str]:
        """Return the tool name if ``call`` invokes a known local tool.

        Matches both the direct form ``read_webpage(...)`` and the LangChain
        runnable form ``read_webpage.invoke(args)`` / ``.run(...)``.  The runnable
        form shares the name ``invoke`` with the LLM exit, so we only accept it
        when the *receiver* is itself a known local tool.
        """
        fn = call.func
        if isinstance(fn, ast.Name) and fn.id in self.local_tool_names:
            return fn.id
        if isinstance(fn, ast.Attribute) and fn.attr in self._TOOL_RUN_METHODS:
            recv = fn.value
            if isinstance(recv, ast.Name) and recv.id in self.local_tool_names:
                return recv.id
        return None

    def _callee_final_name(self, call: ast.Call) -> Optional[str]:
        fn = call.func
        if isinstance(fn, ast.Name):
            return fn.id
        if isinstance(fn, ast.Attribute):
            return fn.attr
        return None

    def _is_dynamic_callee(self, call: ast.Call) -> bool:
        """A call whose concrete target is chosen at runtime (§4.5 dispatch).

        Three shapes, all of which mean the model's (attacker-influenceable)
        reasoning can *select which callable runs*:

        * ``registry[name](...)``        — subscripted callee;
        * ``get_function(name)(...)`` / ``getattr(obj, name)(...)`` /
          ``registry.get(name)(...)`` — *higher-order* dispatch: the callee is
          itself produced by a call, so the target is a runtime lookup.

        A static name-matcher cannot say which concrete tool (hence which sink)
        this reaches; we flag it as a dispatch (recorded only when the arguments
        are control-tainted) and leave the concrete sink to the inter-procedural
        (Pysa) layer.  A method call with a static name on a dynamic receiver
        (``obj[i].method()``) is *not* dynamic — its name is resolvable — so it
        falls through to the normal rules.
        """
        fn = call.func
        # registry[name](...) — subscripted callee chosen at runtime.
        if isinstance(fn, ast.Subscript):
            return True
        # higher-order dispatch: the callee is the result of another call, so the
        # concrete target is selected at runtime (registry getter / getattr / partial).
        if isinstance(fn, ast.Call):
            return True
        return False

    def _detect_hidden(self, call: ast.Call, entry) -> bool:
        # explicit hidden=True flag
        for kw in call.keywords:
            if kw.arg in ("hidden", "by_reference", "by_ref") and \
               isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        # content wrapped by a hide()/by_ref()/redact() helper
        for i in entry.content_positional:
            if i < len(call.args) and self._is_hide_call(call.args[i]):
                return True
        names = set(entry.content_kwargs)
        for kw in call.keywords:
            if kw.arg in names and self._is_hide_call(kw.value):
                return True
        return False

    def _is_hide_call(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            name = self._callee_final_name(node)
            return name in _HIDE_CALLEES
        return False

    # ------------------------------------------------------------------ #
    # finding recording
    # in-function guards that mitigate (but do not remove) a sink. Detected
    # conservatively: a call to one of these, textually before the sink, in the
    # same function. Recorded as a mitigating annotation — never used to prune.
    _GUARD_NAMES = frozenset({
        "_check_safety", "check_safety", "safety_check", "is_safe", "is_allowed",
        "is_permitted", "validate", "validate_args", "validate_command", "sanitize",
        "sanitise", "confirm", "confirm_action", "ask_confirmation",
        "require_confirmation", "guard", "allow", "allowed", "whitelist",
        "is_whitelisted", "verify", "assert_safe", "check_command", "approve",
    })

    def _detect_guard(self, call: ast.Call) -> Optional[str]:
        """Name of an in-function guard call preceding ``call``, or None."""
        fn = self._cur_fn
        if fn is None or getattr(call, "lineno", None) is None:
            return None
        sink_line = call.lineno
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and n is not call:
                ln = getattr(n, "lineno", None)
                if ln is not None and ln < sink_line:
                    name = self._callee_final_name(n)
                    if name and name.lower() in self._GUARD_NAMES:
                        return name
        return None

    # ------------------------------------------------------------------ #
    def _record_sink(self, call: ast.Call, sink, pos_taints, kw_taints) -> None:
        if self._suppress:
            return  # warmup pass: converge channels only, do not record.
        # find the dangerous argument and its taint.
        danger_node: Optional[ast.AST] = None
        danger_taint: TaintSet = set()
        for i in sink.dangerous_positional:
            if i < len(call.args):
                danger_node = call.args[i]
                danger_taint = pos_taints[i]
                if danger_taint:
                    break
        if not danger_taint:
            for name in sink.dangerous_kwargs:
                for kw in call.keywords:
                    if kw.arg == name:
                        danger_node = kw.value
                        danger_taint = kw_taints.get(name, set())
                        break
                if danger_taint:
                    break
        # also consider **kwargs splat (conservative)
        if not danger_taint and None in kw_taints and kw_taints[None]:
            danger_taint = kw_taints[None]

        if not danger_taint:
            return  # sink reached, but argument is clean — no finding.

        ctl = has_kind(danger_taint, Kind.CTL)
        kind = "implicit" if ctl else "explicit"
        wanted = Kind.CTL if ctl else Kind.DATA
        marks = marks_of(danger_taint, wanted)
        if not marks:
            marks = marks_of(danger_taint)

        arg_expr = self._src(danger_node) if danger_node is not None else "<arg>"
        exits = self._graph_exits if self._in_reducer_pass else self.scope_exits
        self.findings.append(Finding(
            kind=kind,
            sink_name=sink.name,
            sink_category=sink.category,
            severity=sink.severity,
            sink_site=self._site(call),
            arg_expr=arg_expr,
            param_type=sink.param_type,
            source_marks=tuple(sorted(marks, key=lambda m: (m.tool, m.site))),
            exit_sites=tuple(exits) if ctl else (),
            file=self.filename,
            reachable=id(call) not in self._dead,
            guard=self._detect_guard(call),
        ))

    def _record_dispatch(self, call: ast.Call, inputs: TaintSet) -> None:
        if self._suppress:
            return
        marks = marks_of(inputs, Kind.CTL) or marks_of(inputs)
        exits = self._graph_exits if self._in_reducer_pass else self.scope_exits
        self.findings.append(Finding(
            kind="dispatch",
            sink_name=self._src(call.func),
            sink_category="dispatch",
            severity="high",
            sink_site=self._site(call),
            arg_expr=self._src(call),
            param_type="object",
            source_marks=tuple(sorted(marks, key=lambda m: (m.tool, m.site))),
            exit_sites=tuple(exits),
            file=self.filename,
            reachable=id(call) not in self._dead,
            guard=self._detect_guard(call),
        ))

    # ------------------------------------------------------------------ #
    # framework-managed dispatch (項目1)
    # ------------------------------------------------------------------ #
    def _dispatch_candidates(self, call: ast.Call, spec) -> List[str]:
        """Extract the registered tool names from a factory call's tool-list arg.

        Looks at the ``tools=`` keyword (or a declared positional index) and reads
        the names of the elements of the list/tuple literal.  Names are the local
        tool function names (``[fetch_url, run_cmd]``) or call expressions; we keep
        the final identifier so they can be matched against the sink tool set.

        Real agents frequently bind the tool list to a variable first
        (``tools = [..]``; ``create_react_agent(llm, tools, prompt)``); when the
        argument is a bare Name we resolve it via the module-level tool-list
        bindings collected in :meth:`analyze_module`.
        """
        arg_node = None
        for kw in call.keywords:
            if kw.arg in spec.tools_kwarg:
                arg_node = kw.value
                break
        if arg_node is None:
            for i in spec.tools_positional:
                if i < len(call.args):
                    arg_node = call.args[i]
                    break
        if arg_node is None:
            return []
        if isinstance(arg_node, ast.Name):
            # a variable bound to a tool-list literal (resolved in analyze_module).
            return list(getattr(self, "_toollist_bindings", {}).get(arg_node.id, []))
        names: List[str] = []
        if isinstance(arg_node, (ast.List, ast.Tuple, ast.Set)):
            for e in arg_node.elts:
                n = self._toollist_element(e)
                if n:
                    names.append(n)
        return names

    @staticmethod
    def _toollist_element(node: ast.AST) -> Optional[str]:
        """Identifier for one tool-list element.

        Unwraps the common ``Tool(name=.., func=f)`` / ``Tool("n", f)`` and
        ``StructuredTool.from_function(func=f)`` wrappers to the wrapped callable's
        final name, so a tool registered via a wrapper is still matchable against
        the classifier's sink tools (which key on the function name).  Falls back
        to the element's own final identifier.
        """
        if isinstance(node, ast.Call):
            fin = Analyzer._element_name(node.func) or ""
            if fin in ("Tool", "StructuredTool", "from_function"):
                # prefer the func= kwarg, else a positional callable argument.
                for kw in node.keywords:
                    if kw.arg == "func":
                        n = Analyzer._element_name(kw.value)
                        if n:
                            return n
                for a in node.args:
                    if isinstance(a, (ast.Name, ast.Attribute)):
                        n = Analyzer._element_name(a)
                        if n:
                            return n
            return Analyzer._element_name(node.func)
        return Analyzer._element_name(node)

    @staticmethod
    def _element_name(node: ast.AST) -> Optional[str]:
        """Final identifier of a tool-list element (Name, Attribute, or Call)."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Call):
            return Analyzer._element_name(node.func)
        return None

    def _dispatch_launch_info(self, call: ast.Call, resolved) -> Optional[dict]:
        """If ``call`` is a launch (.invoke/.stream/...) on a bound agent var,
        return the registration info recorded for that variable."""
        spec = self.reg.match_dispatch_launch(call, resolved)
        if spec is None:
            return None
        fn = call.func
        if not isinstance(fn, ast.Attribute):
            return None
        # case 1: launch on a local Name bound to a framework agent (e.g. agent.invoke).
        if isinstance(fn.value, ast.Name):
            info = self.agent_registry.get(fn.value.id)
            if info is not None:
                return info
            # not locally bound: fall through to the AgentDojo presumption below.
        # case 2: launch on an instance attribute (e.g. self.agent.invoke), bound by a
        # factory call in __init__/elsewhere — resolved via the module-scoped registry
        # so it crosses method boundaries (項目1, 1-hop cross-method, recall-safe).
        elif isinstance(fn.value, ast.Attribute) and isinstance(fn.value.value, ast.Name) \
                and fn.value.value.id in ("self", "cls"):
            info = getattr(self, "_self_agent_registry", {}).get(fn.value.attr)
            if info is not None:
                return info
            # fall through to the AgentDojo presumption below.
        # case 3: AgentDojo runtime presumption (項目1, declarative).  run_function is
        # AgentDojo's FIXED dispatcher; its receiver (the runtime) is typically created
        # elsewhere and passed in as a parameter, so it is not locally bound to a
        # factory.  When the matched spec is the AgentDojo runtime, presume the wall
        # regardless of where the receiver was bound — the candidate set is supplied
        # out-of-band by the (declared) domain sinks, so an empty candidate set here is
        # intentional and resolution falls back to the model's sinks (recall-first).
        if getattr(spec, "framework", None) == "agentdojo":
            return {"spec": spec, "candidates": [], "agentdojo_presumed": True}
        return None

    def _record_framework_dispatch(self, call: ast.Call, prompt: TaintSet, info: dict) -> None:
        if self._suppress:
            return
        cands = info.get("candidates") or []
        if not cands and not info.get("agentdojo_presumed"):
            return  # no registered tool set -> nothing to resolve against
        marks = marks_of(prompt, Kind.CTL) or marks_of(prompt)
        if not marks:
            # the framework ran its tools internally; seed a control mark standing
            # for the attacker-influenceable tool outputs fed to the model inside
            # the framework (mirrors ExitSpec.taints_result for runner-style APIs).
            seed = self._fresh_mark(
                tool=f"<{info['spec'].framework}-tools>",
                framework=info["spec"].framework, node=call, out_type="string")
            marks = frozenset({seed})
        exits = self._graph_exits if self._in_reducer_pass else self.scope_exits
        # the launch site is itself the LLM control-region start for this agent.
        launch_site = f"{self.filename}:{self._site(call)}"
        exits = list(exits) + ([launch_site] if launch_site not in exits else [])
        self.findings.append(Finding(
            kind="dispatch",
            sink_name=self._src(call.func),       # e.g. "agent.invoke"
            sink_category="dispatch",
            severity="high",
            sink_site=self._site(call),
            arg_expr=self._src(call),
            param_type="object",
            source_marks=tuple(sorted(marks, key=lambda m: (m.tool, m.site))),
            exit_sites=tuple(exits),
            file=self.filename,
            reachable=id(call) not in self._dead,
            guard=self._detect_guard(call),
            framework_candidates=tuple(cands),     # 項目1: registered tool set
        ))

    # ------------------------------------------------------------------ #
    # statement handling
    # ------------------------------------------------------------------ #
    def _run_stmts(self, body: List[ast.stmt], env: Env) -> None:
        for stmt in body:
            self._run_stmt(stmt, env)

    def _run_stmt(self, stmt: ast.stmt, env: Env) -> None:
        m = getattr(self, "_stmt_" + type(stmt).__name__, None)
        if m is not None:
            m(stmt, env)
        else:
            # default: evaluate any contained expressions for their side effects
            # (sink/exit/dispatch recording happens inside _eval_call).
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self._eval(child, env)

    def _assign_to_target(self, target: ast.AST, value_node: Optional[ast.AST],
                          rhs_taint: TaintSet, env: Env) -> None:
        if isinstance(target, ast.Name):
            env.set(target.id, rhs_taint)
            # 項目1: if the RHS is a framework dispatch factory call, bind this
            # variable to the registration so a later .invoke/.stream on it is
            # recognized as the dispatch wall with the registered candidate set.
            if isinstance(value_node, ast.Call) and id(value_node) in self._pending_dispatch:
                self.agent_registry[target.id] = self._pending_dispatch[id(value_node)]
            # if RHS is a literal collection, also record element taint so a later
            # aggregate read / append chain sees the elements.
            if isinstance(value_node, (ast.List, ast.Tuple, ast.Set)):
                elt: TaintSet = set()
                for e in value_node.elts:
                    elt |= self._eval(e, env)
                env.set(target.id + ELEM, elt)
            else:
                env.set(target.id + ELEM, set())
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            p = self._path_of(target)
            if p:
                env.set(p, rhs_taint)
        elif isinstance(target, (ast.Tuple, ast.List)):
            # unpacking: conservatively project the whole RHS taint to each name.
            for elt in target.elts:
                if isinstance(elt, ast.Starred):
                    elt = elt.value
                self._assign_to_target(elt, None, rhs_taint, env)

    def _stmt_Assign(self, stmt: ast.Assign, env: Env) -> None:
        rhs = self._eval(stmt.value, env)
        for tgt in stmt.targets:
            self._assign_to_target(tgt, stmt.value, rhs, env)

    def _stmt_AnnAssign(self, stmt: ast.AnnAssign, env: Env) -> None:
        if stmt.value is not None:
            rhs = self._eval(stmt.value, env)
            self._assign_to_target(stmt.target, stmt.value, rhs, env)

    def _stmt_AugAssign(self, stmt: ast.AugAssign, env: Env) -> None:
        # x += y : extend semantics for collections + keep own taint.
        rhs = self._eval(stmt.value, env)
        p = self._path_of(stmt.target)
        if p is not None:
            insert_element(env, p, rhs)   # rule 1: elements of y become elements of x
            env.add(p, rhs)               # also keep direct taint (string +=)

    def _stmt_Expr(self, stmt: ast.Expr, env: Env) -> None:
        val = stmt.value
        if isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) \
                and val.func.attr in _COLLECTION_MUTATORS:
            recv = val.func.value
            recv_path = self._path_of(recv)
            # evaluate args (records nested sinks/exits) and gather their taint.
            arg_taint: TaintSet = set()
            for a in val.args:
                arg_taint |= self._eval(a, env)
            if recv_path is not None and arg_taint:
                if val.func.attr == "extend":
                    # extend(xs): xs is a collection — push its element taint.
                    insert_element(env, recv_path, arg_taint)
                else:
                    # append/insert/add(x): x is one element.
                    insert_element(env, recv_path, arg_taint)
            return
        # ordinary expression statement: evaluate for side effects.
        self._eval(val, env)

    def _stmt_Return(self, stmt: ast.Return, env: Env) -> None:
        if stmt.value is not None:
            self._eval(stmt.value, env)
            # cross-node reducer merge (§4.3 rule 3): returning ``{key: [msg]}``
            # from a node merges the new-message taint into the shared channel.
            if self._in_reducer_pass and isinstance(stmt.value, ast.Dict):
                for k_node, v_node in zip(stmt.value.keys, stmt.value.values):
                    if (isinstance(k_node, ast.Constant)
                            and k_node.value in self.reducer_keys
                            and v_node is not None):
                        self.state_channels.setdefault(k_node.value, set()).update(
                            self._eval(v_node, env))

    def _stmt_If(self, stmt: ast.If, env: Env) -> None:
        self._eval(stmt.test, env)
        branch = env.copy()
        self._run_stmts(stmt.body, branch)
        orelse = env.copy()
        self._run_stmts(stmt.orelse, orelse)
        env.join_in(branch)
        env.join_in(orelse)

    def _loop_fixpoint(self, body: List[ast.stmt], env: Env,
                       rebind=None) -> None:
        """Run a loop body to a fixpoint (§4.3 loop handling).

        Static analysis cannot know the iteration count, so we abstract
        *reachability regardless of turn*: an output appended on one pass must be
        visible to an ``llm.invoke`` that textually precedes the append.  We
        therefore iterate the body, merging effects back, until the environment
        signature stops growing (or a safety cap is hit).  ``findings`` recorded
        on a throwaway pass are deduplicated later by ``Finding.key``.
        """
        for _ in range(_FIXPOINT_CAP):
            before = env.signature()
            if rebind is not None:
                rebind(env)
            self._run_stmts(body, env)
            if env.signature() == before:
                break

    def _stmt_For(self, stmt, env: Env) -> None:
        iter_taint = self._eval(stmt.iter, env)

        def rebind(e: Env) -> None:
            self._assign_to_target(stmt.target, None, iter_taint, e)

        self._loop_fixpoint(stmt.body, env, rebind=rebind)
        self._run_stmts(stmt.orelse, env)

    _stmt_AsyncFor = _stmt_For

    def _stmt_While(self, stmt: ast.While, env: Env) -> None:
        self._eval(stmt.test, env)
        self._loop_fixpoint(stmt.body, env)
        self._run_stmts(stmt.orelse, env)

    def _stmt_With(self, stmt, env: Env) -> None:
        for item in stmt.items:
            ctx_taint = self._eval(item.context_expr, env)
            if item.optional_vars is not None:
                self._assign_to_target(item.optional_vars, item.context_expr,
                                       ctx_taint, env)
        self._run_stmts(stmt.body, env)

    _stmt_AsyncWith = _stmt_With

    def _stmt_Try(self, stmt: ast.Try, env: Env) -> None:
        # monotone approximation: run all sections in sequence on the same env.
        self._run_stmts(stmt.body, env)
        for handler in stmt.handlers:
            self._run_stmts(handler.body, env)
        self._run_stmts(stmt.orelse, env)
        self._run_stmts(stmt.finalbody, env)

    if hasattr(ast, "TryStar"):  # py3.11+
        _stmt_TryStar = _stmt_Try

    # nested defs are analyzed as their own scopes by analyze_module.
    def _stmt_FunctionDef(self, stmt, env: Env) -> None:
        return

    _stmt_AsyncFunctionDef = _stmt_FunctionDef

    def _stmt_ClassDef(self, stmt, env: Env) -> None:
        return

    # ------------------------------------------------------------------ #
    # cross-node reducer (inter-procedural §4.3 rule 3)
    # ------------------------------------------------------------------ #
    _REDUCER_NAMES = frozenset({"add_messages", "add"})

    def _collect_reducer_keys(self, tree: ast.AST) -> Set[str]:
        """Find the state fields that a reducer accumulates across nodes.

        Three signals: a modelled reducer ``BridgeSpec`` (its ``reducer_key``); a
        ``MessagesState`` base class (its ``messages`` field); and a TypedDict
        field annotated ``Annotated[..., add_messages]``.
        """
        keys: Set[str] = set()
        for b in self.reg.bridges:
            if b.kind == "reducer" and b.reducer_key:
                keys.add(b.reducer_key)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for base in node.bases:
                bn = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
                if bn == "MessagesState":
                    keys.add("messages")
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    ann = stmt.annotation
                    if isinstance(ann, ast.Subscript):
                        head = ann.value
                        hn = head.id if isinstance(head, ast.Name) else getattr(head, "attr", "")
                        if hn == "Annotated":
                            sl = ann.slice
                            elts = sl.elts if isinstance(sl, ast.Tuple) else [sl]
                            for e in elts:
                                en = e.id if isinstance(e, ast.Name) else getattr(e, "attr", "")
                                if en in self._REDUCER_NAMES:
                                    keys.add(stmt.target.id)
        return keys

    def _collect_node_functions(self, tree: ast.AST) -> List[ast.AST]:
        """Functions that participate in the graph's shared state.

        A participant is either referenced by an ``add_node(...)`` call or
        syntactically touches a reducer-keyed state field.  Order is preserved
        (document order) and duplicates removed.
        """
        node_fn_names: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                is_add_node = (isinstance(fn, ast.Attribute) and fn.attr == "add_node") \
                    or (isinstance(fn, ast.Name) and fn.id == "add_node")
                if is_add_node:
                    for a in node.args:
                        if isinstance(a, ast.Name):
                            node_fn_names.add(a.id)

        participants: List[ast.AST] = []
        seen: Set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if id(node) in seen:
                    continue
                if node.name in node_fn_names or self._touches_channel(node):
                    participants.append(node)
                    seen.add(id(node))
        return participants

    def _touches_channel(self, fn: ast.AST) -> bool:
        if not self.reducer_keys:
            return False
        for node in ast.walk(fn):
            # state["messages"] ...
            if isinstance(node, ast.Subscript):
                k = node.slice
                if isinstance(k, ast.Constant) and k.value in self.reducer_keys:
                    return True
            # state.messages ...
            if isinstance(node, ast.Attribute) and node.attr in self.reducer_keys:
                return True
            # return {"messages": [...]}
            if isinstance(node, ast.Dict):
                for kk in node.keys:
                    if isinstance(kk, ast.Constant) and kk.value in self.reducer_keys:
                        return True
        return False

    def _seed_state_env(self, fn: ast.AST) -> Env:
        """A fresh Env in which the node's state parameter already carries the
        accumulated channel taint (so a read of ``state[key]`` sees what other
        nodes have merged)."""
        env = Env()
        params = list(getattr(fn.args, "posonlyargs", []) or []) + list(fn.args.args)
        pname = params[0].arg if params else None
        if pname is None:
            return env
        for key in self.reducer_keys:
            taint = self.state_channels.get(key)
            if not taint:
                continue
            for path in (
                f'{pname}["{key}"]', f'{pname}["{key}"]' + ELEM,
                f'{pname}.{key}', f'{pname}.{key}' + ELEM,
            ):
                env.set(path, set(taint))
        return env

    def _run_reducer_passes(self, participants: List[ast.AST]) -> None:
        """Thread the shared state channel between node functions and run to a
        fixpoint, then record findings against the converged channel.

        A *warmup* loop converges ``state_channels`` (and gathers the graph's LLM
        nodes) with finding-recording suppressed, so transient under-converged
        states — e.g. the model node analyzed before the tool node has merged its
        output — do not emit spurious findings.  A single final pass then records
        against the stable channel.  Convergence is guaranteed: ``add_messages``
        only accumulates and source marks are site-identified (equal across
        passes), so the channel taint sets are monotone and bounded.
        """
        self.state_channels = {k: set() for k in self.reducer_keys}
        self._graph_exits = []
        self._in_reducer_pass = True
        try:
            self._suppress = True
            for _ in range(_FIXPOINT_CAP):
                before = {k: frozenset(v) for k, v in self.state_channels.items()}
                for fn in participants:
                    self.scope_exits = []
                    self._run_stmts(fn.body, self._seed_state_env(fn))
                after = {k: frozenset(v) for k, v in self.state_channels.items()}
                if after == before:
                    break
            self._suppress = False
            for fn in participants:
                self.scope_exits = []
                self._cur_fn = fn
                self._run_stmts(fn.body, self._seed_state_env(fn))
                self._cur_fn = None
        finally:
            self._in_reducer_pass = False
            self._suppress = False


def analyze_source(source: str, filename: str, registry: ModelRegistry) -> List[Finding]:
    """Parse ``source`` and return raw (pre-pruning) findings.

    The canonical agent loop this engine is built to see::

        while True:
            response = llm.invoke(messages)          # (A) LLM node, textually first
            for tc in response.tool_calls:
                if tc["name"] == "run_cmd":
                    out = subprocess.run(tc["args"]["cmd"])   # (C) sink
            messages.append(ToolMessage(content=fetch()))     # (B) append, textually last

    On pass 1 ``messages`` is clean, so (A) yields no CTL and (C) is silent.  (B)
    then taints ``messages[*]``.  On pass 2 the join at (A) lifts that to a CTL
    label on ``response``; ``response.tool_calls[i]["args"]["cmd"]`` inherits it;
    (C) fires as an implicit cross-tool flow.  Running the loop body to a
    fixpoint is what makes this visible without execution.
    """
    tree = ast.parse(source, filename=filename)
    analyzer = Analyzer(source=source, filename=filename, registry=registry)
    return analyzer.analyze_module(tree)
