"""Dynamic-dispatch wall resolution (lowering pass) — TaintP2X preprocessing.

External preprocessing only: never modifies the base analyzer (TaintP2X / Pysa).
For each dynamic-dispatch *wall* — a call site whose callee is a runtime-selected
value, so the static call graph has no edge across it — this pass inserts an
``if False:`` block of direct calls to every *resolved* target, threading the
wall's (tainted) argument(s) into each target's parameters. The block never
executes (``if False``); it only hands Pysa's static data flow the edges it
lacks, so taint can cross the wall to the dangerous sink.

Generalised from the AutoGPT-specific ``@command`` version to a language-level
idiom taxonomy, while staying byte-for-byte backward compatible with the legacy
spec ``{"tool_decorator": "command", "dispatch_resolver_hint": "command"}`` so
the existing AutoGPT M2 reproduction (0 -> 7 issues) is unchanged.

Wall idioms (a Call whose callee is a runtime-selected value):
  (S) subscript-registry     REG[key](...)              detect_subscript
  (G) getattr / reflective   getattr(obj, name)(...)    detect_getattr
  (H) higher-order / factory, via a local bound to (S)/(G)/Call-result:
        f = REG[key];      f(...)
        f = getattr(o, n); f(...)
        f = resolve(name); f(...)                        detect_higher_order
The AutoGPT idiom ``command = self._get_command(name); command(**args)`` is the
(H)+Call case; a non-empty ``resolver_hints`` filters (H) to resolver calls whose
dotted name contains a hint (this is the legacy behaviour).

Resolved target set (candidates), any combination of:
  * functions/methods decorated with one of ``tool_decorators``
    (``@command``, ``@tool``, ``@register(...)`` ...);
  * (precision, planned) members of a registry dict/list literal the wall reads;
  * every def under the candidate root (``scan_all_callables`` — most
    over-approximate, recall-first fallback for unknown projects).

PRECISION NOTE (recall-first discipline). (S) and (G) are structurally
unambiguous dispatch sites. (H) with an EMPTY ``resolver_hints`` is the
maximally over-approximate end: it flags every ``f = g(...); f(...)`` and, if
the candidate set is global, connects each such wall to ALL candidates. The
intended precision lever is candidate narrowing to the registry membership the
wall actually reads (``targets = candidates ∩ registry``), mirroring
``ctaudit/analysis/dispatch_resolution.py``; that narrowing is the next step to
harvest from the native engine and is NOT yet applied here. Until then, use
``resolver_hints`` / ``registry_vars`` (or per-target specs) to keep (H) tight.
"""
from __future__ import annotations

import ast
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# Spec
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class LoweringSpec:
    # candidate (registered-tool) recovery
    tool_decorators: Tuple[str, ...] = ()        # (1) @tool / @command / @mcp.tool()
    register_methods: Tuple[str, ...] = ()       # (2) x.register(fn) / add_tool(fn)
    tool_list_names: Tuple[str, ...] = ()        # (3) tools=[...] / TOOLS = [...]
    tool_wrappers: Tuple[str, ...] = ()          # (4) Tool(func=fn) / StructuredTool.from_function(fn)
    wrapper_func_kwargs: Tuple[str, ...] = ("func", "fn", "function", "coroutine", "callback")
    registry_vars: Tuple[str, ...] = ()          # (5) TOOLS = {"a": fn_a} (also membership narrowing)
    scan_all_callables: bool = False
    candidate_import_module: str = ""            # inject `from <mod> import <cands>` at the wall (library-internal walls)
    insert_before: bool = False                  # place block BEFORE the wall line (reachable when wall is `return f(...)`)
    # wall detection
    resolver_hints: Tuple[str, ...] = ()         # (H) only flag resolver calls whose
                                                 # dotted name contains a hint; () = any
    detect_subscript: bool = True
    detect_getattr: bool = True
    detect_higher_order: bool = True
    wall_param_names: Tuple[str, ...] = ()       # flag p(...) where p is a callable param (e.g. "fn")
    wall_attr_names: Tuple[str, ...] = ()        # flag o.a(...) where a holds a callable (e.g. "fn","func")
    _legacy: bool = False                        # internal: reproduce original exactly


_NEW_KEYS = {
    "tool_decorators", "register_methods", "tool_list_names", "tool_wrappers",
    "wrapper_func_kwargs", "registry_vars", "scan_all_callables", "candidate_import_module", "insert_before",
    "resolver_hints", "detect_subscript", "detect_getattr", "detect_higher_order",
    "wall_param_names", "wall_attr_names",
}


def _coerce_spec(spec) -> LoweringSpec:
    """Accept a LoweringSpec, or a dict with legacy and/or new keys.

    A dict carrying ONLY legacy keys (``tool_decorator`` / ``dispatch_resolver_hint``)
    selects legacy mode, which reproduces the original pass exactly.
    """
    if isinstance(spec, LoweringSpec):
        return spec
    spec = dict(spec or {})
    has_new = bool(_NEW_KEYS & spec.keys())

    decs = tuple(spec.get("tool_decorators", ()))
    if "tool_decorator" in spec:                 # legacy singular
        decs = decs + (spec["tool_decorator"],)

    hints = tuple(spec.get("resolver_hints", ()))
    if "dispatch_resolver_hint" in spec:         # legacy singular
        hints = hints + (spec["dispatch_resolver_hint"],)

    legacy = (not has_new) and (
        "dispatch_resolver_hint" in spec or "tool_decorator" in spec
    )
    return LoweringSpec(
        tool_decorators=decs,
        register_methods=tuple(spec.get("register_methods", ())),
        tool_list_names=tuple(spec.get("tool_list_names", ())),
        tool_wrappers=tuple(spec.get("tool_wrappers", ())),
        wrapper_func_kwargs=tuple(spec.get("wrapper_func_kwargs",
                                           ("func", "fn", "function", "coroutine", "callback"))),
        registry_vars=tuple(spec.get("registry_vars", ())),
        scan_all_callables=bool(spec.get("scan_all_callables", False)),
        candidate_import_module=str(spec.get("candidate_import_module", "") or ""),
        insert_before=bool(spec.get("insert_before", False)),
        resolver_hints=hints,
        detect_subscript=bool(spec.get("detect_subscript", True)),
        detect_getattr=bool(spec.get("detect_getattr", True)),
        detect_higher_order=bool(spec.get("detect_higher_order", True)),
        wall_param_names=tuple(spec.get("wall_param_names", ())),
        wall_attr_names=tuple(spec.get("wall_attr_names", ())),
        _legacy=legacy,
    )


# --------------------------------------------------------------------------- #
# AST helpers
# --------------------------------------------------------------------------- #
def _dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _dec_last(dec) -> str:
    if isinstance(dec, ast.Call):
        fn = dec.func
        return fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Name):
        return dec.id
    return ""


def _params_of(fn) -> List[str]:
    return [a.arg for a in fn.args.args if a.arg != "self"]


def _is_subscript(node) -> bool:
    return isinstance(node, ast.Subscript)


def _is_getattr_call(node) -> bool:
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr")


def _hint_ok(call, hints) -> bool:
    if not hints:
        return True
    name = (_dotted(call.func) or "").lower()
    return any(h.lower() in name for h in hints)


def _scope_bodies(tree):
    """Yield the statement list of each binding scope: the module and every def."""
    yield getattr(tree, "body", [])
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield n.body


def _own_stmt_walk(stmts):
    """Yield nodes inside ``stmts`` (and their expressions), NOT descending into
    nested def/class bodies — those are separate scopes handled on their own."""
    stack = list(stmts)
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(n))


# --------------------------------------------------------------------------- #
# Candidate (registered-tool) recovery
# --------------------------------------------------------------------------- #
def _iter_py(src_root):
    for root, _, files in os.walk(src_root):
        for f in files:
            if f.endswith(".py"):
                p = os.path.join(root, f)
                try:
                    yield p, ast.parse(open(p, encoding="utf-8", errors="replace").read())
                except Exception:
                    continue


def _index_defs(src_root) -> Dict[str, List[Tuple[Optional[str], str, List[str]]]]:
    """short callable name -> list of (class_or_None, name, params). Codebase-wide."""
    by_short: Dict[str, List[Tuple[Optional[str], str, List[str]]]] = defaultdict(list)
    for _p, tree in _iter_py(src_root):
        for cls in ast.walk(tree):
            if isinstance(cls, ast.ClassDef):
                for m in cls.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        by_short[m.name].append((cls.name, m.name, _params_of(m)))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                by_short[node.name].append((None, node.name, _params_of(node)))
    return by_short


def _callable_ref(node, sp: LoweringSpec) -> Optional[str]:
    """Short name of the callable referenced by ``node``, unwrapping tool wrappers."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr                       # self.execute / mod.run -> last component
    if isinstance(node, ast.Call):
        fn = node.func
        names = set()
        if isinstance(fn, ast.Name):
            names.add(fn.id)
        elif isinstance(fn, ast.Attribute):
            names.add(fn.attr)                 # ...Tool(func=fn)
            root = fn.value                    # StructuredTool.from_function(fn) -> StructuredTool
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                names.add(root.id)
        if names & set(sp.tool_wrappers):      # (4) wrapper / factory wrapping a callable
            for kw in node.keywords:
                if kw.arg in sp.wrapper_func_kwargs:
                    return _callable_ref(kw.value, sp)
            if node.args:
                return _callable_ref(node.args[0], sp)
    return None


def _registration_refs(src_root, sp: LoweringSpec):
    """(2)(3)(5) short-name references registered as tools (outside decorators)."""
    refs = set()
    for _p, tree in _iter_py(src_root):
        for node in ast.walk(tree):
            # (2) register method call: x.register(fn) / x.add_tool(func=fn)
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in sp.register_methods):
                target = None
                for kw in node.keywords:
                    if kw.arg in sp.wrapper_func_kwargs:
                        target = kw.value
                if target is None and node.args:
                    target = node.args[0]
                if target is not None:
                    r = _callable_ref(target, sp)
                    if r:
                        refs.add(r)
            # (3) tool list as a kwarg: f(..., tools=[a, b, Tool(func=c)])
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg in sp.tool_list_names and isinstance(kw.value, (ast.List, ast.Tuple)):
                        for el in kw.value.elts:
                            r = _callable_ref(el, sp)
                            if r:
                                refs.add(r)
            # (3)/(5) assignment: TOOLS = [...]  or  TOOLS = {"a": fn_a, ...}
            if isinstance(node, ast.Assign):
                names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                if any(n in sp.tool_list_names for n in names) and isinstance(node.value, (ast.List, ast.Tuple)):
                    for el in node.value.elts:
                        r = _callable_ref(el, sp)
                        if r:
                            refs.add(r)
                if any(n in sp.registry_vars for n in names) and isinstance(node.value, ast.Dict):
                    for v in node.value.values:
                        r = _callable_ref(v, sp)
                        if r:
                            refs.add(r)
    return refs


def collect_candidates(src_root, spec) -> List[Tuple[Optional[str], str, List[str]]]:
    """Recover the registered-tool set R as ``(class_or_None, name, param_names)``.

    Legacy mode: decorator-marked *class methods* only (original behaviour).
    General mode: decorators + module functions, PLUS register-calls, tool-list
    literals, wrapper ctors and dict registries, resolved against a codebase-wide
    def index. References that don't resolve are reported by ``describe_candidates``.
    """
    sp = _coerce_spec(spec)
    decset = set(sp.tool_decorators)
    out: List[Tuple[Optional[str], str, List[str]]] = []

    def _wanted(fn) -> bool:
        if sp.scan_all_callables:
            return True
        return bool(decset) and any(_dec_last(d) in decset for d in fn.decorator_list)

    for root, _, files in os.walk(src_root):
        for f in files:
            if not f.endswith(".py"):
                continue
            try:
                tree = ast.parse(open(os.path.join(root, f)).read())
            except Exception:
                continue
            # class methods (legacy + general)
            for cls in ast.walk(tree):
                if isinstance(cls, ast.ClassDef):
                    for m in cls.body:
                        if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and _wanted(m):
                            out.append((cls.name, m.name, _params_of(m)))
            # module-level functions (general only; legacy was class-only)
            if not sp._legacy:
                for node in tree.body:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _wanted(node):
                        out.append((None, node.name, _params_of(node)))

    # (2)(3)(4)(5) registration idioms beyond decorators (general mode only)
    if not sp._legacy and (sp.register_methods or sp.tool_list_names or sp.registry_vars):
        index = _index_defs(src_root)
        for r in _registration_refs(src_root, sp):
            for entry in index.get(r, []):     # all matches: recall-first (ambiguity reported)
                out.append(entry)

    seen, uniq = set(), []
    for c in out:
        k = (c[0], c[1])
        if k not in seen:
            seen.add(k)
            uniq.append(c)
    return uniq


def describe_candidates(src_root, spec) -> dict:
    """Diagnostics: how R was recovered, and which references could NOT be resolved
    (cross-module / aliased / dynamic) -- the explicit gap in the soundness
    precondition (complete registration recovery)."""
    sp = _coerce_spec(spec)
    index = _index_defs(src_root) if not sp._legacy else {}
    refs = _registration_refs(src_root, sp) if not sp._legacy else set()
    resolved, ambiguous, unresolved = [], [], []
    for r in sorted(refs):
        entries = index.get(r, [])
        if not entries:
            unresolved.append(r)
        elif len(entries) > 1:
            ambiguous.append((r, len(entries)))
        else:
            resolved.append(r)
    return {
        "registration_refs": sorted(refs),
        "resolved_refs": resolved,
        "ambiguous_refs": ambiguous,        # short name matched >1 def (recall-first over-include)
        "unresolved_refs": unresolved,      # GAP in R -> precondition unmet for these refs
        "total_candidates": len(collect_candidates(src_root, sp)),
    }


def collect_commands(src_root, spec):
    """Backward-compatible alias used by ``reproduce_m2.sh`` (decorator-based,
    class methods). Identical results to the original ``collect_commands``."""
    return collect_candidates(src_root, _coerce_spec(spec))


# --------------------------------------------------------------------------- #
# Wall detection
# --------------------------------------------------------------------------- #
def _find_walls_legacy(tree, hint: str) -> List[ast.Call]:
    """Exact port of the original ``_find_walls``: a var bound to a Call whose
    dotted name contains ``hint``, then bare-Name calls to that var."""
    cmd_vars = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if hint in (_dotted(node.value.func) or "").lower():
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        cmd_vars.add(t.id)
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in cmd_vars]


def _find_walls_general(tree, sp: LoweringSpec) -> List[ast.Call]:
    """Function-scoped multi-idiom wall detection (S)/(G)/(H).

    runtime_vars are accumulated across ALL scopes first, so a callable bound in
    an outer scope (e.g. ``update_func = a or b``) and invoked inside a nested
    closure is still recognised as a wall. Closures see enclosing names, so this
    is sound; it is recall-first (may over-flag same-named vars across scopes).
    """
    bodies = list(_scope_bodies(tree))
    # pass 1: collect every local bound to a runtime-selected value, across scopes
    runtime_vars = set()
    for body in bodies:
        for node in _own_stmt_walk(body):
            if isinstance(node, ast.Assign):
                v = node.value
                bound = (
                    (sp.detect_subscript and _is_subscript(v))
                    or (sp.detect_getattr and _is_getattr_call(v))
                    or (sp.detect_higher_order and isinstance(v, ast.Call)
                        and not _is_getattr_call(v) and _hint_ok(v, sp.resolver_hints))
                    or (sp.detect_higher_order and isinstance(v, ast.BoolOp)
                        and any(isinstance(e, (ast.Name, ast.Call, ast.Attribute))
                                for e in v.values))
                )
                if bound:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            runtime_vars.add(t.id)
    # pass 2: flag calls whose callee is runtime-selected
    walls: List[ast.Call] = []
    for body in bodies:
        for node in _own_stmt_walk(body):
            if isinstance(node, ast.Call):
                fn = node.func
                if (sp.detect_subscript and _is_subscript(fn)) \
                   or (sp.detect_getattr and _is_getattr_call(fn)) \
                   or (isinstance(fn, ast.Name) and fn.id in runtime_vars) \
                   or (isinstance(fn, ast.Name) and fn.id in sp.wall_param_names) \
                   or (isinstance(fn, ast.Attribute) and fn.attr in sp.wall_attr_names):
                    walls.append(node)
    uniq, seen = [], set()
    for w in walls:
        if id(w) not in seen:
            seen.add(id(w))
            uniq.append(w)
    return uniq


def find_walls(tree, spec) -> List[ast.Call]:
    sp = _coerce_spec(spec)
    if sp._legacy:
        hint = (sp.resolver_hints[0] if sp.resolver_hints else "").lower()
        return _find_walls_legacy(tree, hint)
    return _find_walls_general(tree, sp)

def find_walls_with_scope(tree, spec):
    """Return (walls, chain) where chain[id(wall)] is the list of enclosing
    FunctionDefs from innermost to outermost. Lexical scope: a closure sees its
    own locals AND every enclosing scope, so taint sources are collected from
    the whole chain. Framework-agnostic — depends only on nesting structure."""
    sp = _coerce_spec(spec)
    walls = find_walls(tree, sp)
    wall_ids = {id(w) for w in walls}
    chain = {wid: [] for wid in wall_ids}

    def visit(node, stack):
        if isinstance(node, ast.Call) and id(node) in wall_ids:
            chain[id(node)] = list(reversed(stack))   # innermost first
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, stack + [child])
            else:
                visit(child, stack)

    visit(tree, [])
    return walls, chain


def describe_walls(source, spec):
    """Diagnostics: list detected walls as ``(lineno, idiom, callee_src)`` without
    rewriting. Useful to inspect what fires on a new OSS target."""
    sp = _coerce_spec(spec)
    tree = ast.parse(source)
    out = []
    for call in find_walls(tree, sp):
        fn = call.func
        if _is_subscript(fn):
            idiom = "subscript"
        elif _is_getattr_call(fn):
            idiom = "getattr"
        elif isinstance(fn, ast.Name) and fn.id in sp.wall_param_names:
            idiom = "param_call"
        elif isinstance(fn, ast.Attribute) and fn.attr in sp.wall_attr_names:
            idiom = "attr_call"
        elif sp._legacy:
            idiom = "higher_order(hint)"
        else:
            idiom = "higher_order"
        out.append((call.lineno, idiom, ast.unparse(fn)))
    return out


# --------------------------------------------------------------------------- #
# Lowering (source rewrite)
# --------------------------------------------------------------------------- #
def _is_simple(node) -> bool:
    """Forward only simple Name / attribute-chain expressions (e.g. ``arguments``,
    ``context.arguments``). Drop complex exprs (ternary, BoolOp, Call, ...) so the
    inserted block stays syntactically clean and Pysa-parseable."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return isinstance(node, ast.Name)

def _scope_taint_sources(func_nodes) -> List[str]:
    """Collect simple taint-source expressions (parameters + assignment LHS)
    across a list of enclosing functions (innermost first). A closure sees its
    own locals and every enclosing scope, so we union over the whole chain.
    Recall-first: forward them all; Pysa keeps only those actually tainted.

    __ctaudit_ret (the writeback variable from a prior lowering stage) is
    promoted to position 1 so it maps to the second positional parameter of
    the resolved candidate — typically the key data argument (e.g. filter_str)
    that receives taint from the previous wall's return value."""
    if not isinstance(func_nodes, (list, tuple)):
        func_nodes = [func_nodes]
    out, seen = [], set()

    def add(s):
        if s and s not in seen:
            seen.add(s); out.append(s)

    for func_node in func_nodes:
        if func_node is None:
            continue
        a = func_node.args
        for grp in (getattr(a, "posonlyargs", []), a.args, a.kwonlyargs):
            for arg in grp:
                add(arg.arg)
        if a.vararg: add(a.vararg.arg)
        if a.kwarg:  add(a.kwarg.arg)
        for node in ast.walk(func_node):
            targets = []
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.AnnAssign) and node.target:
                targets = [node.target]
            for t in targets:
                if _is_simple(t):
                    add(ast.unparse(t))

    # Promote __ctaudit_ret to position 1 so it maps to the second positional
    # parameter of the resolved candidate (the taint-bearing data argument).
    if "__ctaudit_ret" in out and len(out) > 1:
        out.remove("__ctaudit_ret")
        out.insert(1, "__ctaudit_ret")

    return out


def _taint_args(call) -> List[str]:
    """All *simple* argument expressions of the wall call, forwarded verbatim to
    the resolved target(s). Recall-first: we don't guess which arg is tainted —
    we forward them all; Pysa propagates only the ones that actually carry taint.
    Complex argument expressions are dropped (see _is_simple)."""
    out = []
    for a in call.args:
        v = a.value if isinstance(a, ast.Starred) else a
        if _is_simple(v):
            out.append(ast.unparse(v))
    for kw in call.keywords:
        if kw.arg is None:                      # **kwargs
            if _is_simple(kw.value):
                out.append(ast.unparse(kw.value))
        elif _is_simple(kw.value):              # name=value (simple value only)
            out.append(f"{kw.arg}={ast.unparse(kw.value)}")
    return out


def _resolved_calls(taint_args: List[str], candidates) -> List[str]:
    args = ", ".join(taint_args)
    calls = []
    for cls, name, _params in candidates:       # params no longer used
        qual = f"{cls}.{name}" if cls else name
        calls.append(f"{qual}({args})")
    return calls


def _build_assign_map(tree) -> Dict[int, str]:
    """Map id(call_node) -> assign_target_str for wall calls that are Assign/AnnAssign RHS.

    Handles both direct ``x = wall(...)`` and awaited ``x = await wall(...)`` forms.
    Only records simple (Name or attribute-chain) targets so the writeback stays clean."""
    result: Dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and node.targets:
            value = node.value
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            value = node.value
            target = node.target
        else:
            continue
        if not _is_simple(target):
            continue
        tgt = ast.unparse(target)
        # direct:  x = wall(...)
        if isinstance(value, ast.Call):
            result[id(value)] = tgt
        # awaited: x = await wall(...)
        elif isinstance(value, ast.Await) and isinstance(value.value, ast.Call):
            result[id(value.value)] = tgt
    return result


def _inject_type_checking_imports(source, candidates, module):
    """Add a top-of-file ``if TYPE_CHECKING: from <module> import <Class...>`` so
    Pysa can resolve candidate CLASSES referenced inside the unreachable lowering
    blocks. An inline import inside ``if __ctaudit_unreachable__:`` is not followed
    by Pysa, so a candidate class becomes *obscure* and its precise sink model is
    lost. Adding the TYPE_CHECKING import makes the lowering fully automatic (no
    manual 1-line preprocessing).

    Only CLASS candidates (tuple[0] is not None) need this; module-level function
    candidates resolve fine from the in-block import. Insertion point is computed
    from the AST so multi-line (parenthesised) imports are never split."""
    if not module:
        return source
    # class candidates only
    class_names = sorted({c[0] for c in candidates if c[0]})
    if not class_names:
        return source
    imp = "from " + module + " import " + ", ".join(class_names)
    if ("if TYPE_CHECKING:" in source) and (imp in source):
        return source  # idempotent
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    lines = source.splitlines()
    has_tc = any(
        isinstance(n, ast.ImportFrom) and n.module == "typing"
        and any(a.name == "TYPE_CHECKING" for a in n.names)
        for n in ast.walk(tree)
    )
    # last top-level import/from at module scope -> insert after its end_lineno
    insert_at = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            insert_at = (node.end_lineno or node.lineno)
        elif isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant) and isinstance(node.value.value, str):
            # module docstring: skip
            continue
        else:
            # first real statement; stop (only count leading import block)
            if insert_at:
                break
    block = []
    if not has_tc:
        block.append("from typing import TYPE_CHECKING")
    block.append("if TYPE_CHECKING:")
    block.append("    " + imp)
    out = lines[:insert_at] + block + lines[insert_at:]
    tail = "\n" if source.endswith("\n") else ""
    return "\n".join(out) + tail

def lower_wall_file(source, candidates, spec):
    """Insert an ``if __ctaudit_unreachable__:`` resolved-dispatch block before/after
    each detected wall.  Byte-identical to the original in legacy mode.

    Writeback: when the wall is the RHS of an Assign (``x = wall(...)``), each
    resolved call is wrapped as ``__ctaudit_ret = cand(...); x = __ctaudit_ret`` so
    Pysa sees taint flow into the assigned variable without executing the block."""
    sp = _coerce_spec(spec)
    tree = ast.parse(source)
    walls, chain = find_walls_with_scope(tree, sp)
    if not walls or not candidates:
        return source

    assign_map = _build_assign_map(tree)   # id(call) -> assign target str
    lines = source.splitlines()
    inserts = {}
    for call in walls:
        func_nodes = chain.get(id(call)) or []
        taint_args = _scope_taint_sources(func_nodes) if func_nodes else _taint_args(call)
        if not taint_args:
            continue
        resolved = _resolved_calls(taint_args, candidates)
        assign_target = assign_map.get(id(call))  # None if not an Assign RHS
        ln = call.lineno
        base = lines[ln - 1]
        indent = " " * (len(base) - len(base.lstrip()))
        block = [f"{indent}if __ctaudit_unreachable__:  # [ctaudit] resolved dynamic dispatch -> {len(resolved)} targets"]
        if sp.candidate_import_module:
            names = sorted({(c[0] or c[1]) for c in candidates})
            block.append(f"{indent}    from {sp.candidate_import_module} import {', '.join(names)}")
        if assign_target:
            # writeback form: propagate return value back to the assigned variable
            for r in resolved:
                block.append(f"{indent}    __ctaudit_ret = {r}")
                block.append(f"{indent}    {assign_target} = __ctaudit_ret")
        else:
            block += [indent + "    " + r for r in resolved]
        inserts.setdefault(ln, []).extend(block)

    out = list(lines)
    off = 1 if sp.insert_before else 0          # line ln is at index ln-1; before => ln-1, after => ln
    for ln in sorted(inserts, reverse=True):
        for bl in reversed(inserts[ln]):
            out.insert(ln - off, bl)
    result = "\n".join(out) + "\n"
    result = _inject_type_checking_imports(result, candidates, sp.candidate_import_module)
    return result


if __name__ == "__main__":
    src_root, wall_file = sys.argv[1], sys.argv[2]
    # default = legacy AutoGPT @command idiom (unchanged). For general use, build a
    # LoweringSpec (e.g. detect_subscript/getattr/higher_order, tool_decorators=...)
    # and pass it instead.
    spec = {"tool_decorator": "command", "dispatch_resolver_hint": "command"}
    candidates = collect_candidates(src_root, spec)
    print(f"[ctaudit] collected {len(candidates)} candidate targets")
    open(wall_file, "w").write(lower_wall_file(open(wall_file).read(), candidates, spec))
    print(f"[ctaudit] lowered wall in {wall_file}")