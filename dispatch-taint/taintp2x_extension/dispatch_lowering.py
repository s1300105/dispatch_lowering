"""Dynamic-dispatch wall resolution (lowering pass) — TaintP2X preprocessing.

External preprocessing only: never modifies the base analyzer (TaintP2X / Pysa).
For each dynamic-dispatch *wall* — a call site whose callee is a runtime-selected
value, so the static call graph has no edge across it — this pass inserts an
``if __ctaudit_unreachable__:`` block of direct calls to every *resolved*
target, threading the wall's (tainted) argument(s) into each target's
parameters. The block never executes (the guard is an undefined name, so it is
never truthy at runtime, yet Pyre cannot prove it false and therefore analyses
the block — ``if False:`` would be pruned as dead code). It only hands Pysa's
static data flow the edges it lacks, so taint can cross the wall to the sink.

Structure (IccTA analogue — see ``links.py``):
  1. wall detection          (``find_walls``)             ~ ICC call-site discovery
  2. candidate recovery      (``collect_candidates``)     ~ component enumeration
  3. link construction       (``links.build_links``)      ~ Epicc/IC3 ``Links`` table
                             + registry narrowing / argument-compatibility filters
                             (~ ``UnreasonableLinksRemover``)
  4. emission                (``lower_wall_file[_ex]``)   ~ ``ICCInstrumentSource``
       emit="inline"      : the direct-call block right at the wall (original form)
       emit="redirector"  : one generated ``redirector_N`` per link in a synthetic
                            module ``__ctaudit_redirect`` (~ ``IpcSC.redirectorN``);
                            the wall gets a one-line call per link, and the
                            candidate object is constructed inside the redirector
                            (~ ``ICCInstrumentDestination``'s ``<init>(Intent)``).
  Every wall/link decision is recorded (``LoweringStats``, ``links.json``);
  nothing is dropped silently.

Generalised from the AutoGPT-specific ``@command`` version to a language-level
idiom taxonomy. The legacy spec ``{"tool_decorator": "command",
"dispatch_resolver_hint": "command"}`` still selects the original *detection and
candidate* rules; the emitted code is the current form (guard, bound receiver,
link tags). AutoGPT M2 reproduction: 0 -> 7 issues, 5 distinct sink pairs.

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
  * members of a registry dict/list literal the wall reads (``registry_vars``;
    a trusted registry also drives membership narrowing, ``match_level`` 1);
  * every def under the candidate root (``scan_all_callables`` — most
    over-approximate, recall-first fallback for unknown projects).

PRECISION NOTE (recall-first discipline). (S) and (G) are structurally
unambiguous dispatch sites. (H) with an EMPTY ``resolver_hints`` is the
maximally over-approximate end: it flags every ``f = g(...); f(...)``. Two
precision levers are applied per link in ``links.build_links`` (both on by
default, off in legacy mode):
  * registry narrowing (``spec.narrow``): when the wall reads a trusted static
    registry (single dict literal, never mutated/aliased/rebound) or a BoolOp
    all of whose alternatives are plain names, ``targets = candidates ∩ members``;
  * argument compatibility (``spec.filter_unreasonable``): a candidate whose
    signature cannot accept the wall's actual arguments is dropped as
    ``unreasonable`` (splats make the shape unknowable -> kept).
``spec.match_level`` caps how speculative a LINK may be (1 registry member,
2 decorator/registration, 3 scan-all); narrowing promotes a candidate that is a
member of the registry the wall reads to level 1. Registry narrowing is off in
legacy mode; the argument-compatibility filter applies in both modes (disable it
with ``filter_unreasonable=False``).
"""
from __future__ import annotations

import ast
import keyword
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# this file is loaded by path (importlib) from the harnesses; make the sibling
# ``links`` module importable regardless of the caller's sys.path
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


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
    tool_base_classes: Tuple[str, ...] = ()      # (6) class XxxTool(BaseTool): -> class-based tools
    tool_impl_methods: Tuple[str, ...] = ()      # (6) the method carrying the tool body (e.g. _run)
    wrapper_func_kwargs: Tuple[str, ...] = ("func", "fn", "function", "coroutine", "callback")
    registry_vars: Tuple[str, ...] = ()          # (5) TOOLS = {"a": fn_a} (also membership narrowing)
    scan_all_callables: bool = False
    candidate_import_module: str = ""            # inject `from <mod> import <cands>` at the wall (library-internal walls)
    insert_before: bool = False                  # place block BEFORE the wall line (reachable when wall is `return f(...)`)
    # wall detection
    resolver_hints: Tuple[str, ...] = ()         # (H) only flag resolver calls whose
                                                 # dotted name contains a hint; () = any
    wall_method_names: Tuple[str, ...] = ()      # REQUIRED to flag `t.run(x)` where t is runtime-selected;
                                                 # naming the framework's dispatch method (run/arun/_run)
                                                 # keeps every other method call on that object out
    detect_subscript: bool = True
    detect_getattr: bool = True
    detect_higher_order: bool = True
    detect_boolop: Optional[bool] = None         # (B) f = a or b; f(...)  — default: follows detect_higher_order
    wall_param_names: Tuple[str, ...] = ()       # flag p(...) where p is a callable param (e.g. "fn")
    wall_attr_names: Tuple[str, ...] = ()        # flag o.a(...) where a holds a callable (e.g. "fn","func")
    # link precision (links.build_links)
    narrow: bool = True                          # registry / BoolOp membership narrowing
    filter_unreasonable: bool = True             # drop candidates whose signature rejects the wall's args
    match_level: int = 3                         # max candidate speculation level kept (1..3)
    # emission
    emit: str = "inline"                         # "inline" | "redirector"
    candidate_module_root: str = ""              # root for deriving candidate dotted modules (default: package walk-up)
    candidates: Tuple[dict, ...] = ()            # explicit candidate records (skip recovery); see links.Candidate
    _legacy: bool = False                        # internal: original detection/candidate rules


_NEW_KEYS = {
    "tool_decorators", "register_methods", "tool_list_names", "tool_wrappers", "tool_base_classes", "tool_impl_methods",
    "wrapper_func_kwargs", "registry_vars", "scan_all_callables", "candidate_import_module", "insert_before",
    "resolver_hints", "detect_subscript", "detect_getattr", "detect_higher_order", "detect_boolop",
    "wall_method_names", "wall_param_names", "wall_attr_names",
    "narrow", "filter_unreasonable", "match_level", "emit", "candidate_module_root", "candidates",
}
# keys that configure precision/emission only — they do not switch a legacy
# spec (AutoGPT @command) into general detection mode
_META_KEYS = {"narrow", "filter_unreasonable", "match_level", "emit", "candidate_module_root", "candidates"}


def _coerce_spec(spec) -> LoweringSpec:
    """Accept a LoweringSpec, or a dict with legacy and/or new keys.

    A dict carrying ONLY legacy keys (``tool_decorator`` / ``dispatch_resolver_hint``)
    — plus, optionally, precision/emission keys — selects legacy mode, which uses
    the original wall-detection and candidate-recovery rules (the emitted code is
    the current form).
    """
    if isinstance(spec, LoweringSpec):
        return spec
    spec = dict(spec or {})
    has_new = bool((_NEW_KEYS - _META_KEYS) & spec.keys())

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
        tool_base_classes=tuple(spec.get("tool_base_classes", ())),
        tool_impl_methods=tuple(spec.get("tool_impl_methods", ())),
        wrapper_func_kwargs=tuple(spec.get("wrapper_func_kwargs",
                                           ("func", "fn", "function", "coroutine", "callback"))),
        registry_vars=tuple(spec.get("registry_vars", ())),
        scan_all_callables=bool(spec.get("scan_all_callables", False)),
        candidate_import_module=str(spec.get("candidate_import_module", "") or ""),
        insert_before=bool(spec.get("insert_before", False)),
        resolver_hints=hints,
        wall_method_names=tuple(spec.get("wall_method_names", ())),
        detect_subscript=bool(spec.get("detect_subscript", True)),
        detect_getattr=bool(spec.get("detect_getattr", True)),
        detect_higher_order=bool(spec.get("detect_higher_order", True)),
        detect_boolop=(None if spec.get("detect_boolop") is None else bool(spec.get("detect_boolop"))),
        wall_param_names=tuple(spec.get("wall_param_names", ())),
        wall_attr_names=tuple(spec.get("wall_attr_names", ())),
        narrow=bool(spec.get("narrow", True)),
        filter_unreasonable=bool(spec.get("filter_unreasonable", True)),
        match_level=int(spec.get("match_level", 3)),
        emit=str(spec.get("emit", "inline") or "inline"),
        candidate_module_root=str(spec.get("candidate_module_root", "") or ""),
        candidates=tuple(spec.get("candidates", ()) or ()),
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


GUARD_NAME = "__ctaudit_unreachable__"
_GEN_PREFIX = "__ctaudit_"


def _is_generated_block(node) -> bool:
    """An ``if __ctaudit_unreachable__:`` block this pass inserted earlier.
    Its contents must not be re-detected as walls, or a second stage (or a
    re-run) nests duplicate blocks and inflates every statistic."""
    return (isinstance(node, ast.If) and isinstance(node.test, ast.Name)
            and node.test.id == GUARD_NAME)


def _own_stmt_walk(stmts):
    """Yield nodes inside ``stmts`` (and their expressions), NOT descending into
    nested def/class bodies — those are separate scopes handled on their own —
    nor into blocks this pass generated."""
    stack = list(stmts)
    while stack:
        n = stack.pop()
        if _is_generated_block(n):
            continue
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


def _index_defs(src_root, mod_root: str = "") -> Dict[str, list]:
    """short callable name -> list of links.Candidate. Codebase-wide."""
    from links import Candidate, module_of
    by_short: Dict[str, list] = defaultdict(list)
    for p, tree in _iter_py(src_root):
        mod = module_of(p, mod_root)
        for cls in ast.walk(tree):
            if isinstance(cls, ast.ClassDef):
                for m in cls.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        by_short[m.name].append(Candidate.from_def(m, cls.name, mod, p, origin="registration"))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                by_short[node.name].append(Candidate.from_def(node, None, mod, p, origin="registration"))
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


def collect_candidates(src_root, spec) -> List["Candidate"]:
    """Recover the registered-tool set R as ``links.Candidate`` records
    (iterable as ``(class_or_None, name, param_names)`` for old callers).

    Legacy mode: decorator-marked *class methods* only (original behaviour).
    General mode: decorators + module functions, PLUS register-calls, tool-list
    literals, wrapper ctors and dict registries, resolved against a codebase-wide
    def index. References that don't resolve are reported by ``describe_candidates``.
    Each record carries its dotted ``module`` (for the redirector emitter), its
    full signature (for the argument-compatibility filter) and a ``match_level``
    (1 registry-literal member, 2 decorator/registration, 3 scan-all).
    ``spec.candidates`` (explicit records) short-circuits recovery entirely.
    """
    from links import Candidate, module_of
    sp = _coerce_spec(spec)
    if sp.candidates:
        return _dedup_candidates([Candidate.from_any(c) for c in sp.candidates])
    decset = set(sp.tool_decorators)
    out: List[Candidate] = []
    mod_root = sp.candidate_module_root

    def _wanted(fn) -> bool:
        if sp.scan_all_callables:
            return True
        return bool(decset) and any(_dec_last(d) in decset for d in fn.decorator_list)

    def _level(fn) -> int:
        # decorator-marked = 2; only reached through scan_all_callables = 3
        if decset and any(_dec_last(d) in decset for d in fn.decorator_list):
            return 2
        return 3

    for root, _, files in os.walk(src_root):
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(root, f)
            try:
                tree = ast.parse(open(path).read())
            except Exception:
                continue
            mod = module_of(path, mod_root)
            # class methods (legacy + general)
            for cls in ast.walk(tree):
                if isinstance(cls, ast.ClassDef):
                    for m in cls.body:
                        if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and _wanted(m):
                            out.append(Candidate.from_def(
                                m, cls.name, mod, path,
                                origin="decorator" if _level(m) == 2 else "scan_all",
                                match_level=_level(m)))
            # (6) class-based tools: class XxxTool(BaseTool): with an impl method (_run)
            if sp.tool_base_classes and sp.tool_impl_methods:
                _bases = set(sp.tool_base_classes)
                _impls = set(sp.tool_impl_methods)
                for cls in ast.walk(tree):
                    if isinstance(cls, ast.ClassDef):
                        base_names = {b.id for b in cls.bases if isinstance(b, ast.Name)}
                        base_names |= {b.attr for b in cls.bases if isinstance(b, ast.Attribute)}
                        if base_names & _bases:
                            for m in cls.body:
                                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name in _impls:
                                    out.append(Candidate.from_def(m, cls.name, mod, path,
                                                                  origin="base_class", match_level=2))
            # module-level functions (general only; legacy was class-only)
            if not sp._legacy:
                for node in tree.body:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _wanted(node):
                        out.append(Candidate.from_def(
                            node, None, mod, path,
                            origin="decorator" if _level(node) == 2 else "scan_all",
                            match_level=_level(node)))

    # (2)(3)(4)(5) registration idioms beyond decorators (general mode only)
    if not sp._legacy and (sp.register_methods or sp.tool_list_names or sp.registry_vars):
        index = _index_defs(src_root, mod_root)
        for r in _registration_refs(src_root, sp):
            for entry in index.get(r, []):     # all matches: recall-first (ambiguity reported)
                out.append(entry)

    return _dedup_candidates(out)


def _dedup_candidates(cands):
    seen, uniq = set(), []
    for c in cands:
        k = (c.cls, c.name, c.module)
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
def _walk_source(tree):
    """``ast.walk`` over the original source only — blocks this pass generated
    are skipped so a re-run does not lower its own output."""
    stack = [tree]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(c for c in ast.iter_child_nodes(n) if not _is_generated_block(c))


def _find_walls_legacy(tree, hint: str) -> List[ast.Call]:
    """Exact port of the original ``_find_walls``: a var bound to a Call whose
    dotted name contains ``hint``, then bare-Name calls to that var."""
    cmd_vars = set()
    for node in _walk_source(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if hint in (_dotted(node.value.func) or "").lower():
                for t in node.targets:
                    if isinstance(t, ast.Name) and not t.id.startswith(_GEN_PREFIX):
                        cmd_vars.add(t.id)
    return [n for n in _walk_source(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in cmd_vars]


def _find_walls_general(tree, sp: LoweringSpec) -> List[ast.Call]:
    """Function-scoped multi-idiom wall detection (S)/(G)/(H).

    runtime_vars are accumulated across ALL scopes first, so a callable bound in
    an outer scope (e.g. ``update_func = a or b``) and invoked inside a nested
    closure is still recognised as a wall. Closures see enclosing names, so this
    is sound; it is recall-first (may over-flag same-named vars across scopes).
    """
    bodies = list(_scope_bodies(tree))
    detect_boolop = sp.detect_higher_order if sp.detect_boolop is None else sp.detect_boolop
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
                    or (detect_boolop and isinstance(v, ast.BoolOp)
                        and any(isinstance(e, (ast.Name, ast.Call, ast.Attribute))
                                for e in v.values))
                )
                if bound:
                    for t in node.targets:
                        # never treat this pass's own temporaries as walls
                        if isinstance(t, ast.Name) and not t.id.startswith(_GEN_PREFIX):
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
                   or (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                       and fn.value.id in runtime_vars
                       and fn.attr in sp.wall_method_names) \
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

    # Promote __ctaudit_ret (a previous stage's writeback) to position 1 so
    # that, once the enclosing method's receiver is stripped by build_links,
    # it maps to the resolved candidate's first real parameter (the data
    # argument that receives the previous wall's return value).
    if "__ctaudit_ret" in out and len(out) > 1:
        out.remove("__ctaudit_ret")
        out.insert(1 if out[0] in ("self", "cls") else 0, "__ctaudit_ret")

    return out


def _taint_args(call) -> List[str]:
    """All *simple* argument expressions of the wall call, forwarded verbatim to
    the resolved target(s). Recall-first: we don't guess which arg is tainted —
    we forward them all; Pysa propagates only the ones that actually carry taint.
    Complex argument expressions are dropped (see _is_simple)."""
    out = []
    for a in call.args:
        if isinstance(a, ast.Starred):
            continue                            # *args splat: not forwardable positionally
        if _is_simple(a) or isinstance(a, ast.Constant):
            out.append(ast.unparse(a))
    for kw in call.keywords:
        if kw.arg is None:                      # **kwargs: drop from resolved call
            # a ``**kwargs`` splat can't be forwarded as a positional/keyword arg
            # without breaking argument order; it's dict-expansion (typically
            # non-tainted logging kwargs), so we omit it from the resolved target.
            continue
        elif _is_simple(kw.value) or isinstance(kw.value, ast.Constant):
            out.append(f"{kw.arg}={ast.unparse(kw.value)}")   # name=value (simple / literal)
    return out


def _call_expr(qual: str, taint_args: List[str], is_async: bool, in_async: bool) -> str:
    """``qual(args)``, awaited when the target is a coroutine function and the
    wall sits in an ``async def`` (otherwise ``await`` would be a syntax error)."""
    expr = f"{qual}({', '.join(taint_args)})"
    return f"await {expr}" if (is_async and in_async) else expr


def _resolved_calls(taint_args: List[str], candidates) -> List[str]:
    """Kept for old callers: one unbound direct call per candidate."""
    from links import coerce_candidates
    return [_call_expr(c.qualname, taint_args, False, False) for c in coerce_candidates(candidates)]


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

REDIRECT_MODULE = "__ctaudit_redirect"
# statements after which an inserted block would be unreachable (return/raise)
# or would land inside/after a body the wall's header controls
_BEFORE_KINDS = {"Return", "Raise", "If", "While", "For", "AsyncFor", "With", "AsyncWith",
                 "Try", "TryStar", "Match", "Assert"}


def _module_bindings(source: str) -> set:
    """Top-level names the wall file already binds (imports, defs, classes,
    assignments). A target whose name is already bound must not be re-imported
    into the block — that would shadow or conflict with the file's own name."""
    out = set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return out
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                out.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out.add(t.id)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and isinstance(node.target, ast.Name):
            out.add(node.target.id)
    return out


def _receiver_stmt(cls: str) -> str:
    """Construct the target object without running a constructor whose
    arguments we cannot supply statically — IccTA's generated ``<init>(Intent)``
    / null-argument constructor fallback. ``Cls.__new__(Cls)`` is typed as
    ``Cls`` by Pyre, so method resolution and the target's sink models apply."""
    return f"__ctaudit_obj = {cls}.__new__({cls})"


def _param_name(expr: str, taken: set) -> str:
    """Valid, unique parameter name derived from a forwarded argument expression
    (``tool_call.arguments`` -> ``tool_call_arguments``)."""
    base = re.sub(r"\W+", "_", expr).strip("_") or "arg"
    if base[0].isdigit():
        base = "a_" + base
    if keyword.iskeyword(base):
        base += "_"
    name, i = base, 1
    while name in taken:
        i += 1
        name = f"{base}_{i}"
    taken.add(name)
    return name


class RedirectModuleBuilder:
    """Accumulates generated redirectors across wall files and renders the
    synthetic module ``__ctaudit_redirect.py`` (IccTA's ``IpcSC`` class).

    Each redirector takes exactly the wall's forwarded arguments, constructs the
    target object when the target is a method (``Cls.__new__(Cls)`` — the
    ``<init>(Intent)`` analogue: an instance without running a constructor we
    cannot statically provide arguments for), calls the target and returns its
    result, so the wall's writeback sees the target's return value."""

    def __init__(self, module_name: str = REDIRECT_MODULE):
        self.module_name = module_name
        self.aliases: Dict[Tuple[str, str], str] = {}   # (module, name) -> local alias
        self.defs: List[str] = []
        self.count = 0

    def _alias(self, module: str, name: str) -> str:
        """Local alias for ``module.name``, module-qualified so two candidates
        with the same name in different modules never shadow each other."""
        key = (module, name)
        if key not in self.aliases:
            suffix = re.sub(r"\W+", "_", module).strip("_")
            alias = name if not any(k[1] == name for k in self.aliases) else f"{name}__{suffix}"
            self.aliases[key] = alias
        return self.aliases[key]

    def add(self, link, wall, sp: LoweringSpec) -> Optional[str]:
        """Register a redirector for ``link``; returns its name, or None if the
        target cannot be imported from the synthetic module (phantom)."""
        c = link.target
        module = c.module or sp.candidate_import_module
        if not module:
            return None
        alias = self._alias(module, c.import_name)
        name = f"redirector_{self.count}"
        self.count += 1

        taken: set = set()
        params, call_args = [], []
        for a in link.args_for(wall):
            # the forwarded item is structured text: '**expr', 'kw=expr' or 'expr'.
            # Match the keyword form on a leading identifier so a forwarded string
            # constant containing '=' is not split into a broken keyword.
            m = None if a.startswith("**") else re.match(r"^([A-Za-z_]\w*)=(?!=)", a)
            if a.startswith("**"):
                p = _param_name(a[2:], taken)
                params.append("**" + p)
                call_args.append("**" + p)
            elif m:
                kw = m.group(1)
                p = _param_name(kw, taken)
                params.append(p)
                call_args.append(f"{kw}={p}")
            else:
                p = _param_name(a, taken)
                params.append(p)
                call_args.append(p)
        if c.cls:
            # method target: bound call on a constructed instance
            body = [f"    {_receiver_stmt(alias)}",
                    f"    return {_call_expr('__ctaudit_obj.' + c.name, call_args, c.is_async, c.is_async)}"]
        else:
            body = [f"    return {_call_expr(alias, call_args, c.is_async, c.is_async)}"]
        head = "async def" if c.is_async else "def"
        doc = f'    """{link.id}: {wall.file}:{wall.line} {wall.callee}(...) -> {c.module}.{c.qualname}"""'
        self.defs.append("\n".join([f"{head} {name}({', '.join(params)}):", doc] + body))
        return name

    def render(self) -> str:
        lines = ['"""[ctaudit] generated redirectors — one per resolved dispatch link.',
                 "",
                 "IccTA analogue of the synthetic ``IpcSC`` class: each ``redirector_N`` makes",
                 "the resolved edge explicit as ordinary Python that the taint engine already",
                 "understands. Only ever referenced from ``if __ctaudit_unreachable__:`` blocks,",
                 'so it is never imported at runtime."""', ""]
        by_module: Dict[str, List[str]] = defaultdict(list)
        for (module, name), alias in self.aliases.items():
            by_module[module].append(name if alias == name else f"{name} as {alias}")
        for mod in sorted(by_module):
            lines.append(f"from {mod} import {', '.join(sorted(by_module[mod]))}")
        lines.append("")
        for d in self.defs:
            lines += ["", d, ""]
        return "\n".join(lines).rstrip("\n") + "\n"


@dataclass
class LoweringResult:
    source: str
    walls: list
    links: list
    stats: "object"
    redirect_module: str = ""      # rendered synthetic module (redirector mode, standalone builder)


def lower_wall_file_ex(source, candidates, spec, *, wall_file: str = "",
                       registry_index=None, links=None, redirect=None,
                       id_offset: int = 0, id_prefix: str = "") -> LoweringResult:
    """Full-information lowering: returns the rewritten source plus the wall and
    link records and statistics. ``links`` (pre-built, e.g. loaded from a
    hand-written ``links.json``) bypasses candidate joining; otherwise
    ``links.build_links`` is used. ``redirect`` is a shared
    ``RedirectModuleBuilder`` for ``emit='redirector'`` across several files."""
    import links as L
    sp = _coerce_spec(spec)
    cands = L.coerce_candidates(candidates)
    if links is None:
        walls, lnks, stats = L.build_links(source, wall_file, cands, sp,
                                           registry_index=registry_index,
                                           id_offset=id_offset, id_prefix=id_prefix)
    else:
        walls, lnks, stats = _adopt_links(source, wall_file, links, sp,
                                          id_offset=id_offset, id_prefix=id_prefix)
    lowered = [l for l in lnks if l.status == "lowered"]
    if not lowered:
        return LoweringResult(source, walls, lnks, stats)

    own_builder = None
    if sp.emit == "redirector" and redirect is None:
        redirect = own_builder = RedirectModuleBuilder()

    by_wall: Dict[str, list] = defaultdict(list)
    for l in lowered:
        by_wall[l.wall_id].append(l)
    bound_names = _module_bindings(source)
    lines = source.splitlines()
    inserts: Dict[int, list] = {}
    call_rows: Dict[int, list] = {}      # ln -> [(link, row offset within block)]
    for w in walls:
        group = by_wall.get(w.id)
        if not group:
            continue
        # Anchor on the enclosing *statement*: after its last line (so a
        # multi-line call never gets the block spliced into its argument list),
        # or before its first line. "Before" is forced for statements after
        # which the block would be unreachable or misplaced (return/raise,
        # compound statements whose body the wall sits in the header of).
        before = sp.insert_before or w.stmt_kind in _BEFORE_KINDS
        anchor = w.stmt_line or w.line                       # statement's FIRST line
        ln = anchor if before else (w.stmt_end_line or w.end_line)
        if before and w.chain_line:
            # a wall in an ``elif``/``else`` header: anchoring on the elif line
            # would splice the block between the parent ``if`` body and its
            # ``elif``, re-parenting the whole chain to the inserted ``if``
            ln = anchor = w.chain_line
        # indentation always comes from the statement's first line: its closing
        # line may be continuation-indented (``f(a,\n    b)``), which would emit
        # an over-indented block and break the file
        base = lines[anchor - 1]
        indent = " " * (len(base) - len(base.lstrip()))
        block = [f"{indent}if {GUARD_NAME}:  # [ctaudit] resolved dynamic dispatch -> "
                 f"{len(group)} targets | wall={w.file}:{w.line}"]
        rows = []
        if sp.emit == "redirector":
            names = []
            for l in group:
                l.redirector = redirect.add(l, w, sp) or ""
                if not l.redirector:
                    l.status, l.reason = "phantom", "target module unknown; not importable from redirect module"
                    stats.links_lowered -= 1
                    stats.links_phantom += 1
                else:
                    names.append(l.redirector)
            if not names:
                continue
            block.append(f"{indent}    from {redirect.module_name} import {', '.join(names)}")
            for l in group:
                if not l.redirector:
                    continue
                expr = _call_expr(l.redirector, l.args_for(w), l.target.is_async, w.in_async)
                rows.append((l, len(block)))
                if w.assign_target:
                    block.append(f"{indent}    __ctaudit_ret = {expr}  # {l.id} -> {l.qualname}")
                    block.append(f"{indent}    {w.assign_target} = __ctaudit_ret")
                else:
                    block.append(f"{indent}    {expr}  # {l.id} -> {l.qualname}")
        else:
            # import every target the wall file does not already bind, grouped by
            # module — without this the inserted call is an undefined name and
            # Pysa cannot resolve the target (the block is analysed, not run)
            need: Dict[str, set] = defaultdict(set)
            for l in group:
                mod = sp.candidate_import_module or l.target.module
                if mod and l.target.import_name not in bound_names:
                    need[mod].add(l.target.import_name)
            for mod in sorted(need):
                block.append(f"{indent}    from {mod} import {', '.join(sorted(need[mod]))}")
            for l in group:
                c = l.target
                if c.cls:
                    # destination-side instrumentation, inline: construct the
                    # receiver so the target runs as a bound method
                    block.append(f"{indent}    {_receiver_stmt(c.cls)}")
                    expr = _call_expr("__ctaudit_obj." + c.name, l.args_for(w), c.is_async, w.in_async)
                else:
                    expr = _call_expr(c.name, l.args_for(w), c.is_async, w.in_async)
                rows.append((l, len(block)))
                if w.assign_target:
                    # writeback form: propagate return value back to the assigned variable
                    block.append(f"{indent}    __ctaudit_ret = {expr}  # {l.id}")
                    block.append(f"{indent}    {w.assign_target} = __ctaudit_ret")
                else:
                    block.append(f"{indent}    {expr}  # {l.id}")
        key = (ln, before)
        off0 = len(inserts.get(key, []))
        inserts.setdefault(key, []).extend(block)
        call_rows.setdefault(key, []).extend((l, off0 + r) for l, r in rows)

    out = list(lines)
    # line ln is at index ln-1; before => insert at ln-1, after => at ln
    order = sorted(inserts, key=lambda k: (k[0], not k[1]))
    for key in reversed(order):
        ln, before = key
        at = ln - 1 if before else ln
        for bl in reversed(inserts[key]):
            out.insert(at, bl)
    # final line numbers of the inserted calls (JimpleIndexNumberTag analogue)
    shift = 0
    for key in order:
        ln, before = key
        start = (ln - 1 if before else ln) + shift   # 0-based index of the block's first line
        for l, r in call_rows.get(key, []):
            l.lowered_line = start + r + 1
        shift += len(inserts[key])
    stats.lines_added += sum(len(b) for b in inserts.values())
    result = "\n".join(out) + "\n"
    if sp.emit != "redirector":
        n_before = result.count("\n")
        result = _inject_type_checking_imports(result, [l.target for l in lowered], sp.candidate_import_module)
        # the TYPE_CHECKING block goes above every wall, so each recorded line moves down
        injected = result.count("\n") - n_before
        if injected:
            for l in lowered:
                if l.lowered_line:
                    l.lowered_line += injected
        stats.lines_added += injected
    stats.redirectors = redirect.count if redirect is not None else 0
    return LoweringResult(result, walls, lnks, stats,
                          redirect_module=own_builder.render() if own_builder else "")


def _adopt_links(source, wall_file, links, sp, id_offset: int = 0, id_prefix: str = ""):
    """Attach externally supplied links (hand-written / loaded) to the walls
    detected in ``source``, matched by line number — the ``ICCLink.linkWithTarget``
    ordinal remap: the link names *where* the wall is, we find the call unit.
    Links are copied, so one provider object can be offered to several wall
    files without the last file's adoption overwriting the others' state."""
    import copy
    import links as L
    walls, _auto, stats = L.build_links(source, wall_file, [], sp,
                                        id_offset=id_offset, id_prefix=id_prefix)
    by_line = {w.line: w for w in walls}
    base = os.path.basename(wall_file) if wall_file else "<source>"
    out = []
    for src_link in links:
        if src_link.file and os.path.basename(src_link.file) != base:
            continue
        l = copy.deepcopy(src_link)
        w = by_line.get(l.line)
        if w is None:
            l.status, l.reason = "phantom", f"no wall detected at {base}:{l.line}"
            stats.links_phantom += 1
            out.append(l)
            continue
        if w.status == "skipped_no_args":
            l.status, l.reason = "phantom", w.reason
            stats.links_phantom += 1
            out.append(l)
            continue
        l.wall_id, l.file = w.id, base
        if l.status == "lowered":
            w.status, w.reason = "resolved", ""
            stats.links_lowered += 1
        stats.links_built += 1
        out.append(l)
    for w in walls:
        if w.status == "resolved" and not any(l.wall_id == w.id and l.status == "lowered" for l in out):
            w.status, w.reason = "unresolved", "no link supplied for this wall"
    return walls, out, stats


def lower_wall_file(source, candidates, spec, **kw):
    """Insert an ``if __ctaudit_unreachable__:`` resolved-dispatch block before/after
    each detected wall (inline emission) — see ``lower_wall_file_ex`` for the
    records. Writeback: when the wall is the RHS of an Assign (``x = wall(...)``),
    each resolved call is wrapped as ``__ctaudit_ret = cand(...); x = __ctaudit_ret``
    so Pysa sees taint flow into the assigned variable without executing the block."""
    return lower_wall_file_ex(source, candidates, spec, **kw).source


if __name__ == "__main__":
    # Thin legacy entry point; use ``pipeline.py`` for the configurable driver.
    src_root, wall_file = sys.argv[1], sys.argv[2]
    spec = {"tool_decorator": "command", "dispatch_resolver_hint": "command"}
    candidates = collect_candidates(src_root, spec)
    print(f"[ctaudit] collected {len(candidates)} candidate targets")
    res = lower_wall_file_ex(open(wall_file).read(), candidates, spec, wall_file=wall_file)
    open(wall_file, "w").write(res.source)
    print(f"[ctaudit] lowered wall in {wall_file}: {res.stats.links_lowered} link(s)")