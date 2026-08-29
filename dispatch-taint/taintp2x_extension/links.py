"""Dispatch links — the explicit wall -> target intermediate representation.

IccTA analogue: IC3/Epicc resolve every ICC call site to an ``ICCLink``
(source method, call unit, exit kind, destination component) *before* any Jimple
is instrumented, and the link table is a first-class artifact that can be
inspected, filtered and persisted. This module plays the same role for Python
dynamic-dispatch walls:

    wall (call site whose callee is runtime-selected)
      x candidate (registered tool / callable recovered from the tree)
      -> DispatchLink  (status: lowered | filtered_registry | unreasonable | ...)

``build_links`` joins walls and candidates, applies the precision filters
(registry-membership narrowing, argument/signature compatibility — the
``UnreasonableLinksRemover`` analogue) and records every decision, so nothing
is dropped silently. The emitters in ``dispatch_lowering`` consume links only;
they never look at candidates directly.

Persisted form (``links.json``)::

    {"walls": [WallRecord...], "links": [DispatchLink...], "stats": {...}}
"""
from __future__ import annotations

import ast
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


# decorators that provably keep the wrapped signature callable as written, so a
# def carrying only these can still be signature-checked
_SIGNATURE_PRESERVING_DECORATORS = {
    "staticmethod", "classmethod", "property", "abstractmethod", "override",
    "cached_property", "lru_cache", "cache", "overload", "final",
}


def _dec_name(dec) -> str:
    """Last component of a decorator expression: ``@a.b.tool()`` -> ``tool``."""
    if isinstance(dec, ast.Call):
        dec = dec.func
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Name):
        return dec.id
    return ""


# --------------------------------------------------------------------------- #
# Candidate (resolved target)
# --------------------------------------------------------------------------- #
@dataclass
class Candidate:
    """A callable the wall may dispatch to. ``params`` are the positional
    parameter names excluding ``self``; ``kwonly``/``has_varargs``/``has_kwargs``
    complete the signature for compatibility checks. ``module`` is the dotted
    import path (empty when unknown — e.g. legacy 3-tuples or explicit specs
    without one)."""
    cls: Optional[str]
    name: str
    params: List[str] = field(default_factory=list)
    kwonly: List[str] = field(default_factory=list)
    has_varargs: bool = False
    has_kwargs: bool = False
    module: str = ""
    path: str = ""
    lineno: int = 0
    is_async: bool = False
    decorated: bool = False          # def carries decorators -> the runtime callee may be a wrapper
    origin: str = "decorator"        # decorator | registration | base_class | scan_all | explicit
    match_level: int = 2             # 1 registry-literal member, 2 decorator/registration, 3 scan-all
    forward: List[str] = field(default_factory=list)   # explicit argument expressions to forward
                                                        # (analyst-pinned link; overrides the wall's)

    @property
    def qualname(self) -> str:
        return f"{self.cls}.{self.name}" if self.cls else self.name

    @property
    def import_name(self) -> str:
        """Name to import from ``module``: the class for methods, else the function."""
        return self.cls or self.name

    def as_tuple(self) -> Tuple[Optional[str], str, List[str]]:
        return (self.cls, self.name, list(self.params))

    # old callers unpack / index candidates as (cls, name, params)
    def __iter__(self):
        return iter(self.as_tuple())

    def __getitem__(self, i):
        return self.as_tuple()[i]

    @classmethod
    def from_any(cls, obj) -> "Candidate":
        if isinstance(obj, Candidate):
            return obj
        if isinstance(obj, dict):
            known = {k: v for k, v in obj.items() if k in cls.__dataclass_fields__}
            # a hand-written record (spec ``candidates`` / links.json target) is
            # explicit unless it says otherwise: its omitted fields mean
            # "unknown", not "empty signature". ``cls`` may be omitted for a
            # module-level function target.
            known.setdefault("origin", "explicit")
            known.setdefault("cls", None)
            if "name" not in known:
                raise ValueError(f"candidate record needs a 'name': {obj!r}")
            return cls(**known)
        c, n, p = obj[0], obj[1], (list(obj[2]) if len(obj) > 2 else [])
        return cls(cls=c, name=n, params=p, origin="explicit")

    @classmethod
    def from_def(cls, fn, class_name: Optional[str], module: str = "", path: str = "",
                 origin: str = "decorator", match_level: int = 2) -> "Candidate":
        a = fn.args
        pos = [x.arg for x in list(getattr(a, "posonlyargs", [])) + list(a.args)]
        if class_name and pos and pos[0] in ("self", "cls"):
            pos = pos[1:]
        return cls(
            cls=class_name, name=fn.name, params=pos,
            kwonly=[x.arg for x in a.kwonlyargs],
            has_varargs=a.vararg is not None, has_kwargs=a.kwarg is not None,
            module=module, path=path, lineno=getattr(fn, "lineno", 0),
            is_async=isinstance(fn, ast.AsyncFunctionDef),
            decorated=bool([d for d in fn.decorator_list
                            if _dec_name(d) not in _SIGNATURE_PRESERVING_DECORATORS]),
            origin=origin, match_level=match_level,
        )


def coerce_candidates(cands) -> List[Candidate]:
    return [Candidate.from_any(c) for c in (cands or [])]


def module_of(path: str, root: str = "") -> str:
    """Dotted module path of ``path``. Walk up while ``__init__.py`` exists
    (package boundary), or stop at ``root`` when given. ``''`` if undecidable."""
    path = os.path.abspath(path)
    if not path.endswith(".py"):
        return ""
    parts = [os.path.basename(path)[:-3]]
    d = os.path.dirname(path)
    root = os.path.abspath(root) if root else ""
    while True:
        if root and os.path.abspath(d) == root:
            break
        if not os.path.exists(os.path.join(d, "__init__.py")):
            if root:
                # inside root but not a package: still relative to root
                rel = os.path.relpath(d, root)
                if rel != ".":
                    parts = rel.split(os.sep) + parts
            break
        parts.insert(0, os.path.basename(d))
        d = os.path.dirname(d)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(p for p in parts if p)


# --------------------------------------------------------------------------- #
# Wall / link records
# --------------------------------------------------------------------------- #
@dataclass
class WallRecord:
    """One detected wall (IccTA ``ExitPoints`` row). ``status`` explains walls
    that produced no lowered link."""
    id: str
    file: str
    line: int
    end_line: int
    idiom: str
    callee: str
    stmt_line: int = 0                   # enclosing statement span — insertion anchors
    stmt_end_line: int = 0
    stmt_kind: str = ""                  # ast class name of the enclosing statement
    chain_line: int = 0                  # if the statement is an ``elif``: the chain's outermost ``if``
    registry: Optional[str] = None       # registry name the wall reads (REG[k] / f = REG[k])
    members: Optional[List[str]] = None  # BoolOp alternatives / trusted registry tokens
    assign_target: Optional[str] = None
    is_method_wall: bool = False
    in_async: bool = False
    taint_args: List[str] = field(default_factory=list)
    status: str = "resolved"             # resolved | skipped_no_args | unresolved
    reason: str = ""


@dataclass
class DispatchLink:
    """One wall -> target edge (IccTA ``Links`` row)."""
    id: str
    wall_id: str
    file: str
    line: int
    target: Candidate
    match_level: int = 2
    status: str = "lowered"              # lowered | filtered_registry | unreasonable | phantom
    reason: str = ""
    taint_args: List[str] = field(default_factory=list)  # forwarded args (empty -> the wall's)
    redirector: str = ""                 # generated redirector name (redirector emit mode)
    lowered_line: int = 0                # line of the inserted call after lowering

    @property
    def qualname(self) -> str:
        return self.target.qualname

    def args_for(self, wall) -> List[str]:
        return list(self.taint_args or self.target.forward or wall.taint_args)


@dataclass
class LoweringStats:
    """IccTA ``InfoStatistic`` analogue — every count the pass makes, so
    nothing is dropped silently."""
    files: int = 0
    walls_detected: int = 0
    walls_by_idiom: Dict[str, int] = field(default_factory=dict)
    walls_skipped_no_args: int = 0
    candidates_total: int = 0
    links_built: int = 0
    links_lowered: int = 0
    links_filtered_registry: int = 0
    links_filtered_level: int = 0
    links_unreasonable: int = 0
    links_no_args: int = 0
    links_phantom: int = 0
    lines_added: int = 0
    redirectors: int = 0
    unresolved_refs: List[str] = field(default_factory=list)

    def merge(self, other: "LoweringStats") -> "LoweringStats":
        out = LoweringStats()
        for k in self.__dataclass_fields__:
            a, b = getattr(self, k), getattr(other, k)
            if isinstance(a, dict):
                m = dict(a)
                for kk, vv in b.items():
                    m[kk] = m.get(kk, 0) + vv
                setattr(out, k, m)
            elif isinstance(a, list):
                setattr(out, k, sorted(set(a) | set(b)))
            else:
                setattr(out, k, a + b)
        return out

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Registry index (ported from ctaudit/analysis/dispatch_resolution.py)
# --------------------------------------------------------------------------- #
def _final(node) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dict_member_tokens(d: ast.Dict):
    """(tokens, ok) for a dict literal. ``ok`` is False if any key/value is not
    statically resolvable — including a ``**other`` unpacking, whose members
    live in another object — so the registry must NOT be trusted for narrowing."""
    toks, ok = set(), True
    for k, v in zip(d.keys, d.values):
        if k is None:
            ok = False                      # {**other}: members not statically known
            continue
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            toks.add(k.value)
        else:
            ok = False
        vn = _final(v)
        if vn:
            toks.add(vn)
        elif isinstance(v, ast.Constant) and isinstance(v.value, str):
            toks.add(v.value)
        else:
            ok = False
    return toks, ok


_MUTATORS = ("update", "setdefault", "__setitem__", "pop", "popitem", "clear")


def index_registries(paths) -> Dict[str, frozenset]:
    """name -> frozenset(member tokens) for registries that are a SINGLE static
    dict literal never mutated, rebound or aliased anywhere in the scanned tree.
    Anything else is left out, so the caller falls back to no narrowing
    (recall-first). ``paths`` may be files or directories.

    Trust is decided over ALL bindings of a name before any is accepted, so the
    verdict does not depend on file/walk order, and every form that could add a
    member the literal does not show — ``REG[k] = v``, ``REG.update(...)``,
    ``REG |= other`` (AugAssign), ``del``, ``REG = {**other}``, a computed key,
    an alias ``r = REG`` (which can be mutated through), a name also bound as a
    function parameter — marks it untrusted. Importing a registry is not a
    binding (it refers to the same object).

    Registries are keyed by bare name, not by module, so a name bound more than
    once anywhere in the scanned tree is untrusted even when the definitions
    agree: two modules defining ``REGISTRY`` are two different objects and this
    index cannot tell which one a wall reads. Erring this way costs precision
    (no narrowing), never recall."""
    literal: Dict[str, set] = {}     # name -> members of its single dict literal
    bindings: Dict[str, int] = {}    # name -> number of bindings seen
    untrusted = set()

    def bind(name):
        if name:
            bindings[name] = bindings.get(name, 0) + 1

    for py in _iter_py_files(paths):
        try:
            tree = ast.parse(open(py, encoding="utf-8", errors="replace").read())
        except Exception:
            continue
        for n in ast.walk(tree):
            # every binding form for a bare/attribute name
            if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                value = getattr(n, "value", None)
                for tgt in targets:
                    if isinstance(tgt, ast.Subscript):
                        name = _final(tgt.value)         # REG[k] = v
                        if name:
                            untrusted.add(name)
                        continue
                    if isinstance(tgt, (ast.Tuple, ast.List)):
                        for el in tgt.elts:              # a, REG = ...
                            nm = _final(el)
                            if nm:
                                untrusted.add(nm)
                        continue
                    name = _final(tgt)
                    if not name:
                        continue
                    bind(name)
                    if isinstance(n, ast.AugAssign):     # REG |= other
                        untrusted.add(name)
                    elif isinstance(value, ast.Dict):
                        toks, ok = _dict_member_tokens(value)
                        if not ok or (name in literal and literal[name] != toks):
                            untrusted.add(name)
                        else:
                            literal[name] = toks
                    else:
                        untrusted.add(name)              # non-literal binding
                    # aliasing: r = REG makes REG mutable through r
                    alias = _final(value) if isinstance(value, (ast.Name, ast.Attribute)) else None
                    if alias:
                        untrusted.add(alias)
            elif isinstance(n, ast.Delete):
                for tgt in n.targets:                    # del REG[k] / del REG
                    nm = _final(tgt.value) if isinstance(tgt, ast.Subscript) else _final(tgt)
                    if nm:
                        untrusted.add(nm)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = n.args
                for arg in (list(getattr(a, "posonlyargs", [])) + list(a.args) + list(a.kwonlyargs)
                            + [x for x in (a.vararg, a.kwarg) if x]):
                    untrusted.add(arg.arg)               # a parameter shadows the registry name
            elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                  and n.func.attr in _MUTATORS):
                name = _final(n.func.value)              # REG.update(...) / REG.pop(...)
                if name:
                    untrusted.add(name)

    return {k: frozenset(v) for k, v in literal.items()
            if k not in untrusted and v and bindings.get(k, 0) == 1}


def _iter_py_files(paths):
    """Yield each .py file under ``paths`` exactly once (paths may overlap —
    e.g. a candidate root that already contains the wall files; scanning a file
    twice would look like a rebinding and wrongly untrust its registries)."""
    if isinstance(paths, str):
        paths = [paths]
    seen = set()
    for p in paths:
        if os.path.isfile(p):
            real = os.path.realpath(p)
            if p.endswith(".py") and real not in seen:
                seen.add(real)
                yield p
            continue
        for root, _dirs, files in os.walk(p):
            if any(x in root.split(os.sep) for x in (".venv", "site-packages", "__pycache__")):
                continue
            for f in files:
                if not f.endswith(".py"):
                    continue
                full = os.path.join(root, f)
                real = os.path.realpath(full)
                if real not in seen:
                    seen.add(real)
                    yield full


# --------------------------------------------------------------------------- #
# Filters (UnreasonableLinksRemover analogue)
# --------------------------------------------------------------------------- #
def _call_shape(call: ast.Call):
    """(n_positional, keyword_names, has_star, has_double_star) of a call."""
    n_pos, has_star = 0, False
    for a in call.args:
        if isinstance(a, ast.Starred):
            has_star = True
        else:
            n_pos += 1
    kws, has_dstar = [], False
    for kw in call.keywords:
        if kw.arg is None:
            has_dstar = True
        else:
            kws.append(kw.arg)
    return n_pos, kws, has_star, has_dstar


def _signature_known(cand: Candidate) -> bool:
    """Whether ``cand``'s recorded signature is the one the wall would call.
    A record without any parameter information (an explicit spec/links entry
    written as ``{cls, name, module}``) says nothing; a def carrying decorators
    says nothing either, because the runtime callee is whatever the decorator
    returned (``@tool`` -> ``StructuredTool``, ``functools.wraps`` wrappers)."""
    if cand.decorated:
        return False
    if cand.origin == "explicit":
        return bool(cand.params or cand.kwonly or cand.has_kwargs or cand.has_varargs)
    return True


def arg_compat_reason(call: ast.Call, cand: Candidate, is_method_wall: bool = False) -> str:
    """'' if the wall's actual arguments could be accepted by ``cand``'s
    signature, else a short reason (the link is then ``unreasonable``: Python
    itself would raise TypeError, so ``cand`` cannot be the callee).

    The filter assumes **the wall calls the target with its own signature**.
    That holds for a direct dispatch (``REG[k](x)``, ``f = resolve(n); f(x)``)
    where the wall's callee *is* the target. It does not hold when the wall
    goes through a framework's dispatch method (``tool.run(x, verbose=...)``
    reaching ``_run``) or when the registered def is wrapped by a decorator —
    the arguments are consumed by the wrapper, so no comparison is possible and
    the link is kept (recall-first). Targets are always called bound (the
    emitter constructs the receiver), so positional slots start at the first
    real parameter. A ``*args`` splat hides the positional count."""
    if (cand.forward or is_method_wall or not _signature_known(cand)
            or cand.origin == "base_class"):
        return ""
    n_pos, kws, has_star, _has_dstar = _call_shape(call)
    slots = list(cand.params)
    if not has_star and n_pos > len(slots) and not cand.has_varargs:
        return f"{n_pos} positional args > {len(slots)} params of {cand.qualname}"
    if not cand.has_kwargs:
        accepted = set(slots) | set(cand.kwonly)
        bad = [k for k in kws if k not in accepted]
        if bad:
            return f"keyword(s) {bad} not accepted by {cand.qualname}"
    return ""


def _forwardable(node) -> bool:
    import dispatch_lowering as dl
    return dl._is_simple(node) or isinstance(node, ast.Constant)


def forward_args(call: ast.Call, cand: Candidate, scope_args: List[str]) -> List[str]:
    """The argument list to hand ``cand`` for this wall — the ``Intent``
    delivery of IccTA, made signature-aware:

      1. analyst-pinned ``cand.forward`` wins;
      2. the wall's own simple/literal arguments are forwarded verbatim
         (keywords only where the candidate accepts them);
      3. a ``**d`` (or ``*a``) splat — the typical ``command(**tool_call.arguments)``
         — is delivered to every parameter the wall did not fill explicitly
         (``code=d``, ``filename=d, args=d``, ...) and, when the candidate
         takes ``**kwargs``, also forwarded as ``**d``;
      4. if nothing could be forwarded, fall back to the enclosing scope's
         parameters/locals (recall-first; Pysa keeps the tainted ones).
    """
    if cand.forward:
        return list(cand.forward)
    known = _signature_known(cand)
    accepted = set(cand.params) | set(cand.kwonly)

    # positionals, keeping slot alignment: once a positional cannot be
    # forwarded (a call, a ternary, a splat), later ones must not slide into its
    # slot — pass them by parameter name if we know it, else drop them
    out, filled = [], set()
    aligned = True
    n_pos = 0                      # slots the wall's own positionals occupy
    for i, a in enumerate(call.args):
        if isinstance(a, ast.Starred):
            # a `*a` splat occupies an unknown number of slots; the remaining
            # parameters are filled from the splat below, so stop counting here
            aligned = False
            continue
        n_pos = i + 1
        if not _forwardable(a):
            aligned = False
            continue
        expr = ast.unparse(a)
        if aligned:
            out.append(expr)
            if i < len(cand.params):
                filled.add(cand.params[i])
        elif known and i < len(cand.params):
            out.append(f"{cand.params[i]}={expr}")
            filled.add(cand.params[i])

    for kw in call.keywords:
        if kw.arg is None or not _forwardable(kw.value):
            continue
        if cand.has_kwargs or not known or kw.arg in accepted:
            out.append(f"{kw.arg}={ast.unparse(kw.value)}")
            filled.add(kw.arg)

    star = [ast.unparse(a.value) for a in call.args if isinstance(a, ast.Starred) and _forwardable(a.value)]
    dstar = [ast.unparse(kw.value) for kw in call.keywords if kw.arg is None and _forwardable(kw.value)]
    if dstar or star:
        src = (dstar or star)[0]
        remaining = [p for p in cand.params[n_pos:] if p not in filled]
        remaining += [k for k in cand.kwonly if k not in filled]
        out += [f"{p}={src}" for p in remaining]
        if dstar and cand.has_kwargs:
            out.append(f"**{dstar[0]}")
    if out:
        return out
    return list(scope_args)


# --------------------------------------------------------------------------- #
# Link construction
# --------------------------------------------------------------------------- #
_CONFLICT = ("conflict", None, None)


def _lookup_binding(name, scope_chain, bindings):
    """Resolve ``name`` in the wall's own scope chain (innermost first, then
    module). Returns the binding or None — never a binding from an unrelated
    function that happens to reuse the name."""
    for scope in list(scope_chain) + [None]:
        b = bindings.get((id(scope) if scope is not None else None, name))
        if b is not None:
            return None if b is _CONFLICT else b
    return None


def _registry_of_call(call: ast.Call, scope_chain, bindings):
    """(registry_name, members) the wall reads, or (None, None).
    Subscript walls read it directly; higher-order walls through the local
    they were bound from (``f = REG[k]`` / ``f = a or b``)."""
    fn = call.func
    if isinstance(fn, ast.Subscript):
        return _final(fn.value), None
    name = None
    if isinstance(fn, ast.Name):
        name = fn.id
    # method wall on a runtime-bound receiver: ``t = REG[k]; t.run(x)`` / ``t = a or b; t.run(x)``
    elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
        name = fn.value.id
    if name:
        b = _lookup_binding(name, scope_chain, bindings)
        if b:
            _kind, reg, members = b
            return reg, members
    return None, None


def _runtime_bindings(tree):
    """(scope_id, name) -> (kind, registry, members) for locals bound to a
    runtime-selected value: ``f = REG[k]`` -> ('subscript', 'REG', None);
    ``f = a or b`` -> ('boolop', None, ['a', 'b']).

    Bindings are per binding scope (module or def), because narrowing FILTERS
    candidates: a module-wide, name-keyed map would let one function's
    ``f = SAFE[k]`` silently delete the true targets of another function's
    ``f = DANGER[k]``. A name bound from two different runtime sources within
    one scope resolves to ``_CONFLICT`` (no narrowing).

    A BoolOp is only usable for narrowing when EVERY alternative is statically
    known: ``f = get() or default`` (a call) and ``f = handler or default``
    where ``handler`` is a *parameter* both have an open alternative — the
    caller decides its value — so recording only ``default`` would filter out
    the real callee."""
    import dispatch_lowering as dl
    out = {}

    def record(scope_id, name, value, open_names):
        prev = out.get((scope_id, name))
        if isinstance(value, ast.Subscript):
            cur = ("subscript", _final(value.value), None)
        elif isinstance(value, ast.BoolOp):
            members = [_final(e) for e in value.values]
            if any(m is None or m in open_names for m in members):
                cur = _CONFLICT            # open alternative -> no narrowing
            else:
                cur = ("boolop", None, members)
        else:
            return
        out[(scope_id, name)] = cur if (prev is None or prev == cur) else _CONFLICT

    for body, scope in _scope_bodies_with_owner(tree):
        sid = id(scope) if scope is not None else None
        open_names = _param_names(scope)
        for node in dl._own_stmt_walk(body):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        record(sid, t.id, node.value, open_names)
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
                if isinstance(node.target, ast.Name):
                    record(sid, node.target.id, node.value, open_names)
    return out


def _param_names(scope) -> set:
    """Parameter names of ``scope`` — values its caller chooses, so a BoolOp
    alternative naming one is an open set, not a resolved target."""
    if scope is None:
        return set()
    a = scope.args
    names = {x.arg for x in list(getattr(a, "posonlyargs", [])) + list(a.args) + list(a.kwonlyargs)}
    for extra in (a.vararg, a.kwarg):
        if extra:
            names.add(extra.arg)
    return names


def _scope_bodies_with_owner(tree):
    """(statement list, owning def or None) for the module and every def —
    the same scopes ``dispatch_lowering._scope_bodies`` walks, but paired with
    the node that owns them so bindings can be keyed per scope."""
    yield getattr(tree, "body", []), None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield n.body, n


def _stmt_map(tree):
    """(stmts, chains) where ``stmts[id(Call)]`` is the innermost enclosing
    statement (the unit IccTA instruments after / removes; we anchor insertion
    on the whole statement so multi-line calls never get a block spliced into
    their argument list) and ``chains[id(stmt)]`` is the first line of the
    ``if``/``elif`` chain a statement heads, when it is an ``elif`` — inserting
    at the ``elif`` line would re-parent the rest of the chain."""
    stmts: Dict[int, ast.stmt] = {}
    chains: Dict[int, int] = {}

    def visit(node, stmt):
        if isinstance(node, ast.stmt):
            stmt = node
        if isinstance(node, ast.Call) and stmt is not None:
            stmts[id(node)] = stmt
        for child in ast.iter_child_nodes(node):
            visit(child, stmt)

    def chain(node, head_line):
        # ``elif`` is an If that is the sole element of the parent's orelse and
        # starts on a line the parent's body does not cover
        if isinstance(node, ast.If):
            chains[id(node)] = head_line
            if (len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If)
                    and node.orelse[0].col_offset == node.col_offset):
                chain(node.orelse[0], head_line)
                return
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.If):
                chain(child, child.lineno)
            else:
                chain(child, 0)

    visit(tree, None)
    for n in ast.walk(tree):
        if isinstance(n, ast.If) and id(n) not in chains:
            chain(n, n.lineno)
    return stmts, chains


def _idiom_of(call: ast.Call, sp, scope_chain, bindings) -> str:
    fn = call.func
    if isinstance(fn, ast.Subscript):
        return "subscript"
    if isinstance(fn, ast.Call) and isinstance(fn.func, ast.Name) and fn.func.id == "getattr":
        return "getattr"
    if isinstance(fn, ast.Name) and fn.id in sp.wall_param_names:
        return "param_call"
    if isinstance(fn, ast.Attribute) and fn.attr in sp.wall_attr_names:
        return "attr_call"
    if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
        return "method_call"
    if isinstance(fn, ast.Name):
        b = _lookup_binding(fn.id, scope_chain, bindings)
        if b and b[0] == "boolop":
            return "boolop"
    return "higher_order(hint)" if sp._legacy else "higher_order"


def build_links(source: str, wall_file: str, candidates, spec, *,
                registry_index: Optional[Dict[str, frozenset]] = None,
                id_offset: int = 0, id_prefix: str = ""):
    """Join walls in ``source`` with ``candidates`` into (walls, links, stats).

    Precision filters, in order (each decision is recorded on the link):
      1. registry narrowing — when the wall reads a *trusted* static registry
         (``registry_index``) or a BoolOp of named alternatives, keep only
         candidates whose name is a member (``match_level`` 1). Disabled in
         legacy mode and by ``spec.narrow=False``.
      2. argument compatibility — drop candidates whose signature cannot
         accept the wall's actual arguments (``status='unreasonable'``).
    """
    import dispatch_lowering as dl   # local import: dispatch_lowering imports us lazily too

    sp = dl._coerce_spec(spec)
    cands = coerce_candidates(candidates)
    tree = ast.parse(source)
    walls_ast, chain = dl.find_walls_with_scope(tree, sp)
    assign_map = dl._build_assign_map(tree)
    bindings = _runtime_bindings(tree)
    stmts, chains = _stmt_map(tree)
    registry_index = registry_index or {}
    base = os.path.basename(wall_file) if wall_file else "<source>"

    stats = LoweringStats(files=1, candidates_total=len(cands))
    walls: List[WallRecord] = []
    links: List[DispatchLink] = []
    wid = id_offset
    lid = 0
    for call in walls_ast:
        is_method_wall = (isinstance(call.func, ast.Attribute)
                          and isinstance(call.func.value, ast.Name))
        func_nodes = chain.get(id(call)) or []
        # recall-first fallback list (see forward_args step 4): every parameter
        # and local of the enclosing scope chain, minus the enclosing method's
        # own receiver, which is never an argument of the dispatched call
        scope_args = dl._scope_taint_sources(func_nodes) if func_nodes else []
        if scope_args and scope_args[0] in ("self", "cls"):
            scope_args = scope_args[1:]
        # what the wall itself hands over (display / hand-written links); the
        # per-link list is signature-aware (forward_args)
        taint_args = dl._taint_args(call) or scope_args
        idiom = _idiom_of(call, sp, func_nodes, bindings)
        reg, members = _registry_of_call(call, func_nodes, bindings)
        st = stmts.get(id(call))
        w = WallRecord(
            id=f"{id_prefix}W{wid}", file=base, line=call.lineno,
            end_line=(call.end_lineno or call.lineno), idiom=idiom,
            callee=ast.unparse(call.func),
            stmt_line=(st.lineno if st is not None else call.lineno),
            stmt_end_line=((st.end_lineno or st.lineno) if st is not None else (call.end_lineno or call.lineno)),
            stmt_kind=(type(st).__name__ if st is not None else ""),
            chain_line=(chains.get(id(st), 0) if st is not None
                        and chains.get(id(st), 0) not in (0, st.lineno) else 0),
            registry=reg, members=members,
            assign_target=assign_map.get(id(call)), is_method_wall=is_method_wall,
            in_async=bool(func_nodes) and isinstance(func_nodes[0], ast.AsyncFunctionDef),
            taint_args=list(taint_args),
        )
        wid += 1
        stats.walls_detected += 1
        stats.walls_by_idiom[idiom] = stats.walls_by_idiom.get(idiom, 0) + 1

        # 1. registry narrowing
        narrow_to: Optional[frozenset] = None
        narrow_src = ""
        if not sp._legacy and sp.narrow:
            if members:
                narrow_to, narrow_src = frozenset(members), "boolop"
            elif reg and reg in registry_index:
                narrow_to, narrow_src = registry_index[reg], f"registry {reg}"
        if narrow_to is not None:
            w.members = sorted(narrow_to)

        for c in cands:
            args = forward_args(call, c, scope_args)
            link = DispatchLink(id=f"{id_prefix}L{id_offset + lid}", wall_id=w.id, file=base,
                                line=call.lineno, target=c, match_level=c.match_level,
                                taint_args=args)
            lid += 1
            stats.links_built += 1
            if narrow_to is not None:
                if c.name in narrow_to or c.qualname in narrow_to or (c.cls and c.cls in narrow_to):
                    link.match_level = 1
                else:
                    link.status = "filtered_registry"
                    link.reason = f"{c.qualname} not a member of {narrow_src}"
                    stats.links_filtered_registry += 1
                    links.append(link)
                    continue
            if sp.filter_unreasonable:
                why = arg_compat_reason(call, c, is_method_wall)
                if why:
                    link.status, link.reason = "unreasonable", why
                    stats.links_unreasonable += 1
                    links.append(link)
                    continue
            # the level cap grades the LINK: narrowing above may have promoted a
            # decorator/scan-all candidate to level 1 (a member of the registry
            # this wall actually reads)
            if link.match_level > sp.match_level:
                link.status = "filtered_level"
                link.reason = f"match_level {link.match_level} > allowed {sp.match_level}"
                stats.links_filtered_level += 1
                links.append(link)
                continue
            if not args:
                # nothing at all could be handed to this target (no wall argument,
                # no splat, empty scope) — recorded, not silently dropped
                link.status, link.reason = "no_args", "no argument expression to forward"
                stats.links_no_args += 1
                links.append(link)
                continue
            stats.links_lowered += 1
            links.append(link)
        mine = [l for l in links if l.wall_id == w.id]
        if not any(l.status == "lowered" for l in mine):
            if mine and all(l.status == "no_args" for l in mine):
                w.status, w.reason = "skipped_no_args", "no argument expression to forward"
                stats.walls_skipped_no_args += 1
            else:
                w.status, w.reason = "unresolved", (
                    "no candidate to link" if not mine else "no candidate survived the filters")
        walls.append(w)
    return walls, links, stats


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
def dump_links(path: str, walls: List[WallRecord], links: List[DispatchLink],
               stats: Optional[LoweringStats] = None) -> None:
    data = {
        "walls": [asdict(w) for w in walls],
        "links": [asdict(l) for l in links],
    }
    if stats is not None:
        data["stats"] = stats.to_dict()
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_links(path: str) -> Tuple[List[WallRecord], List[DispatchLink]]:
    """Read a links file (auto-generated or hand-written — the IccTA
    ``IccLinksConfigFile`` analogue). Hand-written files may omit ``walls``;
    each link then needs ``file``, ``line`` and ``target``."""
    data = json.load(open(path))
    walls = [WallRecord(**w) for w in data.get("walls", [])]
    links = []
    for i, l in enumerate(data.get("links", [])):
        l = dict(l)
        if "line" not in l:
            raise ValueError(f"link {i} in {path}: 'line' is required (the wall's line)")
        l["target"] = Candidate.from_any(l["target"])
        l.setdefault("id", f"L{i}")
        l.setdefault("wall_id", "")
        l.setdefault("file", "")        # omitted = applies to every wall file
        l.setdefault("status", "lowered")
        known = {k: v for k, v in l.items() if k in DispatchLink.__dataclass_fields__}
        links.append(DispatchLink(**known))
    return walls, links
