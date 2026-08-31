"""anchoring — registry anchoring, the AST-side complement of engine_walls.

IccTA's *explicit* Intent: the call site names its own destination set. The
Python analogue is a registry whose members are visible in the source:

  * a dict / list literal whose values resolve to defs or classes
        REGISTRY = {"shell": run_shell, "echo": echo}
        TOOLS = [Tool(func=a), b]
  * an attribute assigned a def (vanna: ``self.run_sql = run_sql_sqlite``
    inside ``connect_to_sqlite``, once per backend)
  * a registration call        ``mcp.add_tool(fn)`` / ``registry.register(fn)``
  * a comprehension / mutated registry — an anchor whose member set is *open*
    (``self.tool_map = {t.name: t for t in tools}``, ``self.tools[t.name] = t``)

The reads of an anchor (``A[k](...)``, ``A.get(k)(...)``, ``t = A[k]; t.run(x)``,
``for t in A: t.run(x)``, ``self.attr(...)``) are wall candidates. What the
anchor adds over the engine-driven rows:

  * **candidates** for a wall the engine already flagged: the anchor's members
    are level-1 candidates of that wall (narrowing, when the anchor is closed);
  * **rows** the engine did not flag: a read the engine resolved (a typed
    registry) is listed as ``proposed`` (off by default — the engine carries
    taint there), a read with no engine information likewise;
  * **evidence** lines (``file:line  self.run_sql = run_sql_sqlite``) so a
    reviewer can reject an anchor by name (provider maps, logging callbacks).

Nothing here is a value analysis. Anchors are keyed by their defining module —
``pkg.mod.REGISTRY`` / ``pkg.mod.Cls.attr`` (re-exports are followed to the
defining module) — and an anchor is *closed* (its members may narrow a wall's
candidate set) only when all of the following hold over the whole tree, as
checked here (review C6):

  * every member resolves to a def / class / instance visible in the source
    (no ``**other`` / ``*other`` unpacking, no comprehension, no registration
    of a runtime value);
  * a bare-name anchor is bound once at module level (``NAME = ...`` twice
    -> open), and nothing mutates it in any scope of the tree — module body,
    class body or function body (a name the function binds itself is a local
    and does not count): ``NAME[k] = v`` / ``del NAME[k]`` / ``NAME += ...`` /
    ``NAME |= ...`` / ``.update() .pop() .append() ...``, whether written
    through the module's own name, through ``from X import NAME`` / ``import
    X as Y`` in another module, through a module-level alias ``ALIAS = NAME``
    (an alias is itself an open reason), or through ``global NAME``;
  * for ``Cls.attr``: no ``self.attr = <anything but a def / class / instance>``
    (parameter, call, attribute, constant, empty literal, BoolOp, IfExp ...)
    — written as ``self.attr = v``, ``setattr(self, "attr", v)``,
    ``object.__setattr__(self, "attr", v)`` or ``self.__dict__["attr"] = v``
    — no ``setattr(self, <expr>, v)`` / ``self.__dict__[<expr>] = v`` (any
    attribute may be rebound), no ``Cls.attr = v`` written outside the class,
    and no ``self.attr[k] = v`` / ``self.attr |= ...`` in a method of the
    class, no class-body ``attr = ...`` / ``attr: T [= ...]`` in the class or
    its in-tree bases, and no in-tree subclass that assigns or declares
    ``attr``. A nested class is keyed ``module.Outer.Inner.attr`` — it never
    shares a key with a top-level class of the same name.

A read is joined to an anchor by name resolved through the reader module's own
bindings and imports — a name the enclosing function (or the class body the
read sits in) binds itself is a local and joins nothing, even when a module
registry has the same name; a ``self.attr`` read joins ``module.Cls.attr`` of the
reader's own class exactly, or — when the reader class is a transitive in-tree
subclass of exactly one anchor's class and does not bind ``attr`` itself — as an
*inherited* read that carries the members as candidates but is never closed
(``AnchorRead.anchor_closed`` is False and ``by_position`` hands the consumer
an open view of the anchor: candidates may be added, never narrowed, and the
read is never confirmed by the anchor). Any other ``self.attr`` read has no
anchor.

    python3 anchoring.py <src_root> [--engine <cond_A>] [--reject NAME ...] [--json]
"""
from __future__ import annotations

import argparse
import ast
import collections
import json
import os
import sys
from dataclasses import dataclass, field, asdict, replace
from typing import Dict, List, Optional, Set, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import dispatch_lowering as dl   # noqa: E402
import engine_walls as EW        # noqa: E402
import links as L                # noqa: E402

DEFAULT_REGISTER_METHODS = ("register", "register_function", "register_tool", "add_tool",
                            "add_function", "add_tools", "add_plugin", "add")
_MUTATORS = ("update", "setdefault", "pop", "popitem", "clear", "append", "extend", "insert", "remove")
_SKIP_DIRS = (".venv", "site-packages", "__pycache__", "tests", "test")
_REGISTER_KW = ("func", "fn", "function", "tool", "callback")
_LITERALS = (ast.Dict, ast.List, ast.Tuple, ast.Set, ast.DictComp, ast.ListComp)
_AUG_OPS = {ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.BitOr: "|", ast.BitAnd: "&", ast.BitXor: "^"}


# --------------------------------------------------------------------------- #
# records
# --------------------------------------------------------------------------- #
@dataclass
class AnchorMember:
    kind: str                       # def | class | instance | unknown
    name: str                       # def name / class name
    module: str = ""
    path: str = ""
    lineno: int = 0
    key: str = ""                   # dict key when literal
    importable: bool = True
    evidence: str = ""
    candidate: Optional[dict] = None    # links.Candidate dict for def members


@dataclass
class AnchorRead:
    file: str                       # relative to src_root (posix)
    line: int
    col: int
    end_line: int
    end_col: int
    callee: str
    idiom: str                      # subscript | get | method_call | loop_method | attr_call | higher_order
    key_expr: str = ""
    method: str = ""                # method called on the member (t.run -> run)
    callable: str = ""              # enclosing qualname (Class.method)
    anchor: str = ""
    engine_status: str = ""         # from engine_walls when available ('' = no site)
    confidence: str = "proposed"
    accept: bool = False
    note: str = ""
    candidates: List[dict] = field(default_factory=list)   # Candidate dicts for THIS read
    # review C6: how the read was bound to the anchor — 'exact' (same name /
    # import / own class) or 'inherited' (self.<attr> from a subclass of the
    # anchor's class); only an exact read of a closed anchor may narrow
    binding: str = "exact"
    anchor_closed: bool = False

    @property
    def position(self) -> str:
        return f"{self.file}:{self.line}:{self.col}"


@dataclass
class Anchor:
    name: str                       # module-qualified: pkg.mod.REGISTRY | pkg.mod.Agent.tools | pkg.mod.VannaBase.run_sql
    kind: str                       # dict_literal | list_literal | attr_assign | register_call | subscript_assign | comprehension
    file: str
    line: int
    module: str = ""
    short: str = ""                 # REGISTRY | Agent.tools (display, --reject)   (review C6)
    members: List[AnchorMember] = field(default_factory=list)
    open: bool = False
    open_reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    reads: List[AnchorRead] = field(default_factory=list)
    rejected: bool = False

    @property
    def closed(self) -> bool:
        return not self.open and bool(self.members) and all(m.kind != "unknown" for m in self.members)

    def member_candidates(self, method: str = "") -> List[dict]:
        """Candidate dicts the reads dispatch to: def members as they are,
        class / instance members as ``Cls.<method>`` when a method is named."""
        out = []
        for m in self.members:
            if m.kind == "def" and m.candidate:
                out.append(dict(m.candidate))
            elif m.kind in ("class", "instance") and method:
                out.append({"cls": m.name, "name": method, "module": m.module, "path": m.path,
                            "origin": "anchor", "match_level": 1, "importable": m.importable,
                            "evidence": m.evidence})
        return out


@dataclass
class AnchoringResult:
    src_root: str
    anchors: List[Anchor]
    by_position: Dict[Tuple[str, int, int], Tuple[Anchor, AnchorRead]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"src_root": self.src_root,
                "anchors": [dict(asdict(a), closed=a.closed, reads=[dict(asdict(r), position=r.position) for r in a.reads])
                            for a in self.anchors],
                "counts": {"anchors": len(self.anchors), "closed": sum(1 for a in self.anchors if a.closed),
                           "rejected": sum(1 for a in self.anchors if a.rejected),
                           "reads": sum(len(a.reads) for a in self.anchors)}}


# --------------------------------------------------------------------------- #
# per-file scan
# --------------------------------------------------------------------------- #
def _target_names(t) -> List[str]:
    """Bare names an assignment target binds (Name, or Names inside a Tuple /
    List / Starred unpacking)."""
    if isinstance(t, ast.Name):
        return [t.id]
    if isinstance(t, ast.Starred):
        return _target_names(t.value)
    if isinstance(t, (ast.Tuple, ast.List)):
        out: List[str] = []
        for e in t.elts:
            out += _target_names(e)
        return out
    return []


class _ModuleScan:
    """Defs, classes, imports, module-level bindings / aliases, class bases and
    the enclosing-class map of one file. Imports are stored with their
    *absolute* module (relative imports resolved against the module path —
    review C6) and whether the imported module exists under ``src_root``."""

    def __init__(self, path: str, src_root: str, tree: ast.AST):
        self.path, self.tree = path, tree
        self.src_root = src_root
        self.rel = os.path.relpath(path, src_root).replace(os.sep, "/")
        self.module = L.module_of(path, src_root)
        self.is_pkg = os.path.basename(path) == "__init__.py"
        self.defs: Dict[str, ast.AST] = {}
        self.classes: Dict[str, ast.ClassDef] = {}
        self.imports: Dict[str, Tuple[str, str]] = {}      # local name -> (module, name)
        self.import_ok: Dict[str, bool] = {}                # local name -> resolved file exists under src_root
        self.mod_imports: Dict[str, str] = {}               # local name -> module bound by ``import a.b [as X]``
        self.assigns: Set[str] = set()                      # names bound at module level by assignment
        self.aliases: Dict[str, Tuple[str, str]] = {}       # module-level ``X = NAME`` -> (qualified NAME, evidence)
        self.owner: Dict[int, Optional[ast.ClassDef]] = {}   # id(def) -> enclosing class
        self.functions: List[Tuple[ast.AST, Optional[ast.ClassDef]]] = []
        self.all_classes: List[ast.ClassDef] = []
        # review C6 (repair): classes are keyed by their local qualname
        # (``Outer.Inner``), so a nested class never shares a key with a
        # top-level class of the same name
        self.class_local: Dict[int, str] = {}               # id(ClassDef) -> local qualname
        self.bases: Dict[str, List[str]] = {}               # class local qualname -> base qualnames ('?<expr>' when unresolvable)
        self.class_decl: Dict[str, Dict[str, str]] = {}     # class local qualname -> {attr: evidence} (class-body Assign / AnnAssign)
        self.self_assigned: Dict[str, Set[str]] = {}        # class local qualname -> attrs bound by ``self.<attr> = ...`` / setattr in its methods
        self.dyn_setattr: Dict[str, str] = {}               # class local qualname -> evidence of ``setattr(self, <expr>, v)`` (any attr may be rebound)
        self.fn_bound: Dict[Tuple[int, int], Set[str]] = {}  # (def line, col) -> names bound by value / loop in that body
        self.fn_local: Dict[Tuple[int, int], Set[str]] = {}  # (def line, col) -> every local name of that body (params, imports, defs ...)
        self.fn_global: Dict[Tuple[int, int], Set[str]] = {}  # (def line, col) -> names it declares ``global``
        self.module_bound: Optional[Set[str]] = None         # the same for the module body
        self._indexed = False
        # the module's read sites, described once from the tree (review minor:
        # find_reads re-parse); None until ``index_reads``
        self.read_sites: Optional[List["_ReadSite"]] = None
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.defs[node.name] = node
            elif isinstance(node, ast.ClassDef):
                self.classes[node.name] = node
            elif isinstance(node, ast.ImportFrom):
                mod, ok = self._resolve_from(node)
                for a in node.names:
                    self.imports[a.asname or a.name] = (mod, a.name)
                    self.import_ok[a.asname or a.name] = ok
            elif isinstance(node, ast.Import):
                for a in node.names:
                    local = a.asname or a.name.split(".")[0]
                    self.imports[local] = (a.name, "")
                    self.import_ok[local] = True
                    self.mod_imports[local] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    self.assigns.update(_target_names(t))
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                self.assigns.update(_target_names(node.target))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for it in node.items:
                    if it.optional_vars is not None:
                        self.assigns.update(_target_names(it.optional_vars))
        # module-level aliases ``X = NAME`` / ``X = mod.NAME`` (review C6)
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.value, (ast.Name, ast.Attribute)) \
                    and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                target = self.qualify(node.value)
                own = self.qualify_name(node.targets[0].id, follow_alias=False)
                if target and target != own:
                    self.aliases[node.targets[0].id] = (target, f"{self.rel}:{node.lineno} {ast.unparse(node)[:50]}")

        def walk(node, cls, chain):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    self.all_classes.append(child)
                    self.class_local[id(child)] = ".".join(chain + [child.name])
                    self._index_class(child)
                    walk(child, child, chain + [child.name])
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.owner[id(child)] = cls
                    self.functions.append((child, cls))
                    walk(child, None if cls is None else cls, chain)
                else:
                    walk(child, cls, chain)
        walk(tree, None, [])

    # -- imports / qualification ------------------------------------------ #
    def _module_exists(self, mod: str) -> bool:
        p = os.path.join(self.src_root, *mod.split("."))
        return os.path.isfile(p + ".py") or os.path.isfile(os.path.join(p, "__init__.py"))

    def _resolve_from(self, node: ast.ImportFrom) -> Tuple[str, bool]:
        """(absolute module, exists under src_root) of a ``from`` import. An
        absolute import is taken as importable (tree or venv); a relative one
        is resolved against this module (``node.level``) and marked
        non-importable when it climbs above src_root or the file is missing."""
        if not node.level:
            return node.module or "", True
        parts = self.module.split(".") if self.module else []
        if not self.is_pkg:
            parts = parts[:-1]
        up = node.level - 1
        if up > len(parts):
            return ("." * node.level) + (node.module or ""), False
        parts = parts[: len(parts) - up] if up else parts
        if node.module:
            parts = parts + node.module.split(".")
        mod = ".".join(parts)
        return mod, bool(mod) and self._module_exists(mod)

    def _q(self, name: str) -> str:
        return f"{self.module}.{name}" if self.module else name

    def qualify_name(self, name: str, follow_alias: bool = True) -> str:
        """Module-qualified key of a bare name as seen from this module: an
        alias -> its target, a name bound here -> ``module.name``, an imported
        name -> ``X.name`` (``import a.b as X`` -> ``a.b``), else ``module.name``."""
        if follow_alias and name in self.aliases:
            return self.aliases[name][0]
        if name in self.assigns or name in self.defs or name in self.classes:
            return self._q(name)
        if name in self.imports:
            mod, nm = self.imports[name]
            if nm:
                return f"{mod}.{nm}" if mod else nm
            return self.mod_imports.get(name, mod)
        return self._q(name)

    def qualify(self, node, cls: Optional[ast.ClassDef] = None) -> str:
        """Qualified key of a Name / Attribute expression; ``self.attr`` inside
        ``cls`` -> ``module.Cls.attr``; '' when the expression is not a name."""
        if isinstance(node, ast.Name):
            return self.qualify_name(node.id)
        if isinstance(node, ast.Attribute):
            chain: List[str] = []
            root = node
            while isinstance(root, ast.Attribute):
                chain.insert(0, root.attr)
                root = root.value
            if not isinstance(root, ast.Name):
                return ""
            if root.id in ("self", "cls"):
                if cls is None or len(chain) != 1:
                    return ""
                return f"{self.class_q(cls)}.{chain[0]}"
            if root.id in self.mod_imports:
                return ".".join([self.mod_imports[root.id]] + chain)
            return ".".join([self.qualify_name(root.id)] + chain)
        return ""

    def qualify_dotted(self, text: str) -> str:
        try:
            node = ast.parse(text, mode="eval").body
        except Exception:
            return ""
        return self.qualify(node)

    def local_name(self, cls) -> str:
        """Local qualname of a class (``Outer.Inner``) from its ClassDef node,
        or an already-local name unchanged (review C6 repair)."""
        if isinstance(cls, ast.ClassDef):
            return self.class_local.get(id(cls), cls.name)
        return cls

    def class_q(self, cls) -> str:
        return self._q(self.local_name(cls))

    # -- class hierarchy / attribute declarations (review C6) --------------- #
    def _resolve_base(self, b) -> str:
        if isinstance(b, ast.Subscript):          # Generic[T] -> Generic
            b = b.value
        if isinstance(b, ast.Name):
            if b.id in self.classes:
                return self._q(b.id)
            if b.id in self.imports and self.imports[b.id][1]:
                mod, nm = self.imports[b.id]
                return f"{mod}.{nm}" if mod else nm
            return "?" + b.id
        if isinstance(b, ast.Attribute):
            q = self.qualify(b)
            return q if q else "?" + ast.unparse(b)
        return "?" + ast.unparse(b)[:30]

    def _index_class(self, cls: ast.ClassDef) -> None:
        local = self.local_name(cls)
        self.bases[local] = [self._resolve_base(b) for b in cls.bases]
        decl = self.class_decl.setdefault(local, {})
        for st in cls.body:
            if isinstance(st, ast.Assign):
                for t in st.targets:
                    for n in _target_names(t):
                        decl.setdefault(n, f"{self.rel}:{st.lineno} {ast.unparse(st)[:50]}")
            elif isinstance(st, (ast.AnnAssign, ast.AugAssign)) and isinstance(st.target, ast.Name):
                decl.setdefault(st.target.id, f"{self.rel}:{st.lineno} {ast.unparse(st)[:50]}")

    def index_scope(self, nodes: list, fn, cls: Optional[ast.ClassDef]) -> None:
        """Per-scope facts from one materialised ``_own_stmt_walk`` of a body:
        the names bound by value / loop (read pre-filter) and, for a method,
        the attributes it binds through ``self.<attr> = ...``."""
        bound = _value_bound_names(nodes)
        if fn is None:
            self.module_bound = bound
            return
        key = (fn.lineno, fn.col_offset)
        self.fn_bound[key] = bound
        self.fn_local[key], self.fn_global[key] = _local_names(fn, nodes)
        if cls is None:
            return
        local = self.local_name(cls)
        got = self.self_assigned.setdefault(local, set())
        for node in nodes:
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    a = _self_attr(t) or _self_dict_attr(t)
                    if a:
                        got.add(a)
                    elif _self_dict_attr(t, dynamic=True):
                        self.dyn_setattr.setdefault(local, f"{self.rel}:{node.lineno} {ast.unparse(t)} = ...")
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                a = _self_attr(node.target)
                if a:
                    got.add(a)
            elif isinstance(node, ast.Call):
                # review C6 repair: setattr(self, "attr", v) binds like ``self.attr = v``;
                # setattr(self, <expr>, v) may bind any attribute of the class
                sa = _setattr_call(node)
                if sa is not None:
                    if sa[0]:
                        got.add(sa[0])
                    else:
                        self.dyn_setattr.setdefault(local, f"{self.rel}:{node.lineno} {ast.unparse(node)[:50]}")

    def index_all(self) -> None:
        """Index every scope (when ``find_anchors`` did not do it inline)."""
        if self._indexed or self.tree is None:
            return
        self.index_scope(list(dl._own_stmt_walk(self.tree.body)), None, None)
        for fn, cls in self.functions:
            self.index_scope(list(dl._own_stmt_walk(fn.body)), fn, cls)
        self._indexed = True

    def index_reads(self) -> None:
        """Describe the module's read sites (``read_sites``) from its tree —
        once, while the tree is still held, so ``find_reads`` never parses
        the file again (review minor: find_reads re-parse)."""
        if self.read_sites is not None or self.tree is None:
            return
        self.index_all()
        self.read_sites = _read_sites(self, self.tree)

    # -- members ----------------------------------------------------------- #
    def resolve_value(self, v, local_defs: Dict[str, ast.AST], key: str = "") -> AnchorMember:
        """A registry value as a member: def / class / instance / unknown."""
        if isinstance(v, ast.Call) and isinstance(v.func, ast.Name):
            m = self.resolve_value(v.func, local_defs, key)
            if m.kind == "class":
                m.kind = "instance"
            return m
        if isinstance(v, ast.Call):
            # wrapper ctor: Tool(func=fn) / StructuredTool.from_function(fn)
            for kw in v.keywords:
                if kw.arg in ("func", "fn", "function", "coroutine", "callback"):
                    return self.resolve_value(kw.value, local_defs, key)
            if v.args:
                inner = self.resolve_value(v.args[0], local_defs, key)
                if inner.kind != "unknown":
                    return inner
            return AnchorMember("unknown", ast.unparse(v)[:40], key=key)
        if isinstance(v, ast.Name):
            n = v.id
            if n in local_defs:
                fn = local_defs[n]
                c = L.Candidate.from_def(fn, None, self.module, self.path, origin="anchor", match_level=1)
                c.importable = False
                c.evidence = f"nested def {self.rel}:{fn.lineno}"
                return AnchorMember("def", n, self.module, self.path, fn.lineno, key, False,
                                    f"{self.rel}:{fn.lineno} def {n} (nested)", asdict(c))
            if n in self.defs:
                fn = self.defs[n]
                c = L.Candidate.from_def(fn, None, self.module, self.path, origin="anchor", match_level=1)
                c.evidence = f"def {self.rel}:{fn.lineno}"
                return AnchorMember("def", n, self.module, self.path, fn.lineno, key, True,
                                    f"{self.rel}:{fn.lineno} def {n}", asdict(c))
            if n in self.classes:
                cls = self.classes[n]
                return AnchorMember("class", n, self.module, self.path, cls.lineno, key, True,
                                    f"{self.rel}:{cls.lineno} class {n}")
            if n in self.imports:
                mod, name = self.imports[n]
                if name:
                    # review C6: ``mod`` is the resolved absolute module of a
                    # relative import; a target outside src_root is not importable
                    ok = self.import_ok.get(n, True)
                    c = L.Candidate(cls=None, name=name, module=mod, origin="anchor", match_level=1,
                                    evidence=f"imported from {mod}" + ("" if ok else " (not under src_root)"))
                    c.importable = ok
                    # an imported CapWord is most likely a class
                    kind = "class" if name[:1].isupper() else "def"
                    return AnchorMember(kind, name, mod, "", 0, key, ok,
                                        f"{self.rel}: from {mod} import {name}", asdict(c) if kind == "def" else None)
            return AnchorMember("unknown", n, key=key)
        if isinstance(v, ast.Attribute):
            root = v
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in self.imports and not self.imports[root.id][1]:
                mod = self.imports[root.id][0]
                parts = ast.unparse(v).split(".")[1:]
                if len(parts) == 1:
                    c = L.Candidate(cls=None, name=parts[0], module=mod, origin="anchor", match_level=1,
                                    evidence=f"{mod}.{parts[0]}")
                    return AnchorMember("def", parts[0], mod, "", 0, key, True, f"{self.rel}: {mod}.{parts[0]}", asdict(c))
            return AnchorMember("unknown", ast.unparse(v)[:40], key=key)
        return AnchorMember("unknown", ast.unparse(v)[:40] if hasattr(ast, "unparse") else "?", key=key)


class _TreeIndex:
    """Per-module scans (without their trees) and the class hierarchy of the
    whole tree — what ``find_reads`` needs to resolve a read's name and a
    ``self.<attr>`` read's class (review C6)."""

    def __init__(self, src_root: str):
        self.src_root = os.path.abspath(src_root)
        self.scans: Dict[str, _ModuleScan] = {}               # path -> scan (tree dropped)
        self.by_module: Dict[str, _ModuleScan] = {}
        self.bases: Dict[str, List[str]] = {}                  # class qualname -> base qualnames
        self.children: Dict[str, Set[str]] = collections.defaultdict(set)
        self.decl: Dict[str, Dict[str, str]] = {}              # class qualname -> {attr: evidence}
        self.self_assigned: Dict[str, Set[str]] = {}           # class qualname -> attrs bound via self.<attr> = ...
        self.dyn_setattr: Dict[str, str] = {}                  # class qualname -> setattr(self, <expr>, v) evidence (review C6 repair)

    def add(self, scan: _ModuleScan) -> None:
        self.scans[scan.path] = scan
        self.by_module[scan.module] = scan
        for cname, bases in scan.bases.items():
            q = scan.class_q(cname)
            self.bases[q] = bases
            for b in bases:
                if not b.startswith("?"):
                    self.children[b].add(q)
            self.decl[q] = scan.class_decl.get(cname, {})
            self.self_assigned[q] = scan.self_assigned.get(cname, set())
            if cname in scan.dyn_setattr:
                self.dyn_setattr[q] = scan.dyn_setattr[cname]

    def ancestors(self, q: str) -> List[str]:
        """Transitive in-tree ancestors of class ``q`` (unresolvable / outside
        bases end the walk — the relationship through them is unknown)."""
        out, seen, todo = [], {q}, list(self.bases.get(q, []))
        while todo:
            b = todo.pop(0)
            if b in seen or b.startswith("?") or b not in self.bases:
                continue
            seen.add(b)
            out.append(b)
            todo += self.bases[b]
        return out

    def descendants(self, q: str) -> List[str]:
        out, seen, todo = [], {q}, list(self.children.get(q, ()))
        while todo:
            c = todo.pop(0)
            if c in seen:
                continue
            seen.add(c)
            out.append(c)
            todo += list(self.children.get(c, ()))
        return out

    def split(self, q: str) -> Tuple[Optional[str], str, str]:
        """(longest in-tree module prefix, next name, '.rest') of a key;
        (None, '', '') when no prefix is a module of the tree."""
        parts = q.split(".")
        for i in range(len(parts) - 1, 0, -1):
            mod = ".".join(parts[:i])
            if mod in self.by_module:
                return mod, parts[i], ("." + ".".join(parts[i + 1:]) if len(parts) > i + 1 else "")
        return None, "", ""

    def in_tree(self, q: str) -> bool:
        return self.split(q)[0] is not None

    def canonical(self, q: str) -> str:
        """Follow re-exports: ``a.b.NAME`` where module ``a.b`` binds NAME only
        by ``from c.d import NAME`` (or ``import c.d as NAME``) -> ``c.d.NAME``
        (review C6: the key of a registry is its defining module)."""
        for _ in range(6):
            mod, name, rest = self.split(q)
            if mod is None:
                return q
            scan = self.by_module[mod]
            if name in scan.assigns or name in scan.defs or name in scan.classes:
                return q
            if name in scan.imports and scan.imports[name][1]:
                m, n = scan.imports[name]
                nq = (f"{m}.{n}" if m else n) + rest
            elif name in scan.mod_imports:
                nq = scan.mod_imports[name] + rest
            else:
                return q
            if nq == q:
                return q
            q = nq
        return q

    def binds(self, cls_q: str, attr: str) -> str:
        """Evidence when class ``cls_q`` itself binds ``attr`` (class body or
        ``self.attr = ...`` in a method), else ''."""
        if attr in self.decl.get(cls_q, {}):
            return self.decl[cls_q][attr]
        if attr in self.self_assigned.get(cls_q, set()):
            return f"self.{attr} assigned in {cls_q}"
        if cls_q in self.dyn_setattr:
            return f"dynamic setattr in {cls_q}: {self.dyn_setattr[cls_q]}"
        return ""


def _iter_files(src_root: str, exclude_paths=()):
    for root, dirs, files in os.walk(src_root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)      # deterministic order (review C6 repair)
        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            p = os.path.join(root, f)
            if any(x and x in p for x in exclude_paths):
                continue
            try:
                src = open(p, encoding="utf-8", errors="replace").read()
                yield p, ast.parse(src)
            except Exception:
                continue


def _self_attr(node) -> Optional[str]:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in ("self", "cls"):
        return node.attr
    return None


def _self_dict_attr(node, dynamic: bool = False):
    """``self.__dict__["attr"]`` as an assignment target -> 'attr' (None
    otherwise); with ``dynamic`` True: whether the target is
    ``self.__dict__[<non-constant>]`` (review C6 repair: a rebinding)."""
    if not (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute)
            and node.value.attr == "__dict__" and isinstance(node.value.value, ast.Name)
            and node.value.value.id in ("self", "cls")):
        return False if dynamic else None
    const = isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str)
    if dynamic:
        return not const
    return node.slice.value if const else None


def _setattr_call(node) -> Optional[Tuple[Optional[str], ast.AST]]:
    """``setattr(self, "attr", v)`` / ``object.__setattr__(self, "attr", v)``
    / ``super().__setattr__("attr", v)`` / ``self.__setattr__("attr", v)``
    -> ('attr', v); (None, v) when the
    attribute name is not a string constant; None when the call is not a
    setattr on self / cls (review C6 repair: these rebind like
    ``self.attr = v``)."""
    if not isinstance(node, ast.Call):
        return None
    f = node.func
    args = list(node.args)
    if isinstance(f, ast.Name) and f.id == "setattr":
        pass
    elif isinstance(f, ast.Attribute) and f.attr == "__setattr__":
        if (isinstance(f.value, ast.Call) and isinstance(f.value.func, ast.Name) and f.value.func.id == "super") \
                or (isinstance(f.value, ast.Name) and f.value.id in ("self", "cls")):
            args = [ast.Name(id="self", ctx=ast.Load())] + args          # implicit receiver (super() / self)
    else:
        return None
    if len(args) < 3 or not (isinstance(args[0], ast.Name) and args[0].id in ("self", "cls")):
        return None
    name = args[1]
    if isinstance(name, ast.Constant) and isinstance(name.value, str):
        return name.value, args[2]
    return None, args[2]


def _members_of_literal(scan: _ModuleScan, value, local_defs) -> Tuple[List[AnchorMember], List[str]]:
    members, reasons = [], []
    if isinstance(value, ast.Dict):
        for k, v in zip(value.keys, value.values):
            if k is None:
                reasons.append("{**other} unpacking")
                continue
            key = k.value if isinstance(k, ast.Constant) else ast.unparse(k)
            m = scan.resolve_value(v, local_defs, str(key))
            members.append(m)
            if m.kind == "unknown":
                reasons.append(f"value {m.name!r} does not resolve to a def/class")
    elif isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        for el in value.elts:
            if isinstance(el, ast.Starred):
                reasons.append("*other unpacking")
                continue
            m = scan.resolve_value(el, local_defs, "")
            members.append(m)
            if m.kind == "unknown":
                reasons.append(f"element {m.name!r} does not resolve to a def/class")
    elif isinstance(value, (ast.DictComp, ast.ListComp, ast.SetComp)):
        reasons.append("comprehension: members come from the iterated collection")
        gen = value.generators[0] if value.generators else None
        if gen is not None and isinstance(gen.iter, (ast.List, ast.Tuple)):
            for el in gen.iter.elts:
                members.append(scan.resolve_value(el, local_defs, ""))
    return members, reasons


def _literal_kind(value) -> str:
    return ("dict_literal" if isinstance(value, ast.Dict) else
            "comprehension" if isinstance(value, (ast.DictComp, ast.ListComp)) else "list_literal")


def _is_empty_literal(value) -> bool:
    if isinstance(value, ast.Dict):
        return not value.keys
    return isinstance(value, (ast.List, ast.Tuple, ast.Set)) and not value.elts


def _value_shape(v, fn) -> str:
    """Shape of a ``self.attr = <value>`` that is not a def / class / instance
    (review C6: every such rebinding opens the anchor)."""
    if isinstance(v, ast.Await):
        v = v.value
    if isinstance(v, ast.Name):
        return "parameter" if (fn is not None and v.id in L._param_names(fn)) else "name"
    if isinstance(v, ast.Call):
        return "call"
    if isinstance(v, ast.Attribute):
        return "attribute"
    if isinstance(v, ast.Constant):
        return "constant"
    if _is_empty_literal(v):
        return "empty literal"
    if isinstance(v, ast.BoolOp):
        return "boolop"
    if isinstance(v, ast.IfExp):
        return "conditional"
    if isinstance(v, ast.Lambda):
        return "lambda"
    if isinstance(v, ast.Subscript):
        return "subscript"
    return type(v).__name__.lower()


def _value_bound_names(nodes) -> Set[str]:
    """Names a scope binds by a value / loop / comprehension / with statement
    — a superset of the bindings ``engine_walls._binding_of`` can turn into a
    resolver key (imports, defs, classes and parameters never do). Pre-filter
    for ``find_reads`` (review minor: find_reads re-parse / describe_call
    cost). ``nodes`` = the scope's own statements (``dl._own_stmt_walk``)."""
    out: Set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                out.update(_target_names(t))
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            if node.value is not None:
                out.update(_target_names(node.target))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            out.update(_target_names(node.target))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for it in node.items:
                if it.optional_vars is not None:
                    out.update(_target_names(it.optional_vars))
    return out


def _local_names(fn, nodes) -> Tuple[Set[str], Set[str]]:
    """(names bound inside ``fn``'s own body — parameters, assignment / loop /
    with / import / def / except targets —, names it declares ``global``).
    ``nodes`` = the body's own statements (``dl._own_stmt_walk``)."""
    local = set(L._param_names(fn))
    glob: Set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Global):
            glob |= set(node.names)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                local.update(_target_names(t))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            local.update(_target_names(node.target))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            local.update(_target_names(node.target))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for it in node.items:
                if it.optional_vars is not None:
                    local.update(_target_names(it.optional_vars))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            local.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                local.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            local.add(node.name)
    return local - glob, glob


def _class_body_names(cls: ast.ClassDef) -> Set[str]:
    out: Set[str] = set()
    for st in cls.body:
        if isinstance(st, ast.Assign):
            for t in st.targets:
                out.update(_target_names(t))
        elif isinstance(st, (ast.AnnAssign, ast.AugAssign)):
            out.update(_target_names(st.target))
        elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(st.name)
    return out


# --------------------------------------------------------------------------- #
# anchors
# --------------------------------------------------------------------------- #
def find_anchors(src_root: str, register_methods=DEFAULT_REGISTER_METHODS, exclude_paths=(),
                 index: Optional[_TreeIndex] = None) -> List[Anchor]:
    """Anchors of the tree, keyed ``module.NAME`` / ``module.Cls.attr``
    (review C6). ``index`` (when given) is filled with the per-module scans,
    their read sites and the class hierarchy so ``find_reads`` can reuse
    them — the tree is parsed once (review minor: find_reads re-parse)."""
    src_root = os.path.abspath(src_root)
    if index is None:
        index = _TreeIndex(src_root)
    anchors: Dict[str, Anchor] = {}
    defined: Set[str] = set()                                  # anchors that have a defining site (literal / attr)
    bindings = collections.Counter()                           # module.NAME -> module-level bindings
    mutated: Dict[str, List[str]] = collections.defaultdict(list)
    rebound: Dict[str, List[str]] = collections.defaultdict(list)   # module.Cls.attr -> runtime rebinding sites
    rebound_any: Dict[str, List[str]] = collections.defaultdict(list)   # module.Cls -> setattr(self, <expr>, v) sites (review C6 repair)
    aliases: Dict[str, Tuple[str, str]] = {}                   # module.X -> (target qualname, evidence)
    reg_methods = set(register_methods)

    def get(q: str, short: str, kind: str, scan: _ModuleScan, line: int, defining: bool) -> Anchor:
        a = anchors.get(q)
        if a is None:
            a = anchors[q] = Anchor(name=q, kind=kind, file=scan.rel, line=line,
                                    module=scan.module if defining else "", short=short)
            if defining:
                defined.add(q)
        elif defining and q not in defined:
            # first defining site wins over a mutation / registration seen earlier
            a.kind, a.file, a.line, a.module, a.short = kind, scan.rel, line, scan.module, short
            defined.add(q)
        return a

    def short_of(scan: _ModuleScan, q: str, base, cls) -> str:
        """Display name of a non-defining site: ``Cls.attr`` for ``self.attr``,
        the last component of the key for a bare name, the expression otherwise."""
        attr = _self_attr(base)
        if attr and cls is not None:
            return f"{scan.local_name(cls)}.{attr}"
        if isinstance(base, ast.Name):
            return q.rsplit(".", 1)[-1]
        return ast.unparse(base)

    def register(scan, node: ast.Call, cls, local_defs, skip: Set[str]) -> None:
        """``recv.register(fn)`` / ``recv.add_tool(fn=...)`` — a member of the receiver's anchor."""
        recv = node.func.value
        target = None
        for kw in node.keywords:
            if kw.arg in _REGISTER_KW:
                target = kw.value
        if target is None and node.args:
            target = node.args[0]
        if target is None:
            return
        root = recv
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and root.id in skip:
            return                                         # a local object: not a module registry
        q = scan.qualify(recv, cls)
        if not q:
            return
        m = scan.resolve_value(target, local_defs)
        a = get(q, short_of(scan, q, recv, cls), "register_call", scan, node.lineno, False)
        a.members.append(m)
        a.evidence.append(f"{scan.rel}:{node.lineno} {ast.unparse(node)[:70]}")
        if m.kind == "unknown":
            a.open_reasons.append(f"{scan.rel}:{node.lineno} registers {m.name!r} (not a def/class)")

    def subscript_assign(scan, t: ast.Subscript, value, node, cls, local_defs, skip: Set[str]) -> None:
        """``NAME[k] = v`` / ``self.attr[k] = v`` in any scope: a member when
        ``v`` is visible, and always a mutation (review C6)."""
        base = t.value
        if isinstance(base, ast.Name) and base.id in skip:
            return
        q = scan.qualify(base, cls)
        if not q:
            return
        m = scan.resolve_value(value, local_defs, ast.unparse(t.slice))
        a = get(q, short_of(scan, q, base, cls), "subscript_assign", scan, node.lineno, False)
        a.members.append(m)
        a.evidence.append(f"{scan.rel}:{node.lineno} {ast.unparse(t)} = {ast.unparse(value)[:40]}")
        mutated[q].append(f"{scan.rel}:{node.lineno} {ast.unparse(t)} = ...")
        if m.kind == "unknown":
            a.open_reasons.append(f"{scan.rel}:{node.lineno} registers a value that is not a def/class")

    def mutate(scan, base, node, cls, skip: Set[str], what: str) -> None:
        if isinstance(base, ast.Subscript):
            base = base.value
        if isinstance(base, ast.Name) and base.id in skip:
            return
        q = scan.qualify(base, cls)
        if q:
            mutated[q].append(f"{scan.rel}:{node.lineno} {what}")

    def self_assign(scan: _ModuleScan, attr: str, value, node, cls, fn, local_defs, text: str = "") -> None:
        """``self.<attr> = value`` in a method (also ``setattr(self, "<attr>",
        value)`` / ``self.__dict__["<attr>"] = value`` — review C6 repair): a
        literal's members, a member when the value is a def / class /
        instance, else a rebinding to a runtime value that opens the anchor."""
        q = f"{scan.class_q(cls)}.{attr}"
        short = f"{scan.local_name(cls)}.{attr}"
        text = text or f"self.{attr} = {ast.unparse(value)[:60]}"
        if isinstance(value, _LITERALS) and not _is_empty_literal(value):
            a = get(q, short, _literal_kind(value), scan, node.lineno, True)
            ms, reasons = _members_of_literal(scan, value, local_defs)
            a.members += ms
            a.open_reasons += reasons
            a.evidence.append(f"{scan.rel}:{node.lineno} {text}")
            return
        m = None
        if isinstance(value, (ast.Name, ast.Attribute)) or (
                isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id in scan.classes):
            m = scan.resolve_value(value, local_defs)
        if m is not None and m.kind in ("def", "class", "instance"):
            a = get(q, short, "attr_assign", scan, node.lineno, True)
            a.members.append(m)
            a.evidence.append(f"{scan.rel}:{node.lineno} {text}")
        else:
            # review C6: a rebinding to a runtime value opens the anchor
            rebound[q].append(f"{scan.rel}:{node.lineno} {text[:60]} ({_value_shape(value, fn)})")

    def scan_scope(scan: _ModuleScan, nodes: list, kind: str, cls, fn, skip: Set[str], glob: Set[str]) -> None:
        """One scope's own statements (``nodes``). ``skip`` = names bound
        locally (never a module registry); ``glob`` = names declared
        ``global`` in a function."""
        local_defs = ({n.name: n for n in fn.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
                      if fn is not None else {})
        in_method = cls is not None and kind == "function"
        for node in nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if value is None:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    attr = _self_attr(t) or (_self_dict_attr(t) if in_method else None)
                    if attr and in_method:
                        self_assign(scan, attr, value, node, cls, fn, local_defs,
                                    text=f"{ast.unparse(t)} = {ast.unparse(value)[:60]}")
                        continue
                    if isinstance(t, ast.Subscript):
                        if in_method and _self_dict_attr(t, dynamic=True):
                            # review C6 repair: ``self.__dict__[k] = v`` may rebind any attribute
                            rebound_any[scan.class_q(cls)].append(f"{scan.rel}:{node.lineno} {ast.unparse(t)} = ...")
                            continue
                        subscript_assign(scan, t, value, node, cls, local_defs, skip)
                        continue
                    if isinstance(t, ast.Attribute) and not attr:
                        # review C6 repair: ``Cls.attr = v`` / ``mod.NAME = v`` written
                        # outside the owner's own methods rebinds the anchor's name
                        root = t
                        while isinstance(root, ast.Attribute):
                            root = root.value
                        if not (isinstance(root, ast.Name) and root.id in skip):
                            q = scan.qualify(t, cls)
                            if q:
                                rebound[q].append(f"{scan.rel}:{node.lineno} {ast.unparse(t)} = "
                                                  f"{ast.unparse(value)[:40]} ({_value_shape(value, fn)})")
                        continue
                    names = _target_names(t)
                    if not names:
                        continue
                    if kind == "module":
                        for n in names:
                            bindings[scan._q(n)] += 1
                        if isinstance(t, ast.Name) and isinstance(value, _LITERALS):
                            q = scan._q(t.id)
                            a = get(q, t.id, _literal_kind(value), scan, node.lineno, True)
                            ms, reasons = _members_of_literal(scan, value, {})
                            a.members += ms
                            a.open_reasons += reasons
                            a.evidence.append(f"{scan.rel}:{node.lineno} {t.id} = {ast.unparse(value)[:60]}")
                    elif kind == "function":
                        # review C6: ``global NAME`` + assignment rebinds the module registry
                        for n in names:
                            if n in glob:
                                q = scan.qualify_name(n)
                                mutated[q].append(f"{scan.rel}:{node.lineno} global {n} = {ast.unparse(value)[:30]}")
                                if isinstance(t, ast.Name) and isinstance(value, _LITERALS):
                                    a = get(q, n, _literal_kind(value), scan, node.lineno, True)
                                    ms, reasons = _members_of_literal(scan, value, local_defs)
                                    a.members += ms
                                    a.open_reasons += reasons
                                    a.evidence.append(f"{scan.rel}:{node.lineno} global {n} = {ast.unparse(value)[:60]}")
            elif isinstance(node, ast.AugAssign):
                # review C6: ``NAME += [...]`` / ``MERGED |= {...}`` / ``self.tools |= ...`` mutate
                t = node.target
                if isinstance(t, (ast.Name, ast.Attribute, ast.Subscript)):
                    op = _AUG_OPS.get(type(node.op), type(node.op).__name__)
                    mutate(scan, t, node, cls, skip, f"{ast.unparse(t)} {op}= {ast.unparse(node.value)[:30]}")
            elif isinstance(node, ast.Delete):
                for t in node.targets:
                    mutate(scan, t, node, cls, skip, "del")
            elif isinstance(node, ast.Call) and in_method and _setattr_call(node) is not None:
                # review C6 repair: setattr(self, "attr", v) / object.__setattr__(self, "attr", v)
                # rebind like ``self.attr = v``; a non-constant name may rebind any attribute
                attr, value = _setattr_call(node)
                if attr:
                    self_assign(scan, attr, value, node, cls, fn, local_defs, text=ast.unparse(node)[:60])
                else:
                    rebound_any[scan.class_q(cls)].append(f"{scan.rel}:{node.lineno} {ast.unparse(node)[:50]}")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                meth = node.func.attr
                if meth in reg_methods and (node.args or node.keywords):
                    register(scan, node, cls, local_defs, skip)
                elif meth in _MUTATORS:
                    mutate(scan, node.func.value, node, cls, skip, f".{meth}()")

    for path, tree in _iter_files(src_root, exclude_paths):
        scan = _ModuleScan(path, src_root, tree)
        for local, (target, ev) in scan.aliases.items():
            aliases[scan._q(local)] = (target, ev)
        # module body, class bodies and function bodies — each statement
        # walked once (the node list feeds the scan and the read pre-filter)
        nodes = list(dl._own_stmt_walk(tree.body))
        scan.index_scope(nodes, None, None)
        scan_scope(scan, nodes, "module", None, None, set(), set())
        for cls in scan.all_classes:
            scan_scope(scan, list(dl._own_stmt_walk(cls.body)), "class", cls, None, _class_body_names(cls), set())
        for fn, cls in scan.functions:
            nodes = list(dl._own_stmt_walk(fn.body))
            scan.index_scope(nodes, fn, cls)
            key = (fn.lineno, fn.col_offset)
            scan_scope(scan, nodes, "function", cls, fn, scan.fn_local[key], scan.fn_global[key])
        scan._indexed = True
        scan.index_reads()          # the read sites, from this tree — find_reads does not parse again
        scan.tree = None
        index.add(scan)

    # keys seen through a re-export (``from a.b import NAME`` where a.b itself
    # imports NAME) collapse onto the defining module (review C6)
    def canon_lists(d):
        out: Dict[str, List[str]] = collections.defaultdict(list)
        for k, v in d.items():
            out[index.canonical(k)] += v
        return out
    mutated, rebound, rebound_any = canon_lists(mutated), canon_lists(rebound), canon_lists(rebound_any)
    canon_bindings = collections.Counter()
    for k, v in bindings.items():
        canon_bindings[index.canonical(k)] += v
    bindings = canon_bindings
    aliases = {index.canonical(k): (index.canonical(t), ev) for k, (t, ev) in aliases.items()}
    merged: Dict[str, Anchor] = {}
    merged_defined: Set[str] = set()      # canonical keys whose merged anchor carries its defining site
    for q, a in anchors.items():
        cq = index.canonical(q)
        if cq in merged:
            b = merged[cq]
            b.members += a.members
            b.evidence += a.evidence
            b.open_reasons += a.open_reasons
            # review C6 repair: the defining site wins whatever the order the
            # keys were seen in (``q == cq`` is itself in ``defined``, so the
            # old ``cq not in defined`` test skipped it when a re-exported
            # mutation site had claimed the canonical key first)
            if q in defined and cq not in merged_defined:
                b.kind, b.file, b.line, b.module, b.short = a.kind, a.file, a.line, a.module, a.short
                b.evidence = a.evidence + [e for e in b.evidence if e not in a.evidence]
                merged_defined.add(cq)
        else:
            a.name = cq
            merged[cq] = a
            if q in defined:
                merged_defined.add(cq)
    anchors, defined = merged, merged_defined

    # review C6: mutations through an alias reach the aliased registry
    for alias_q, (target_q, ev) in aliases.items():
        for why in mutated.get(alias_q, []):
            mutated[target_q].append(f"via alias {alias_q}: {why}")

    out = []
    for a in anchors.values():
        if a.name not in defined and not index.in_tree(a.name):
            continue        # registrations into an external object (os.environ, loguru.logger): not a tree registry
        if not a.module and a.name.endswith("." + a.short):
            a.module = a.name[: -len(a.short) - 1]
        if "." not in a.short and bindings.get(a.name, 0) > 1:
            a.open_reasons.append(f"{a.short} is bound {bindings[a.name]} times in {a.module or '<module>'}")
        for why in mutated.get(a.name, []):
            a.open_reasons.append(f"mutated: {why}")
        for why in rebound.get(a.name, []):
            a.open_reasons.append(f"rebound: {why}")
        for alias_q, (target_q, ev) in aliases.items():
            if target_q == a.name:
                a.open_reasons.append(f"aliased as {alias_q} ({ev})")
        if "." in a.short and a.name.endswith("." + a.short):
            # Cls.attr (``Outer.Inner.attr`` for a nested class — review C6
            # repair): class-body declarations in the class or its in-tree
            # bases, subclasses binding the attribute, and a dynamic
            # ``setattr(self, <expr>, v)`` in the class open the anchor
            attr = a.short.rsplit(".", 1)[1]
            cls_q = a.name[: -len(attr) - 1]
            if cls_q in index.bases:
                for why in rebound_any.get(cls_q, []):
                    a.open_reasons.append(f"rebound: {why} (dynamic attribute name)")
                for anc in [cls_q] + index.ancestors(cls_q):
                    ev = index.decl.get(anc, {}).get(attr)
                    if ev:
                        a.open_reasons.append(f"class body of {anc} declares {attr}: {ev}")
                for sub in index.descendants(cls_q):
                    ev = index.binds(sub, attr)
                    if ev:
                        a.open_reasons.append(f"subclass {sub} binds {attr}: {ev}")
        if a.kind == "subscript_assign" and not any(m.kind != "unknown" for m in a.members):
            a.open_reasons.append("only runtime values registered")
        a.open = bool(a.open_reasons) or any(m.kind == "unknown" for m in a.members)
        # an anchor is worth its name only when it NAMES a destination: at
        # least one def / class member visible in the source. A map of strings
        # (provider names) or a registry filled with runtime values only is
        # not an anchor — its reads are the engine's business
        if any(m.kind in ("def", "class", "instance") for m in a.members):
            out.append(a)
    return sorted(out, key=lambda a: (a.file, a.line))


# --------------------------------------------------------------------------- #
# reads
# --------------------------------------------------------------------------- #
def _anchor_key(resolver: str) -> Optional[Tuple[str, str]]:
    """What a resolver text names: ``REGISTRY`` -> ('name', 'REGISTRY');
    ``self.tools`` -> ('self', 'tools'); ``REGISTRY.get`` / ``REG.pop`` /
    ``iter(REG.values())`` -> ('name', 'REG'); ``mod.REG`` -> ('dotted', 'mod.REG');
    None when the text is not a name (a call, an index, ``self.a.b``)."""
    r = resolver.strip()
    if r.startswith("iter(") and r.endswith(")"):
        r = r[5:-1]
    for suf in (".get", ".pop", ".values()", ".items()", ".values", ".items", ".keys()", ".keys"):
        if r.endswith(suf):
            r = r[: -len(suf)]
    if not r or "(" in r or "[" in r:
        return None
    if r.startswith("self.") or r.startswith("cls."):
        attr = r.split(".", 1)[1]
        if "." in attr:
            return None
        return ("self", attr)
    if "." in r:
        return ("dotted", r)
    return ("name", r)


class _CallIndex:
    """The part of ``engine_walls._FileIndex`` that ``describe_call`` reads —
    the tree, every Call by position and its enclosing scopes — built from
    the tree ``_iter_files`` already parsed, without the statement map and
    runtime-binding tables the wall scan needs (review minor: find_reads
    re-parse / describe_call cost)."""

    def __init__(self, path: str, tree: ast.AST):
        self.path, self.tree = path, tree
        self.calls: Dict[Tuple[int, int], List[ast.Call]] = collections.defaultdict(list)
        self.by_line: Dict[int, List[ast.Call]] = collections.defaultdict(list)
        self.scopes: Dict[int, list] = {}
        self._walk(self.tree, [])

    def _walk(self, node, stack):
        if dl._is_generated_block(node):        # cond_B trees: never wall candidates
            return
        if isinstance(node, ast.Call):
            self.calls[(node.lineno, node.col_offset)].append(node)
            self.by_line[node.lineno].append(node)
            self.scopes[id(node)] = list(reversed(stack))
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._walk(child, stack + [child])
            else:
                self._walk(child, stack)


@dataclass
class _ReadSite:
    """One call that may read an anchor — the anchor-independent half of an
    ``AnchorRead`` (position, shape, key, reader class / scope, whether the
    key's name is a local of an enclosing scope), described once from the
    parsed tree by ``_read_sites``; ``find_reads`` joins it to the anchors
    (review minor: find_reads re-parse / describe_call cost)."""
    line: int
    col: int
    end_line: int
    end_col: int
    callee: str
    cls_name: str                   # reader class, local qualname ('' outside a class)
    qual: str                       # enclosing scopes joined (``Outer.Inner.run``)
    akey: Tuple[str, str]           # ('self' | 'name' | 'dotted', value) — see _anchor_key
    idiom: str                      # read idiom (AnchorRead.idiom)
    key_expr: str
    method: str
    shadowed: bool                  # the key's first name is bound by an enclosing function / class body


def _may_bind(scan: _ModuleScan, name: str, scopes) -> bool:
    """Can ``_binding_of`` give ``name`` a resolver key here? Only a value /
    loop binding in an enclosing function or the module can."""
    for s in scopes:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bound = scan.fn_bound.get((s.lineno, s.col_offset))
            if bound is None:
                bound = scan.fn_bound[(s.lineno, s.col_offset)] = _value_bound_names(dl._own_stmt_walk(s.body))
            if name in bound:
                return True
    return name in (scan.module_bound or ())


def _shadowed(scan: _ModuleScan, name: str, scopes) -> bool:
    """review C6 repair: a bare name that an enclosing function binds
    itself (parameter, assignment, import, def, loop ...) — or that the
    class body the read sits in directly binds — is a local: it never
    denotes the module registry of the same name, so the read joins no
    anchor (a ``global NAME`` declaration keeps the module binding)."""
    for i, s in enumerate(scopes):
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
            key = (s.lineno, s.col_offset)
            local = scan.fn_local.get(key)
            if local is None:
                local, glob = _local_names(s, list(dl._own_stmt_walk(s.body)))
                scan.fn_local[key], scan.fn_global[key] = local, glob
            if name in local:
                return True
        elif isinstance(s, ast.ClassDef) and i == 0 and name in _class_body_names(s):
            return True
    return False


def _read_sites(scan: _ModuleScan, tree: ast.AST) -> List[_ReadSite]:
    """The read sites of one module from its parsed tree: every call whose
    shape can name a registry (pre-filtered by the scope's value / loop
    bindings, so ``describe_call`` runs only where a key is possible),
    described once. Anchor-independent — ``find_anchors`` calls this while
    it holds the tree; ``find_reads`` only joins the result to the anchors."""
    fx = _CallIndex(scan.path, tree)
    if scan.module_bound is None:
        scan.module_bound = _value_bound_names(dl._own_stmt_walk(tree.body))
    out: List[_ReadSite] = []
    for (line, col), calls in fx.calls.items():
        for call in calls:
            fn = call.func
            scopes = fx.scopes.get(id(call), [])
            # pre-filter: shapes that cannot yield an anchor key skip describe_call
            if isinstance(fn, ast.Name):
                if not _may_bind(scan, fn.id, scopes):
                    continue
            elif isinstance(fn, ast.Attribute):
                if isinstance(fn.value, ast.Name):
                    if fn.value.id not in ("self", "cls") and not _may_bind(scan, fn.value.id, scopes):
                        continue
                else:
                    continue
            elif not isinstance(fn, ast.Subscript) and not dl._is_getattr_call(fn):
                continue
            d = EW.describe_call(call, fx)
            idiom, resolver, key = d["idiom"], d["resolver"], d["key_expr"]
            method = ""
            read_idiom = ""
            akey: Optional[Tuple[str, str]] = None
            if idiom == "subscript":
                akey, read_idiom = _anchor_key(resolver), "subscript"
            elif idiom == "getattr":
                akey, read_idiom = _anchor_key(resolver[8:-1] if resolver.startswith("getattr(") else resolver), "getattr"
            elif idiom == "higher_order" and (resolver.endswith(".get") or resolver.endswith(".pop")):
                akey, read_idiom = _anchor_key(resolver), "get"
            elif idiom == "method_call":
                method = call.func.attr if isinstance(call.func, ast.Attribute) else ""
                rb = d["receiver_binding"]
                if rb == "subscript" or (rb == "resolver_call" and (resolver.endswith(".get") or resolver.endswith(".pop"))):
                    akey, read_idiom = _anchor_key(resolver), "method_call"
                elif rb == "loop":
                    akey, read_idiom = _anchor_key(resolver), "loop_method"
            elif idiom == "loop_call":
                akey, read_idiom = _anchor_key(resolver), "loop_call"
            elif idiom == "attr_call" and resolver in ("self", "cls"):
                akey, read_idiom = ("self", key), "attr_call"
                method = ""
            if akey is None:
                continue
            # the reader class as a local qualname (``Outer.Inner`` — review C6 repair)
            cls_name = ".".join(s.name for s in reversed(scopes) if isinstance(s, ast.ClassDef))
            qual = ".".join(n.name for n in reversed(scopes))
            shadowed = akey[0] != "self" and _shadowed(scan, akey[1].split(".", 1)[0], scopes)
            out.append(_ReadSite(line=line, col=col, end_line=call.end_lineno or line, end_col=call.end_col_offset or col,
                                 callee=ast.unparse(call.func), cls_name=cls_name, qual=qual, akey=akey, idiom=read_idiom,
                                 key_expr=key if read_idiom != "attr_call" else "", method=method, shadowed=shadowed))
    return out


def find_reads(src_root: str, anchors: List[Anchor], exclude_paths=(), index: Optional[_TreeIndex] = None) -> None:
    """Attach the reads of ``anchors`` (their ``reads`` lists) by joining the
    read sites ``find_anchors`` described (``scan.read_sites``) to the
    anchors — no file is opened or parsed again, no call is described again
    (review minor: find_reads re-parse); without an index (standalone use)
    each file is parsed once here. A read's name is resolved through the
    reader module (own bindings, ``from X import``, aliases); ``self.<attr>``
    joins the reader's own class exactly or an ancestor's anchor as an
    *inherited* read (review C6)."""
    src_root = os.path.abspath(src_root)
    if index is None or not index.scans:
        index = _TreeIndex(src_root)
        for path, tree in _iter_files(src_root, exclude_paths):
            scan = _ModuleScan(path, src_root, tree)
            scan.index_reads()
            scan.tree = None
            index.add(scan)
    by_name: Dict[str, Anchor] = {a.name: a for a in anchors}

    def lookup(scan: _ModuleScan, site: _ReadSite) -> Optional[Tuple[Anchor, str]]:
        kind, val = site.akey
        if kind == "self":
            if not site.cls_name:
                return None
            reader_q = scan.class_q(site.cls_name)
            a = by_name.get(f"{reader_q}.{val}")
            if a is not None:
                return a, "exact"
            # review C6: the old ``*.<attr>`` fallback joined ANY class's
            # ``self.<attr>`` read to the first anchor with that attribute
            # name. Now: only an in-tree ancestor's anchor, never when the
            # reader class binds the attribute itself, and only when exactly
            # one ancestor anchors it
            if index.binds(reader_q, val):
                return None
            hits = [by_name[f"{anc}.{val}"] for anc in index.ancestors(reader_q) if f"{anc}.{val}" in by_name]
            if len(hits) == 1:
                return hits[0], "inherited"
            return None
        if site.shadowed:
            return None
        q = scan.qualify_name(val) if kind == "name" else scan.qualify_dotted(val)
        a = by_name.get(index.canonical(q)) if q else None
        return (a, "exact") if a is not None else None

    for path, scan in index.scans.items():
        if scan.read_sites is None:
            # a scan that came without its read sites: parse its file once here
            try:
                scan.tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
                scan.index_reads()
            except Exception:
                continue
            finally:
                scan.tree = None
        for site in scan.read_sites or ():
            hit = lookup(scan, site)
            if hit is None:
                continue
            a, binding = hit
            r = AnchorRead(file=scan.rel, line=site.line, col=site.col, end_line=site.end_line, end_col=site.end_col,
                           callee=site.callee, idiom=site.idiom, key_expr=site.key_expr, method=site.method,
                           callable=site.qual, anchor=a.name, binding=binding,
                           anchor_closed=bool(a.closed and binding == "exact"))
            r.candidates = a.member_candidates(site.method)
            a.reads.append(r)


# --------------------------------------------------------------------------- #
# join with the engine
# --------------------------------------------------------------------------- #
def anchoring(src_root: str, engine: Optional["EW.ScanResult"] = None, reject=(),
              register_methods=DEFAULT_REGISTER_METHODS, exclude_paths=()) -> AnchoringResult:
    index = _TreeIndex(src_root)
    anchors = find_anchors(src_root, register_methods=register_methods, exclude_paths=exclude_paths, index=index)
    rej = set(reject)
    for a in anchors:
        if a.name in rej or a.short in rej:       # qualified or short name (review C6)
            a.rejected = True
    find_reads(src_root, [a for a in anchors if not a.rejected], exclude_paths=exclude_paths, index=index)
    res = AnchoringResult(src_root=os.path.abspath(src_root), anchors=anchors)
    for a in anchors:
        for r in a.reads:
            st = engine.status_at(r.file, r.line, r.col) if engine is not None else None
            r.engine_status = (st or {}).get("status", "") if st else ""
            s = r.engine_status
            r.anchor_closed = bool(a.closed and r.binding == "exact")
            if r.binding != "exact":
                # review C6: an inherited read carries candidates only — never
                # confirmed by the anchor, never narrowed
                r.confidence, r.accept = "proposed", False
                r.note = (f"engine {s or 'no site'}; inherited read of {a.name} from "
                          f"{r.callable.rsplit('.', 1)[0] if '.' in r.callable else r.callable}: "
                          f"candidates only, no narrowing")
            elif (s.startswith("unresolved:") or s in ("resolved_stub", "resolved_obscure")) and r.candidates:
                r.confidence, r.accept = "confirmed", True
                r.note = f"engine {s}; anchor {a.name} ({'closed' if a.closed else 'open'})"
            elif s.startswith("unresolved:") or s in ("resolved_stub", "resolved_obscure"):
                r.confidence, r.accept = "proposed", False
                r.note = f"engine {s}; anchor {a.name} has no member for this read"
            elif s.startswith("resolved_dispatch"):
                r.confidence, r.accept = "proposed", False
                r.note = f"engine {s}; anchor {a.name}"
            elif s == "resolved":
                r.confidence, r.accept = "proposed", False
                r.note = f"engine resolves this read (typed registry); anchor {a.name} — off"
            else:
                r.confidence, r.accept = "proposed", False
                r.note = f"no engine site at this position; anchor {a.name}"
            if not r.candidates:
                r.note += "; anchor has no def/class members for this read"
            if r.binding != "exact" and a.closed:
                # review C6: the consumer (draft._entry / _apply_anchors) keys
                # narrowing on ``Anchor.closed`` — an inherited read gets an
                # open view of the anchor so it can never narrow; ``anchors``
                # / anchors.json keep the real (closed) anchor
                view = replace(a, open=True, reads=[],
                               open_reasons=a.open_reasons + [f"inherited read at {r.position}: narrowing disabled"])
                res.by_position[(r.file, r.line, r.col)] = (view, r)
                continue
            res.by_position[(r.file, r.line, r.col)] = (a, r)
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src_root")
    ap.add_argument("--engine", default="", help="cond dir with r/ to join engine statuses")
    ap.add_argument("--reject", nargs="*", default=[], help="anchor names to ignore (qualified or short)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    eng = EW.scan(a.engine, src_root=a.src_root) if a.engine else None
    res = anchoring(a.src_root, engine=eng, reject=a.reject)
    if a.json:
        print(json.dumps(res.to_dict(), indent=2))
        return 0
    for an in res.anchors:
        flag = "REJECTED" if an.rejected else ("closed" if an.closed else "open")
        print(f"{an.name}  [{an.kind}, {flag}]  {an.file}:{an.line}  members={len(an.members)} reads={len(an.reads)}")
        for m in an.members[:8]:
            print(f"    member {m.kind:8s} {m.name}  {m.evidence}")
        for why in an.open_reasons[:4]:
            print(f"    open: {why}")
        for r in an.reads[:12]:
            print(f"    read {r.position} {r.idiom}/{r.binding} `{r.callee}` engine={r.engine_status or '-'} "
                  f"accept={r.accept} cands={len(r.candidates)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
