"""Engine-driven wall discovery — walls are where the *unmodified engine* loses taint.

IccTA instruments the statements named by an EXTERNAL ICC link analysis
(IC3/Epicc) filtered by the fixed signature list ``IPCMethods.txt``; FlowDroid's
own call graph plays no part in choosing them. This pass has no external link
analysis: it uses the engine's own unresolved-call records as the primary
catalogue — it reads the artifacts Pysa already wrote for cond_A
(``run_ablation.sh`` always analyses the un-lowered tree first) and reports every
in-repo call site the engine could not carry taint across, with no extra
``pyre`` run and no AST heuristics deciding what "looks like" a wall. That is a
DIFFERENCE from IccTA's instrumentation-site selection, not an isomorphism
(review M8); the isomorphic part is what happens after a site is chosen
(explicit link table, guarded destination-side instrumentation).

Operational definition of a wall (SCALE_OUT_DESIGN.md):

  S1 ``unresolved:<reason>``      ``call-graph.json`` records the call as
                                  unresolved (0.9.25 reasons: UnknownIdentifierCallee,
                                  UnknownCallCallee, NonMethodAttribute,
                                  UnknownBaseType, CannotResolveExports, ...)
  S2 ``resolved_stub`` /          the engine names a callee but cannot carry
     ``resolved_obscure``         taint into its body: an in-repo def whose body
                                  is trivial (``pass`` / ``...`` / ``raise`` /
                                  abstract), or whose model is ``Obscure``.
                                  Review C5 policy on the receiver's static type:
                                  an ABSTRACT stub (``@abstractmethod`` / raises
                                  NotImplementedError) with no in-tree override
                                  reachable from the receiver is still a wall,
                                  an UNLOWERABLE one (resolved_stub, proposed,
                                  no candidate; counted in residual_unlowerable);
                                  an EMPTY stub (pass / docstring / ``...``) on a
                                  concrete leaf receiver is resolved (not a wall)
  S3 ``resolved_dispatch:<api>``  the callee is a framework dispatch method: it
                                  matches a catalogue row (``BaseTool.run``,
                                  ``KernelFunction.invoke`` ...) or its own
                                  ``higher-order-call-graph.json`` record shows it
                                  forwarding to a parameter-carried callable
                                  (``Context.run(self._run)`` -> ``Overrides{BaseTool._run}``)

Everything else the engine resolved is *not* a wall, whatever the AST looks like
(the typed-registry ``method_wall`` lesson).

Taint tiers (T1: a source-derived frame touches the call, T2: the enclosing
callable carries a source, T3: reachable from one over the in-repo call graph)
only ORDER the rows; they never gate them, because the tiers are empty before
the target's ``.pysa`` exists. T1 is read off the ``sources`` /
``parameter_sources`` positions of the callable's model only (tito / sink
summaries carry positions too but are not source frames — review minor). T3
needs the callers' records, which an ``extract`` excerpt does not keep: so
``extract`` records the full tree's T2 / T3 membership of the excerpt's
callables in ``r/engine-tiers.json`` and ``scan`` unions that side file in
when present (Pysa never writes it; a real cond dir has none).

Artifacts read (all under ``<cond>/r``): ``call-graph.json`` (old ``singleton`` /
``compound`` and new flat schema, streamed), ``higher-order-call-graph.json``
(only the records of resolved targets), ``taint-output.json`` (models: modes,
sources, positions), ``modules.json``, ``functions.json``,
``decorator-counts.json``, ``override-graph.json``, ``taint-metadata.json``,
``errors.json``; ``engine-tiers.json`` (``extract`` excerpts only, see above).

CLI::

    python3 engine_walls.py scan <cond_A> [--src DIR] [--out DIR] [--catalog spec.presets.json] [--all]
    python3 engine_walls.py dataset-scan <call-graph.json> [--repo PREFIX] [--limit N] [--out FILE]
    python3 engine_walls.py residual <cond_B> [--links cond_B/links.json]
    python3 engine_walls.py extract <cond_A> --out r_min/<name> --files src/agent.py [...] [--tiers-only]
"""
from __future__ import annotations

import argparse
import ast
import collections
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import dispatch_lowering as dl   # noqa: E402
import links as L                # noqa: E402


# --------------------------------------------------------------------------- #
# Pysa vocabulary (empirical, pyre-check 0.9.25 / pysa 7873fbf)
# --------------------------------------------------------------------------- #
PYSA_VERSION_KNOWN = "7873fbf76ce7a1f3b02a527f4e2ee8ac50ca6843"
# side file of an ``extract`` excerpt: the full tree's T2 / T3 membership of
# the excerpt's callables (review minor: T3 was not reproducible on r_min)
TIER_SIDECAR = "engine-tiers.json"

# reason -> (kind, explanation). ``dispatch``: the callee itself is runtime
# selected; ``receiver``: only the receiver's type is unknown, a wall when the
# receiver was runtime-selected; ``env``: an environment gap (missing module,
# base class, attribute), not a dispatch wall.
UNRESOLVED_REASONS: Dict[str, Tuple[str, str]] = {
    "UnknownIdentifierCallee": ("dispatch", "callee is a local whose value the engine cannot type (f = resolve(k); f(...))"),
    "UnknownCallCallee": ("dispatch", "callee is itself a call / subscript expression (REG[k](...), getattr(o, k)(...))"),
    "NonMethodAttribute": ("dispatch", "callee is a callable-valued attribute, not a method (self.handler(...))"),
    "UnknownBaseType": ("receiver", "receiver type unknown (x.m(...)); a wall when x is runtime-selected"),
    "CannotResolveExports": ("env", "imported name could not be resolved (module missing from search_path)"),
    "CannotFindParentClass": ("env", "super() / a base class is not in the environment"),
    "CannotFindAttribute": ("env", "attribute not found on a known type"),
    "LambdaArgument": ("other", "lambda passed as a callable argument"),
    "n/a": ("other", "old-schema record: no reason recorded"),
}

# idioms whose callee is selected at the call site itself (registry / name /
# alternatives / resolver): pre-accepted. ``param_call`` / ``loop_call`` /
# ``call_call`` are runtime-selected too, but their candidates come from the
# callers or the iterated collection — anchoring (component 4) confirms those.
_DISPATCH_IDIOMS = {"subscript", "getattr", "boolop", "higher_order", "method_call", "attr_call"}
_DEFERRED_IDIOMS = {"param_call", "loop_call", "call_call"}
# receiver bindings that make ``x.m(...)`` a dispatch: x was *selected* from a
# collection / by name / among alternatives. A receiver returned by a call
# (``logging.getLogger(__name__)``, ``docker.from_env()``), a parameter or a
# loop variable is merely untyped — anchoring (component 4) may promote those.
_RECEIVER_DISPATCH_BINDINGS = {"subscript", "getattr", "boolop"}

# IPCMethods.txt analogue: framework dispatch methods, matched by dotted suffix so
# ``langchain.tools.base.BaseTool.run`` and ``langchain_core.tools.base.BaseTool.run``
# are one row; ``impl`` names the methods the dispatch forwards to (the candidate
# side reads them). The rows come from the ``dispatch`` blocks of
# ``spec.presets.json`` (catalog.py is the single vocabulary — review M10 / K7);
# this list is used ONLY when that file is missing.
FALLBACK_DISPATCH: List[dict] = [
    {"api": "BaseTool.run", "impl": ["_run"], "framework": "langchain"},
    {"api": "BaseTool.arun", "impl": ["_arun"], "framework": "langchain"},
]

_POS_RE = re.compile(r"^(\d+):(\d+)-(\d+):(\d+)(?:\|(.*))?$")
_OVERRIDES_RE = re.compile(r"^Overrides\{(.+)\}$")
_CALLABLE_RE = re.compile(r'"callable":"([^"]*)"')
_FILENAME_RE = re.compile(r'"filename":"([^"]*)"')
_PATH_RE = re.compile(r'"path":"([^"]*)"')


def _strip_overrides(t: str) -> str:
    m = _OVERRIDES_RE.match(t or "")
    return m.group(1) if m else (t or "")


def _iter_jsonl(path: str) -> Iterator[dict]:
    """Records of a Pysa JSON-lines artifact (tolerates the array form:
    ``[`` / ``]`` lines and trailing commas)."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def _iter_call_objs(value) -> Iterator[dict]:
    """The ``call`` objects of one ``calls`` entry, old or new schema."""
    if not isinstance(value, dict):
        return
    if "call" in value:
        yield value["call"]
    single = value.get("singleton")
    if isinstance(single, dict) and "call" in single:
        yield single["call"]
    comp = value.get("compound")
    if isinstance(comp, dict):
        for sub in comp.values():
            if isinstance(sub, dict) and "call" in sub:
                yield sub["call"]


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #
@dataclass
class CallSite:
    key: str
    line: int
    col: int
    end_line: int
    end_col: int
    artificial: str = ""                       # ``|artificial-call|...`` suffix
    unresolved: Optional[str] = None           # reason, or None when resolved
    targets: List[str] = field(default_factory=list)   # resolved targets (raw, may be Overrides{..})
    constructor: bool = False                  # new_calls / init_calls only
    receiver_classes: List[str] = field(default_factory=list)  # per target: the ``receiver_class`` the
                                               # engine recorded (new schema; '' when absent) — review C5

    @property
    def receiver_class(self) -> str:
        """The receiver's static type at this site as the engine saw it."""
        return next((r for r in self.receiver_classes if r), "")

    @property
    def target_form(self) -> str:
        """'overrides' when the engine resolved through the override set
        (``Overrides{X.m}``), 'plain' for a bare callable, '' when unresolved."""
        if not self.targets:
            return ""
        return "overrides" if any(_OVERRIDES_RE.match(t) for t in self.targets) else "plain"


@dataclass
class CGRecord:
    callable: str
    file: str                                  # path relative to the cond dir ('' when external)
    sites: List[CallSite]


@dataclass
class EngineWall:
    """One call site where the engine loses taint (the review row of walls.md)."""
    id: str
    file: str                                  # relative to src_root
    line: int
    col: int
    end_line: int
    end_col: int
    callable: str                              # Pysa's enclosing callable
    callee: str = ""                           # ast.unparse(call.func)
    idiom: str = ""
    resolver: str = ""                         # what selects the callee (REG / self._get_command / getattr(o))
    key_expr: str = ""                         # the dispatch key expression
    receiver_binding: str = ""                 # for x.m(...): how x was bound
    members: List[str] = field(default_factory=list)    # BoolOp alternatives
    members_open: bool = False                 # a BoolOp alternative is a parameter / call
    engine_status: str = ""                    # unresolved:<reason> | resolved_stub | resolved_obscure | resolved_dispatch:<api>
    engine_reason: str = ""
    engine_targets: List[str] = field(default_factory=list)   # what the engine resolved to (S2/S3)
    dispatch_targets: List[str] = field(default_factory=list) # what the dispatch method forwards to (S3)
    receiver_class: str = ""                   # the receiver's static type at the site (call-graph.json) — C5 / K3
    target_form: str = ""                      # 'plain' | 'overrides' | '' (how the engine resolved the callee)
    s2_reason: str = ""                        # S2 candidate restriction: receiver_subclasses | receiver_unknown
                                               # | receiver_subclass_no_overrides | ''
    engine_tier: str = "none"                  # T1 | T2 | T3 | none
    origin: str = "engine"
    confidence: str = "proposed"               # confirmed | proposed
    accept: bool = False
    note: str = ""
    stmt_line: int = 0
    stmt_end_line: int = 0
    stmt_kind: str = ""
    in_async: bool = False
    taint_args: List[str] = field(default_factory=list)
    aligned: bool = True                       # AST call found at the engine's position
    callable_match: bool = True                # AST scope qualname == Pysa callable

    @property
    def position(self) -> str:
        return f"{self.file}:{self.line}:{self.col}"


@dataclass
class ScanResult:
    walls: List[EngineWall]
    env: dict
    counts: dict
    sites_by_file: Dict[str, List[dict]] = field(default_factory=dict)   # every in-repo site with its status

    def status_at(self, file: str, line: int, col: Optional[int] = None) -> Optional[dict]:
        """Engine status of the call at ``file:line[:col]`` (for AST-detected walls
        the engine may have resolved — ``already_resolved``)."""
        rows = [s for s in self.sites_by_file.get(file, []) if s["line"] == line
                and (col is None or s["col"] == col)]
        if not rows:
            return None
        # a line may hold several calls; prefer a wall over an artificial /
        # constructor site, then the outermost (earliest) one
        rows.sort(key=lambda s: (s["status"] == "resolved", s["col"]))
        return rows[0]

    def to_dict(self) -> dict:
        return {"walls": [dict(asdict(w), position=w.position) for w in self.walls],
                "env": self.env, "counts": self.counts}


# --------------------------------------------------------------------------- #
# Artifact access
# --------------------------------------------------------------------------- #
class EngineRun:
    """Lazy, streaming access to one ``pyre analyze --save-results-to`` directory."""

    def __init__(self, cond_dir: str, src_root: str = "", r_dir: str = ""):
        self.cond_dir = os.path.abspath(cond_dir)
        self.r_dir = os.path.abspath(r_dir) if r_dir else os.path.join(self.cond_dir, "r")
        self.repo = ""
        hdr = next(_iter_jsonl(os.path.join(self.r_dir, "call-graph.json")), {})
        self.repo = (hdr.get("config") or {}).get("repo", "") or ""
        # source roots, relative to cond_dir
        self.source_dirs: List[str] = []
        cfg = os.path.join(self.cond_dir, ".pyre_configuration")
        if os.path.exists(cfg):
            try:
                for sd in json.load(open(cfg)).get("source_directories", []):
                    sd = sd if os.path.isabs(sd) else os.path.join(self.cond_dir, sd)
                    self.source_dirs.append(os.path.relpath(sd, self.cond_dir))
            except Exception:
                pass
        if src_root:
            self.source_dirs = [os.path.relpath(os.path.abspath(src_root), self.cond_dir)]
        # a committed cond dir may carry the configuration of the place it was
        # analysed at: prefer source dirs inside this cond dir, and only fall
        # back to an outside one when nothing inside exists
        exists = [sd for sd in self.source_dirs if os.path.isdir(os.path.join(self.cond_dir, sd))]
        inside = [sd for sd in exists if not sd.startswith("..")]
        if inside:
            self.source_dirs = inside
        elif os.path.isdir(os.path.join(self.cond_dir, "src")):
            self.source_dirs = ["src"]
        else:
            self.source_dirs = exists or ["src"]
        self.src_root = os.path.join(self.cond_dir, self.source_dirs[0])
        # every .py under cond_dir by cond-relative path, for suffix matching of
        # results that were produced elsewhere and copied (``filename: "*"``)
        self._files: Set[str] = set()
        for sd in self.source_dirs:
            base = os.path.join(self.cond_dir, sd)
            for root, dirs, files in os.walk(base):
                dirs[:] = [d for d in dirs if d not in ("__pycache__", ".pyre")]
                for fn in files:
                    if fn.endswith(".py"):
                        self._files.add(os.path.relpath(os.path.join(root, fn), self.cond_dir))
        self._by_suffix: Dict[str, List[str]] = collections.defaultdict(list)
        for rel in self._files:
            self._by_suffix[os.path.basename(rel)].append(rel)
        self._modules: Optional[Dict[str, str]] = None
        self._functions: Optional[Set[str]] = None
        self._metadata: Optional[dict] = None

    # ---- paths ---------------------------------------------------------- #
    def in_repo_rel(self, filename: str, path: str) -> str:
        """cond-relative path of a record when it lies in a source dir, else ''."""
        rel = ""
        if filename and filename != "*":
            rel = filename
        elif path:
            if self.repo and path.startswith(self.repo.rstrip("/") + "/"):
                rel = path[len(self.repo.rstrip("/")) + 1:]
            elif path.startswith(self.cond_dir + "/"):
                rel = path[len(self.cond_dir) + 1:]
            else:
                # copied results (the tree analysed elsewhere, ``r/`` moved here):
                # the whole cond-relative path must be a suffix of the recorded
                # path — a bare basename match would pull a site-packages
                # ``agents/agent.py`` onto the target's ``src/agent.py``
                cands = [c for c in self._by_suffix.get(os.path.basename(path), [])
                         if path.endswith("/" + c)]
                rel = max(cands, key=len) if cands else ""
        if not rel:
            return ""
        rel = rel.replace("\\", "/")
        if rel in self._files:
            return rel
        for sd in self.source_dirs:
            sd = sd.rstrip("/") + "/"
            if rel.startswith(sd) and rel in self._files:
                return rel
        return rel if rel in self._files else ""

    def src_rel(self, cond_rel: str) -> str:
        """Path relative to ``src_root`` (what walls.md and specs use)."""
        abs_p = os.path.join(self.cond_dir, cond_rel)
        return os.path.relpath(abs_p, self.src_root)

    def abs_path(self, cond_rel: str) -> str:
        return os.path.join(self.cond_dir, cond_rel)

    # ---- call graph ----------------------------------------------------- #
    def iter_call_graph(self, in_repo_only: bool = True, path: str = "") -> Iterator[CGRecord]:
        path = path or os.path.join(self.r_dir, "call-graph.json")
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                head = line[:600]
                if not head.startswith('{"kind":"call_graph"'):
                    continue
                if in_repo_only:
                    fm = _FILENAME_RE.search(head)
                    pm = _PATH_RE.search(head)
                    fn = fm.group(1) if fm else ""
                    pt = pm.group(1) if pm else ""
                    if fn == "*" and (not pt or not self.in_repo_rel(fn, pt)):
                        continue
                line = line.strip().rstrip(",")
                try:
                    d = json.loads(line)["data"]
                except Exception:
                    continue
                rel = self.in_repo_rel(d.get("filename", ""), d.get("path", ""))
                if in_repo_only and not rel:
                    continue
                yield CGRecord(callable=d.get("callable", ""), file=rel,
                               sites=list(_sites_of(d.get("calls") or {})))

    def higher_order_records(self, callables: Set[str]) -> Dict[str, dict]:
        """``higher-order-call-graph.json`` records for ``callables`` only (the
        file is the largest artifact; lines are pre-filtered by name)."""
        out: Dict[str, dict] = {}
        path = os.path.join(self.r_dir, "higher-order-call-graph.json")
        if not callables or not os.path.exists(path):
            return out
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = _CALLABLE_RE.search(line[:600])
                if not m or m.group(1) not in callables:
                    continue
                try:
                    d = json.loads(line.strip().rstrip(","))["data"]
                except Exception:
                    continue
                out[d["callable"]] = d
        return out

    def models(self, callables: Optional[Set[str]] = None) -> Tuple[Dict[str, dict], dict]:
        """(models for ``callables`` (all when None), source-model statistics)."""
        keep: Dict[str, dict] = {}
        stats = {"models": 0, "source_models": 0, "source_models_in_repo": 0,
                 "obscure_models": 0, "issues": 0, "source_model_names": []}
        for o in _iter_jsonl(os.path.join(self.r_dir, "taint-output.json")):
            kind = o.get("kind")
            if kind == "issue":
                stats["issues"] += 1
                continue
            if kind != "model":
                continue
            d = o.get("data") or {}
            name = d.get("callable", "")
            stats["models"] += 1
            if "Obscure" in (d.get("modes") or []):
                stats["obscure_models"] += 1
            if d.get("sources") or d.get("parameter_sources"):
                stats["source_models"] += 1
                if self.in_repo_rel(d.get("filename", ""), d.get("path", "")):
                    stats["source_models_in_repo"] += 1
                if len(stats["source_model_names"]) < 200:
                    stats["source_model_names"].append(name)
            if callables is None or name in callables:
                keep[name] = d
        return keep, stats

    def modules(self) -> Dict[str, str]:
        """module name -> path (as recorded)."""
        if self._modules is None:
            self._modules = {}
            for o in _iter_jsonl(os.path.join(self.r_dir, "modules.json")):
                if o.get("kind") == "module":
                    d = o["data"]
                    self._modules[d["name"]] = d.get("path", "")
        return self._modules

    def module_of_file(self, cond_rel: str) -> str:
        abs_p = self.abs_path(cond_rel)
        for name, p in self.modules().items():
            if p == abs_p or (p and p.endswith("/" + cond_rel)):
                return name
        return L.module_of(abs_p, self.src_root)

    def functions(self) -> Set[str]:
        if self._functions is None:
            self._functions = {o["data"]["name"] for o in _iter_jsonl(os.path.join(self.r_dir, "functions.json"))
                               if o.get("kind") == "function"}
        return self._functions

    def decorator_counts(self) -> List[dict]:
        return [o["data"] for o in _iter_jsonl(os.path.join(self.r_dir, "decorator-counts.json"))
                if o.get("kind") == "decorator_count"]

    def override_graph(self) -> Dict[str, List[str]]:
        p = os.path.join(self.r_dir, "override-graph.json")
        if not os.path.exists(p):
            return {}
        try:
            return json.load(open(p))
        except Exception:
            return {}

    def tier_sidecar(self) -> dict:
        """``r/engine-tiers.json`` — written by ``extract`` only: the T2 / T3
        membership of an excerpt's callables as computed on the full tree
        (``_source_reach``). ``{}`` when absent (every real cond dir)."""
        p = os.path.join(self.r_dir, TIER_SIDECAR)
        if not os.path.exists(p):
            return {}
        try:
            d = json.load(open(p))
        except Exception:
            return {}
        return d if isinstance(d, dict) and d.get("kind") == "engine_tiers" else {}

    def metadata(self) -> dict:
        if self._metadata is None:
            p = os.path.join(self.r_dir, "taint-metadata.json")
            try:
                self._metadata = json.load(open(p)) if os.path.exists(p) else {}
            except Exception:
                self._metadata = {}
        return self._metadata

    def errors(self) -> list:
        p = os.path.join(self.r_dir, "errors.json")
        try:
            return json.load(open(p)) if os.path.exists(p) else []
        except Exception:
            return []


def _sites_of(calls: dict) -> Iterator[CallSite]:
    for key, value in calls.items():
        m = _POS_RE.match(key)
        if not m:
            continue
        art = m.group(5) or ""
        for c in _iter_call_objs(value):
            unresolved = None
            u = c.get("unresolved")
            if u is not None and u is not False:
                if isinstance(u, list):
                    inner = [x for x in u if isinstance(x, list)]
                    flat = [str(x) for grp in inner for x in grp] or [str(x) for x in u if isinstance(x, str)]
                    # the leading "BypassingDecorators" is the resolution mode, not the reason
                    flat = [x for x in flat if x != "BypassingDecorators"] or flat
                    unresolved = flat[0] if flat else "n/a"
                elif isinstance(u, str):
                    unresolved = u
                else:
                    unresolved = "n/a"
            real = [t for t in (c.get("calls") or []) if t.get("target")]
            init = [t for t in (c.get("init_calls") or []) if t.get("target")]
            targets = [t["target"] for t in real]
            inits = [t["target"] for t in init]
            constructor = bool(inits) and not targets
            yield CallSite(key=key, line=int(m.group(1)), col=int(m.group(2)),
                           end_line=int(m.group(3)), end_col=int(m.group(4)),
                           artificial=art, unresolved=unresolved,
                           targets=targets + inits, constructor=constructor,
                           receiver_classes=[str(t.get("receiver_class") or "") for t in real + init])


# --------------------------------------------------------------------------- #
# AST side: locate the call, name its idiom / resolver / key
# --------------------------------------------------------------------------- #
_GUARD_TAG_RE = re.compile(r"\[ctaudit\] resolved dynamic dispatch -> (\d+) targets? \| wall=(.+?):(\d+)\s*$")
GENERATED_MODULE_DOC = "[ctaudit] generated redirectors"


@dataclass
class GeneratedBlock:
    """One ``if __ctaudit_unreachable__:`` block the lowering inserted (cond_B
    trees): its line span and the wall tag of its header comment
    (``wall=<file>:<cond_A line>``; the file is relative to the source root,
    a bare basename in trees lowered before review C1)."""
    start: int
    end: int
    wall_file: str = ""
    wall_line: int = 0
    targets: int = 0

    @property
    def size(self) -> int:
        return self.end - self.start + 1


def _typing_injection_ranges(tree, lines: List[str], blocks: List[GeneratedBlock]) -> List[Tuple[int, int]]:
    """Lines of the ``if TYPE_CHECKING: from <mod> import <Cls...>`` block
    ``dispatch_lowering._inject_type_checking_imports`` adds (inline mode with
    ``candidate_import_module``): a module-level TYPE_CHECKING block whose body
    is only imports of classes that the generated blocks construct
    (``Cls.__new__(Cls)``), plus the ``from typing import TYPE_CHECKING`` line
    directly above it when present."""
    if not blocks:
        return []
    constructed = set()
    for b in blocks:
        for ln in lines[b.start - 1:b.end]:
            m = re.search(r"=\s*([A-Za-z_]\w*)\.__new__\(\1\)", ln)
            if m:
                constructed.add(m.group(1))
    out: List[Tuple[int, int]] = []
    for node in getattr(tree, "body", []):
        if not (isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING"):
            continue
        if node.orelse or not all(isinstance(s, ast.ImportFrom) for s in node.body):
            continue
        names = {a.asname or a.name for s in node.body for a in s.names}
        if not names or not names <= constructed:
            continue
        start, end = node.lineno, (node.end_lineno or node.lineno)
        if start >= 2 and lines[start - 2].strip() == "from typing import TYPE_CHECKING":
            start -= 1
        out.append((start, end))
    return out


def cond_a_line(line: int, ranges: List[Tuple[int, int]]) -> Optional[int]:
    """Map a cond_B line back to its cond_A line given the generated spans of
    the file (``(start, end)`` inclusive, any order): every span ending above
    the line was inserted — before or after a wall statement — so its size is
    subtracted; a line inside a span is generated (None). Review C1 (c)."""
    shift = 0
    for s, e in ranges:
        if s <= line <= e:
            return None
        if e < line:
            shift += e - s + 1
    return line - shift


def generated_blocks_of(path: str) -> List[GeneratedBlock]:
    """The guard blocks of one cond_B file (parsed; [] on a syntax error)."""
    try:
        return list(_FileIndex(path).generated)
    except Exception:
        return []


class _FileIndex:
    """One parsed wall file: every Call by position, its enclosing scopes and
    statement, the runtime bindings ``links`` already understands.

    Generated code (review C1 (b)): the line ranges of every
    ``if __ctaudit_unreachable__:`` block are indexed (``generated``), and a
    generated redirector module (docstring ``[ctaudit] generated redirectors``)
    is flagged whole (``generated_module``) — engine sites inside them are
    ``generated``: never a wall, never an environment gap."""

    def __init__(self, path: str, source: str = ""):
        self.path = path
        self.source = source if source else open(path, encoding="utf-8", errors="replace").read()
        self.tree = ast.parse(self.source)
        self.lines = self.source.splitlines()
        self.calls: Dict[Tuple[int, int], List[ast.Call]] = collections.defaultdict(list)
        self.by_line: Dict[int, List[ast.Call]] = collections.defaultdict(list)
        self.scopes: Dict[int, list] = {}        # id(call) -> [enclosing defs/classes, innermost first]
        self.generated: List[GeneratedBlock] = []
        self.generated_module = bool(self.tree.body and isinstance(self.tree.body[0], ast.Expr)
                                     and isinstance(self.tree.body[0].value, ast.Constant)
                                     and isinstance(self.tree.body[0].value.value, str)
                                     and self.tree.body[0].value.value.lstrip().startswith(GENERATED_MODULE_DOC))
        self._walk(self.tree, [])
        self.generated.sort(key=lambda b: b.start)
        self.generated_extra: List[Tuple[int, int]] = _typing_injection_ranges(self.tree, self.lines, self.generated)
        self.stmts, self.chains = L._stmt_map(self.tree)
        self.bindings = L._runtime_bindings(self.tree)
        self.empty_spec = dl._coerce_spec({"detect_subscript": True})

    def generated_ranges(self) -> List[Tuple[int, int]]:
        """Every generated line span (guard blocks + the TYPE_CHECKING
        injection), sorted."""
        return sorted([(b.start, b.end) for b in self.generated] + list(self.generated_extra))

    def in_generated(self, line: int) -> bool:
        if self.generated_module:
            return True
        return any(s <= line <= e for s, e in self.generated_ranges())

    def cond_a_line(self, line: int) -> Optional[int]:
        """The line ``line`` of this (cond_B) file had before the generated
        spans were inserted; None when it lies inside one."""
        return cond_a_line(line, self.generated_ranges())

    def _walk(self, node, stack):
        # a generated ``if __ctaudit_unreachable__:`` block (cond_B trees) holds
        # calls the engine resolved by construction — never wall candidates
        if dl._is_generated_block(node):
            header = self.lines[node.lineno - 1] if node.lineno - 1 < len(self.lines) else ""
            m = _GUARD_TAG_RE.search(header)
            self.generated.append(GeneratedBlock(
                start=node.lineno, end=(node.end_lineno or node.lineno),
                wall_file=(m.group(2) if m else ""), wall_line=(int(m.group(3)) if m else 0),
                targets=(int(m.group(1)) if m else 0)))
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

    def generated_at(self, line: int) -> Optional[GeneratedBlock]:
        return next((b for b in self.generated if b.start <= line <= b.end), None)

    def find(self, line: int, col: int, end_line: int, end_col: int, callee_hint: str = "") -> Tuple[Optional[ast.Call], bool]:
        """(call, exact). Exact start+end; else same start; else same line and
        the same callee text (positions drift when a file was edited)."""
        cands = self.calls.get((line, col), [])
        for c in cands:
            if (c.end_lineno, c.end_col_offset) == (end_line, end_col):
                return c, True
        if cands:
            return cands[0], True
        for c in self.by_line.get(line, []):
            if callee_hint and ast.unparse(c.func) == callee_hint:
                return c, False
        return None, False

    def qualname(self, call: ast.Call, module: str) -> str:
        names = [n.name for n in reversed(self.scopes.get(id(call), []))]
        return ".".join([module] + names) if module else ".".join(names)

    def def_chain(self, call: ast.Call) -> list:
        return [n for n in self.scopes.get(id(call), []) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _spans(node, pos) -> bool:
    """``pos`` = (line, col) lies inside the source span of ``node``."""
    try:
        return ((node.lineno, node.col_offset) <= tuple(pos)
                <= (node.end_lineno or node.lineno, node.end_col_offset or 0))
    except Exception:
        return False


def _loop_target_names(target) -> List[str]:
    """Names a loop / assignment target binds, including tuple unpacking
    ``for name, handler in registry.items()`` (review M1) and ``*rest``."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for el in target.elts for n in _loop_target_names(el)]
    if isinstance(target, ast.Starred):
        return _loop_target_names(target.value)
    return []


class _ScopeBindings:
    """Every binding of one scope's own statements (``dl._own_stmt_walk``
    order), keyed by the bound name — built once per (tree, scope) and cached
    on the tree by ``_scope_bindings`` (review minor: find_reads re-parse /
    describe_call cost — ``_binding_of`` used to re-walk the def body and the
    module body for every call of a file; now each scope is walked once per
    file). The position rules stay in ``_binding_of``: a statement binding
    counts only before the call, a loop's iterable is read before the loop
    binds, a comprehension binds only the calls inside it."""

    __slots__ = ("events", "comps", "params")

    def __init__(self, scope, tree):
        # name -> [(line, col, kind, node)] in walk order; kind 'value' (node = the
        # value), 'loop' (node = the iterable), 'import' / 'def' / 'class' (node = the statement)
        self.events: Dict[str, list] = {}
        # comprehensions in walk order: (node, [(names bound by generator i, its iterable), ...])
        self.comps: list = []
        self.params: set = L._param_names(scope) if scope is not None else set()
        body = scope.body if scope is not None else getattr(tree, "body", [])
        for node in dl._own_stmt_walk(body):
            if isinstance(node, ast.comprehension):
                continue                      # bound through its owner just below
            if isinstance(node, _COMPREHENSIONS):
                self.comps.append((node, [(_loop_target_names(g.target), g.iter) for g in node.generators]))
                continue
            ln, col = getattr(node, "lineno", 0), getattr(node, "col_offset", 0)
            if isinstance(node, ast.Assign):
                # ``fn, keys = REG[name]`` (langchain load_tools): the callee is
                # an element of the value REG[name] selected — the same binding
                # as ``fn = REG[name]`` for the selection kind (review M1)
                for t in node.targets:
                    for n in _loop_target_names(t):
                        self._add(n, ln, col, "value", node.value)
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and isinstance(node.target, ast.Name) \
                    and node.value is not None:
                self._add(node.target.id, ln, col, "value", node.value)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                for n in _loop_target_names(node.target):
                    self._add(n, ln, col, "loop", node.iter)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for it in node.items:
                    if isinstance(it.optional_vars, ast.Name):
                        self._add(it.optional_vars.id, ln, col, "value", it.context_expr)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for a in node.names:
                    self._add(a.asname or a.name.split(".")[0], ln, col, "import", node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._add(node.name, ln, col, "def", node)
            elif isinstance(node, ast.ClassDef):
                self._add(node.name, ln, col, "class", node)

    def _add(self, name: str, ln: int, col: int, kind: str, node) -> None:
        self.events.setdefault(name, []).append((ln, col, kind, node))


def _scope_bindings(scope, tree) -> _ScopeBindings:
    """The cached ``_ScopeBindings`` of ``scope`` (None = the module body) in
    ``tree``; the cache lives on the tree, so it dies with it."""
    cache = getattr(tree, "_ctaudit_bindings", None)
    if cache is None:
        cache = {}
        try:
            tree._ctaudit_bindings = cache
        except Exception:                      # not an AST node: no cache
            return _ScopeBindings(scope, tree)
    key = id(scope) if scope is not None else 0
    hit = cache.get(key)
    if hit is None or hit[0] is not scope:
        hit = cache[key] = (scope, _ScopeBindings(scope, tree))
    return hit[1]


def _binding_of(name: str, scopes: list, tree, before, depth: int = 0):
    """How ``name`` was bound where the call sees it: ('subscript'|'getattr'|
    'resolver_call'|'boolop'|'attr'|'name'|'loop'|'param'|'import'|'def'|'class'|'other',
    node) or None. Innermost scope first, then the module; the latest binding
    before the call position (``before`` = (line, col) or a line) wins inside
    a scope. A parameter is the binding when nothing in the body rebinds it.
    The bindings of a scope come from ``_scope_bindings`` (walked once per
    file), only the position tests run per call."""
    if isinstance(before, int):
        before = (before, 0)
    chain = [s for s in scopes if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]

    for scope in chain + [None]:
        sb = _scope_bindings(scope, tree)
        # ``{k: v() for k, v in REG.items()}``: the generator binds v for the
        # calls inside the comprehension — the innermost scope, so it shadows
        # every binding of the def. A comprehension is its own scope: ``names =
        # [t.name for t in xs]`` written after ``t = REG[k]; t.run()`` never
        # rebinds the ``t`` of that call, and a comprehension has no position
        # of its own, so it must not enter the latest-binding race below
        # (review M1 repair: it used to skip the position check and win that
        # race). The first generator's iterable is evaluated in the enclosing
        # scope, so a call there is not bound here.
        for comp, gens in sb.comps:
            if not _spans(comp, before) or _spans(gens[0][1], before):
                continue
            it = next((it for names, it in gens if name in names), None)
            if it is not None:
                return ("loop", it)
        best = None
        for ln, col, kind, node in sb.events.get(name, ()):
            if scope is not None and (ln, col) >= before:
                continue
            if kind == "loop" and _spans(node, before):
                # the iterable is evaluated before the loop binds its target:
                # ``for k, value in value.items()`` reads the OUTER value
                continue
            if best is None or ln >= best[0]:
                best = (ln, kind, node)
        if best:
            _, kind, node = best
            if kind == "value":
                return _describe_value(node, scopes, tree, before, depth)
            return (kind, node)
        if scope is not None and name in sb.params:
            return ("param", scope)
    return None


def _describe_value(v, scopes, tree, before, depth):
    if isinstance(v, ast.Await):
        v = v.value
    if isinstance(v, ast.Subscript):
        return ("subscript", v)
    if dl._is_getattr_call(v):
        return ("getattr", v)
    if isinstance(v, ast.Call):
        return ("resolver_call", v)
    if isinstance(v, ast.BoolOp):
        return ("boolop", v)
    if isinstance(v, ast.Attribute):
        return ("attr", v)
    if isinstance(v, ast.Name) and depth < 2:
        inner = _binding_of(v.id, scopes, tree, before, depth + 1)
        return inner or ("name", v)
    if isinstance(v, (ast.Lambda, ast.IfExp)):
        return ("other", v)
    return ("other", v)


def _resolver_key(kind: str, node) -> Tuple[str, str]:
    """(resolver, key) strings for a binding / callee shape."""
    try:
        if kind == "subscript":
            return ast.unparse(node.value), ast.unparse(node.slice)
        if kind == "getattr":
            args = node.args
            return (f"getattr({ast.unparse(args[0])})" if args else "getattr",
                    ast.unparse(args[1]) if len(args) > 1 else "")
        if kind == "resolver_call":
            return ast.unparse(node.func), (ast.unparse(node.args[0]) if node.args else
                                            (ast.unparse(node.keywords[0].value) if node.keywords else ""))
        if kind == "boolop":
            return " or ".join(ast.unparse(e) for e in node.values), ""
        if kind == "attr":
            return ast.unparse(node), ""
        if kind == "loop":
            return f"iter({ast.unparse(node)})", ""
        if kind == "param":
            return f"param of {node.name}", ""
        if kind in ("import", "def", "class"):
            return kind, ""
        if kind == "name":
            return ast.unparse(node), ""
    except Exception:
        pass
    return "", ""


def describe_call(call: ast.Call, fx: _FileIndex) -> dict:
    """Idiom, resolver, key and receiver binding of one call — the AST side of
    the row, using the same vocabulary as ``links._idiom_of``."""
    fn = call.func
    scopes = fx.scopes.get(id(call), [])
    out = {"idiom": "other", "resolver": "", "key_expr": "", "receiver_binding": "",
           "members": [], "members_open": False}

    def boolop_members(node):
        mem = [L._final(e) or ast.unparse(e) for e in node.values]
        open_alt = any(not isinstance(e, (ast.Name, ast.Attribute)) for e in node.values)
        params = set()
        for s in scopes:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params |= L._param_names(s)
        open_alt = open_alt or any(isinstance(e, ast.Name) and e.id in params for e in node.values)
        return mem, open_alt

    if isinstance(fn, ast.Subscript):
        out["idiom"] = "subscript"
        out["resolver"], out["key_expr"] = _resolver_key("subscript", fn)
    elif dl._is_getattr_call(fn):
        out["idiom"] = "getattr"
        out["resolver"], out["key_expr"] = _resolver_key("getattr", fn)
    elif isinstance(fn, ast.Call):
        out["idiom"] = "call_call"
        out["resolver"] = ast.unparse(fn.func)
        out["key_expr"] = ast.unparse(fn.args[0]) if fn.args else ""
    elif isinstance(fn, ast.Name):
        b = _binding_of(fn.id, scopes, fx.tree, (call.lineno, call.col_offset))
        kind = b[0] if b else ""
        if kind == "boolop":
            out["idiom"] = "boolop"
            out["members"], out["members_open"] = boolop_members(b[1])
        elif kind in ("subscript", "getattr"):
            out["idiom"] = kind
        elif kind == "resolver_call":
            out["idiom"] = "higher_order"
        elif kind == "param":
            out["idiom"] = "param_call"
        elif kind == "loop":
            out["idiom"] = "loop_call"
        elif kind == "attr":
            out["idiom"] = "attr_call"
        elif kind in ("import", "def", "class", "name"):
            out["idiom"] = "name_call"
        else:
            out["idiom"] = "higher_order" if kind else "name_call"
        if b:
            out["resolver"], out["key_expr"] = _resolver_key(kind, b[1])
            out["receiver_binding"] = kind
    elif isinstance(fn, ast.Attribute):
        recv = fn.value.value if isinstance(fn.value, ast.Await) else fn.value
        if isinstance(recv, ast.Name) and recv.id not in ("self", "cls"):
            b = _binding_of(recv.id, scopes, fx.tree, (call.lineno, call.col_offset))
            kind = b[0] if b else ""
            out["idiom"] = "method_call"
            out["receiver_binding"] = kind or "unknown"
            if b:
                out["resolver"], out["key_expr"] = _resolver_key(kind, b[1])
                if kind == "boolop":
                    out["members"], out["members_open"] = boolop_members(b[1])
        elif isinstance(recv, (ast.Subscript, ast.BoolOp, ast.Call)):
            # inline receiver (review M1): ``self.tools[name].run(a)``,
            # ``REG[k].m()``, ``getattr(o, k).m()``, ``(a or b).m()`` select the
            # receiver at the call site — the same wall as ``t = REG[k]; t.m()``
            # (``links._idiom_of`` mirrors this). A call-bound receiver
            # (``factory().m()``) is method_call/resolver_call: untyped, not a
            # selection, exactly like ``t = factory(); t.m()``.
            kind, node = _describe_value(recv, scopes, fx.tree, (call.lineno, call.col_offset), 0)
            out["idiom"] = "method_call"
            out["receiver_binding"] = kind
            out["resolver"], out["key_expr"] = _resolver_key(kind, node)
            if kind == "boolop":
                out["members"], out["members_open"] = boolop_members(node)
        else:
            out["idiom"] = "attr_call"
            out["resolver"] = ast.unparse(fn.value)
            out["key_expr"] = fn.attr          # the attribute name (spec: wall_attr_names)
            out["receiver_binding"] = "self" if (isinstance(fn.value, ast.Name)) else "attr"
    return out


def _key_is_constant(key_expr: str) -> bool:
    """``REG['x']`` / ``getLogger(__name__)`` select statically — not a dispatch."""
    if not key_expr:
        return False
    try:
        node = ast.parse(key_expr, mode="eval").body
    except Exception:
        return False
    return isinstance(node, ast.Constant) or (isinstance(node, ast.Name) and node.id in ("__name__", "__package__", "__file__", "__spec__"))


def _def_body_trivial(fn) -> Tuple[bool, str]:
    """A def the engine can name but cannot carry taint through: abstract, or
    a body that is only ``pass`` / ``...`` / ``raise`` (after the docstring)."""
    if any(L._dec_name(d) in ("abstractmethod", "abstractproperty") for d in fn.decorator_list):
        return True, "abstractmethod"
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    if not body:
        return True, "docstring only"
    kinds = set()
    for st in body:
        if isinstance(st, ast.Pass):
            kinds.add("pass")
        elif isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant) and st.value.value is Ellipsis:
            kinds.add("...")
        elif isinstance(st, ast.Raise):
            kinds.add("raise")
        else:
            return False, ""
    return True, "/".join(sorted(kinds))


def _stub_kind(fn) -> str:
    """Review C5 policy: ``"abstract"`` when the def is decorated
    ``@abstractmethod`` / ``@abc.abstractmethod`` (``abstractproperty`` too) or
    its body raises ``NotImplementedError``; ``"empty"`` otherwise (``pass`` /
    docstring only / ``...`` / any other raise). Only meaningful for a def
    ``_def_body_trivial`` accepted."""
    if any(L._dec_name(d) in ("abstractmethod", "abstractproperty") for d in fn.decorator_list):
        return "abstract"
    for st in fn.body:
        if isinstance(st, ast.Raise) and st.exc is not None:
            exc = st.exc.func if isinstance(st.exc, ast.Call) else st.exc
            name = exc.id if isinstance(exc, ast.Name) else (exc.attr if isinstance(exc, ast.Attribute) else "")
            if name in ("NotImplementedError", "NotImplemented"):
                return "abstract"
    return "empty"


class _DefIndex:
    """qualname -> def node for in-repo files (resolved lazily per module)."""

    def __init__(self, run: EngineRun):
        self.run = run
        self._by_module: Dict[str, Dict[str, ast.AST]] = {}
        self._mod_to_file: Dict[str, str] = {}
        for name, p in run.modules().items():
            rel = run.in_repo_rel("*", p) if p else ""
            if rel:
                self._mod_to_file[name] = rel

    def lookup(self, qualname: str) -> Tuple[Optional[ast.AST], str]:
        """(def node, cond-relative file) for an in-repo qualname, else (None, '')."""
        node, rel, _mod = self.lookup_ex(qualname)
        return node, rel

    def lookup_ex(self, qualname: str) -> Tuple[Optional[ast.AST], str, str]:
        """(def node, cond-relative file, module) — the module the qualname
        resolved through, needed to read that module's imports."""
        parts = qualname.split(".")
        for i in range(len(parts) - 1, 0, -1):
            mod = ".".join(parts[:i])
            rel = self._mod_to_file.get(mod)
            if not rel:
                continue
            defs = self._defs(mod, rel)
            node = defs.get(".".join(parts[i:]))
            return node, rel, mod
        return None, "", ""

    def in_repo_module(self, mod: str) -> bool:
        return mod in self._mod_to_file

    def imports_of(self, mod: str) -> Dict[str, str]:
        """local name -> absolute dotted target of the module's top-level
        imports (``from a.b import C as D`` -> D: a.b.C, ``import a.b`` -> a: a;
        relative imports resolved against the module)."""
        if not hasattr(self, "_imports"):
            self._imports: Dict[str, Dict[str, str]] = {}
        if mod in self._imports:
            return self._imports[mod]
        out: Dict[str, str] = {}
        rel = self._mod_to_file.get(mod, "")
        try:
            tree = ast.parse(open(self.run.abs_path(rel), encoding="utf-8", errors="replace").read()) if rel else None
        except Exception:
            tree = None
        for node in (getattr(tree, "body", []) if tree is not None else []):
            if isinstance(node, ast.Import):
                for a in node.names:
                    out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom):
                base = L.resolve_relative_module(node.module, node.level or 0, rel, mod)
                for a in node.names:
                    if a.name != "*":
                        out[a.asname or a.name] = f"{base}.{a.name}" if base else a.name
        self._imports[mod] = out
        return out

    def _defs(self, mod: str, rel: str) -> Dict[str, ast.AST]:
        if mod in self._by_module:
            return self._by_module[mod]
        out: Dict[str, ast.AST] = {}
        try:
            tree = ast.parse(open(self.run.abs_path(rel), encoding="utf-8", errors="replace").read())
        except Exception:
            self._by_module[mod] = out
            return out

        def walk(node, prefix):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    q = f"{prefix}.{child.name}" if prefix else child.name
                    # ``@overload`` stubs precede the implementation and have
                    # ``...`` bodies: the engine analyses the implementation
                    if not (isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and any(L._dec_name(d) == "overload" for d in child.decorator_list)):
                        out[q] = child if not isinstance(out.get(q), ast.ClassDef) else out[q]
                    walk(child, q)
                else:
                    walk(child, prefix)
        walk(tree, "")
        self._by_module[mod] = out
        return out


class _ClassHierarchy:
    """Ancestor relation over qualified class names, from two engine-side
    sources (review C5): ``override-graph.json`` (``B.m -> [C, ...]`` says C is
    a subclass of B) and the in-repo ``ClassDef`` bases resolved through each
    module's imports (re-exports followed inside the repo). Used to keep, for
    an S2 stub wall, only the overrides that a receiver of static type R can
    reach: R itself or a transitive subclass of R."""

    def __init__(self, defs: _DefIndex, overrides: Dict[str, List[str]]):
        self.defs = defs
        self._og: Dict[str, Set[str]] = collections.defaultdict(set)
        for key, subs in (overrides or {}).items():
            owner = key.rsplit(".", 1)[0] if "." in key else ""
            if owner:
                for c in subs or []:
                    self._og[c].add(owner)
        self._bases: Dict[str, Set[str]] = {}

    def _resolve_class(self, qual: str, depth: int = 0) -> str:
        """Follow in-repo re-exports: ``pkg.Cls`` imported in ``pkg/__init__``
        from ``pkg.impl`` -> ``pkg.impl.Cls`` (Pysa names the definition)."""
        if depth > 5 or not qual or "." not in qual:
            return qual
        node, _rel, mod = self.defs.lookup_ex(qual)
        if isinstance(node, ast.ClassDef):
            return qual
        if not mod or node is not None:
            return qual
        local = qual[len(mod) + 1:]
        head = local.split(".")[0]
        target = self.defs.imports_of(mod).get(head)
        if not target:
            return qual
        rest = local[len(head):]
        return self._resolve_class(target + rest, depth + 1)

    def bases_of(self, cls: str) -> Set[str]:
        if cls in self._bases:
            return self._bases[cls]
        out: Set[str] = set(self._og.get(cls, ()))
        self._bases[cls] = out                      # cycle guard
        node, _rel, mod = self.defs.lookup_ex(cls)
        if isinstance(node, ast.ClassDef) and mod:
            imports = self.defs.imports_of(mod)
            for b in node.bases:
                name = ""
                if isinstance(b, ast.Name):
                    name = imports.get(b.id) or (f"{mod}.{b.id}" if self.defs.lookup_ex(f"{mod}.{b.id}")[0] is not None else "")
                elif isinstance(b, ast.Attribute):
                    try:
                        dotted = ast.unparse(b)
                    except Exception:
                        dotted = ""
                    root = dotted.split(".")[0]
                    name = (imports.get(root, root) + dotted[len(root):]) if dotted else ""
                if name:
                    out.add(self._resolve_class(name))
        return out

    def is_protocol(self, cls: str) -> bool:
        """A ``typing.Protocol`` class: structural, never in the override
        graph — its nominal name says nothing about the runtime receiver."""
        node, _rel, _mod = self.defs.lookup_ex(self._resolve_class(cls))
        if not isinstance(node, ast.ClassDef):
            return False
        for b in node.bases:
            name = b.id if isinstance(b, ast.Name) else (b.attr if isinstance(b, ast.Attribute) else "")
            if isinstance(b, ast.Subscript):
                v = b.value
                name = v.id if isinstance(v, ast.Name) else (v.attr if isinstance(v, ast.Attribute) else "")
            if name == "Protocol":
                return True
        return False

    def is_subclass(self, cls: str, ancestor: str) -> bool:
        """``cls`` is ``ancestor`` or transitively derives from it."""
        if not cls or not ancestor:
            return False
        cls, ancestor = self._resolve_class(cls), self._resolve_class(ancestor)
        if cls == ancestor:
            return True
        seen, frontier = set(), [cls]
        while frontier:
            c = frontier.pop()
            if c in seen:
                continue
            seen.add(c)
            for b in self.bases_of(c):
                if b == ancestor or self._resolve_class(b) == ancestor:
                    return True
                if b not in seen:
                    frontier.append(b)
        return False


# --------------------------------------------------------------------------- #
# Catalogue
# --------------------------------------------------------------------------- #
def load_catalog(path: str = "") -> List[dict]:
    """The ``dispatch`` rows of the presets file
    (``{"<preset>": {"dispatch": [{"api": ..., "impl": [...]}, ...]}}``), the
    same rows ``catalog.dispatch_rows`` serves (review K7: one vocabulary).
    ``FALLBACK_DISPATCH`` only when the presets file is missing."""
    rows: Dict[str, dict] = {}
    path = path or os.path.join(_HERE, "spec.presets.json")
    if path and os.path.exists(path):
        try:
            presets = json.load(open(path))
        except Exception:
            presets = {}
        for name, preset in presets.items():
            if not isinstance(preset, dict) or name.startswith("_"):
                continue
            for r in preset.get("dispatch", []) or []:
                if isinstance(r, str):
                    r = {"api": r}
                r = dict(r)
                r.setdefault("framework", name)
                r.setdefault("impl", [])
                rows[r["api"]] = r
        return list(rows.values())
    # no presets file at all: the minimal built-in rows (short suffixes)
    return [dict(r) for r in FALLBACK_DISPATCH]


def catalog_match(target: str, catalog: List[dict]) -> Optional[dict]:
    t = _strip_overrides(target)
    for row in catalog:
        api = row["api"]
        if t == api or t.endswith("." + api):
            return row
    return None


# --------------------------------------------------------------------------- #
# Scan
# --------------------------------------------------------------------------- #
def _positions_in(obj, acc: List[Tuple[int, int, int]]):
    if isinstance(obj, dict):
        if "line" in obj and isinstance(obj.get("line"), int):
            acc.append((obj["line"], obj.get("start", 0) or 0, obj.get("end", 0) or 0))
        for v in obj.values():
            _positions_in(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _positions_in(v, acc)


def _reason_kind(reason: str) -> str:
    return UNRESOLVED_REASONS.get(reason, ("other", ""))[0]


def _source_reach(records: List[CGRecord], models: Dict[str, dict],
                  overrides: Dict[str, List[str]]) -> Tuple[Set[str], Set[str], Dict[str, Set[str]], Set[str]]:
    """Source-derived taint per in-repo callable, from the engine's own
    artifacts: ``t2`` = callables whose model carries a source (``sources`` /
    ``parameter_sources``) or that call a return-source model; ``reach`` =
    callables reachable from ``t2`` over the in-repo call graph (``Overrides{X}``
    expanded through the override graph). Shared by ``scan`` (the tiers) and
    ``extract`` (the ``engine-tiers.json`` side file), so what an excerpt
    records is exactly what a scan of the full tree computes.
    Returns ``(t2, reach, adjacency, return_source_models)``."""
    in_repo_callables = {r.callable for r in records}

    def expand_overrides(t: str) -> List[str]:
        m = _OVERRIDES_RE.match(t)
        if not m:
            return [t]
        base = m.group(1)
        meth = base.rsplit(".", 1)[-1]
        return [base] + [f"{c}.{meth}" for c in overrides.get(base, [])]

    return_source_models = {n for n, m in models.items() if m.get("sources")}
    t2: Set[str] = set()
    adjacency: Dict[str, Set[str]] = collections.defaultdict(set)
    for r in records:
        m = models.get(r.callable) or {}
        if m.get("sources") or m.get("parameter_sources"):
            t2.add(r.callable)
        for s in r.sites:
            for t in s.targets:
                for tt in expand_overrides(t):
                    adjacency[r.callable].add(tt)
                    if tt in return_source_models:
                        t2.add(r.callable)
    reach: Set[str] = set()
    frontier = list(t2)
    while frontier:
        c = frontier.pop()
        for n in adjacency.get(c, ()):
            if n in in_repo_callables and n not in reach and n not in t2:
                reach.add(n)
                frontier.append(n)
    return t2, reach, adjacency, return_source_models


def scan(cond_dir: str, src_root: str = "", catalog_path: str = "", include_all: bool = False,
         r_dir: str = "", disable=()) -> ScanResult:
    """``disable`` (leave-one-out ablation): any of "S1" (unresolved rows),
    "S2" (stub / obscure rows), "S3" (dispatch rows) — the disabled class is
    treated as ``resolved`` (not a wall)."""
    disable = {d.strip().upper() for d in (disable or ()) if d}
    run = EngineRun(cond_dir, src_root=src_root, r_dir=r_dir)
    catalog = load_catalog(catalog_path)
    overrides = run.override_graph()
    records = list(run.iter_call_graph(in_repo_only=True))
    in_repo_callables = {r.callable for r in records}

    # every resolved target of an in-repo real call (for S2/S3 evidence)
    targets: Set[str] = set()
    for r in records:
        for s in r.sites:
            if s.artificial or s.constructor:
                continue
            for t in s.targets:
                targets.add(_strip_overrides(t))
    ho = run.higher_order_records(targets)
    models, mstats = run.models(in_repo_callables | targets)
    defs = _DefIndex(run)

    # dispatch evidence per target: the callee's own record forwards a
    # parameter-carried callable that is a method dispatched on the receiver's
    # dynamic type (``Context.run(self._run)`` -> ``Overrides{BaseTool._run}``).
    # A function that merely takes a callback (``pydantic.Field(default_factory=..)``,
    # ``RunnableLambda(func)``, ``max(key=lambda ..)``) is not a dispatch method.
    def ho_dispatch_targets(t: str) -> List[str]:
        rec = ho.get(t)
        if not rec:
            return []
        out: List[str] = []
        for v in (rec.get("calls") or {}).values():
            for c in _iter_call_objs(v):
                for hp in c.get("higher_order_parameters") or []:
                    for cc in hp.get("calls") or []:
                        tgt = cc.get("target", "")
                        if tgt and _OVERRIDES_RE.match(tgt):
                            out.append(tgt)
        return sorted(set(out))

    def overrides_followed(disp_targets: List[str]) -> int:
        """How many concrete overrides the engine already reaches through the
        dispatch (``Overrides{X}`` with X overridden in the tree)."""
        n = 0
        for t in disp_targets:
            m = _OVERRIDES_RE.match(t)
            if m:
                n += len(overrides.get(m.group(1), []))
        return n

    # source-derived taint per in-repo callable
    t2, reach, adjacency, return_source_models = _source_reach(records, models, overrides)
    # an ``extract`` excerpt keeps no caller records, so T3 (reachable from a
    # source-carrying callable) is not computable from it: union the T2 / T3
    # membership its extraction recorded from the full tree (review minor)
    sidecar = run.tier_sidecar()
    if sidecar:
        t2 |= set(sidecar.get("t2") or ()) & in_repo_callables
        reach |= (set(sidecar.get("reach") or ()) & in_repo_callables) - t2

    def tier_of(callable_name: str, line: int, end_line: int) -> str:
        if callable_name in t2:
            # T1 = a SOURCE-derived frame touches the call (docstring / README);
            # only the source parts of the model are searched — tito / sink
            # summaries also carry positions and made the tier depend on
            # whether a slimmed excerpt (``extract``) kept them (review minor)
            acc: List[Tuple[int, int, int]] = []
            m = models.get(callable_name) or {}
            _positions_in({"sources": m.get("sources"), "parameter_sources": m.get("parameter_sources")}, acc)
            if any(line <= ln <= end_line for ln, _s, _e in acc):
                return "T1"
            return "T2"
        if callable_name in reach:
            return "T3"
        return "none"

    # classify every real in-repo site
    walls: List[EngineWall] = []
    sites_by_file: Dict[str, List[dict]] = collections.defaultdict(list)
    counts = collections.Counter()
    by_reason = collections.Counter()
    env_gaps: List[dict] = []
    catalog_hits = collections.Counter()
    file_index: Dict[str, _FileIndex] = {}
    module_cache: Dict[str, str] = {}
    wid = 0

    def fidx(rel: str) -> Optional[_FileIndex]:
        if rel not in file_index:
            try:
                file_index[rel] = _FileIndex(run.abs_path(rel))
            except Exception:
                file_index[rel] = None      # type: ignore[assignment]
        return file_index[rel]

    hierarchy = _ClassHierarchy(defs, overrides)

    for r in records:
        for s in r.sites:
            if s.artificial or s.constructor:
                continue
            counts["sites"] += 1
            status, reason, eng_targets, disp_targets, confidence = "resolved", "", [], [], "proposed"
            s2_reason = ""
            # review C1 (b): a site inside code the lowering generated (a guard
            # block of a cond_B file, or a generated redirector module) is
            # ``generated`` — counted apart, never a wall, never an env gap.
            # (``_FileIndex._walk`` skips the block, so ``call is None`` there and
            # the static-callee exemption below would not apply.)
            fx0 = fidx(r.file)
            if fx0 is not None and (fx0.generated_module or (fx0.generated and fx0.in_generated(s.line))):
                counts["generated"] += 1
                counts["status:generated"] += 1
                sites_by_file[run.src_rel(r.file)].append(
                    {"line": s.line, "col": s.col, "end_line": s.end_line, "end_col": s.end_col,
                     "status": "generated", "targets": s.targets, "callable": r.callable,
                     "note": "inside a generated lowering block / redirector module"})
                continue
            if s.unresolved is not None:
                status = f"unresolved:{s.unresolved}"
                by_reason[s.unresolved] += 1
                counts["unresolved"] += 1
            else:
                stripped = [_strip_overrides(t) for t in s.targets]
                row = next((catalog_match(t, catalog) for t in stripped if catalog_match(t, catalog)), None)
                if row:
                    status, reason = f"resolved_dispatch:{row['api']}", f"catalog:{row.get('framework', '')}"
                    eng_targets, confidence = list(s.targets), "confirmed"
                    catalog_hits[row["api"]] += 1
                    for t in stripped:
                        disp_targets += ho_dispatch_targets(t)
                    # the catalogue names the impl methods the dispatch forwards
                    # to; when the tree overrides them the engine (typed) already
                    # reaches every override through ``Overrides{owner.impl}``
                    for t in stripped:
                        if catalog_match(t, catalog) is row:
                            owner = t.rsplit(".", 1)[0]
                            for impl in row.get("impl") or []:
                                if overrides.get(f"{owner}.{impl}"):
                                    disp_targets.append(f"Overrides{{{owner}.{impl}}}")
                    disp_targets = sorted(set(disp_targets))
                    n_over = overrides_followed(disp_targets)
                    if n_over:
                        # the engine resolves the dispatch to the override set
                        # itself (typed tree): taint may already cross; the
                        # ablation decides, so the row is proposed, not accepted
                        confidence = "proposed"
                        reason += f"; engine follows {n_over} override(s) — lowering may add nothing"
                else:
                    hod = [(t, ho_dispatch_targets(t)) for t in stripped]
                    hod = [(t, d) for t, d in hod if d]
                    if hod:
                        status = f"resolved_dispatch:{hod[0][0]}"
                        reason = "higher_order_parameters"
                        eng_targets = list(s.targets)
                        disp_targets = sorted({x for _t, d in hod for x in d})
                        n_over = overrides_followed(disp_targets)
                        if n_over:
                            reason += f"; engine follows {n_over} override(s)"
                    else:
                        # S2: an in-repo callee the engine cannot see into
                        stub, obscure = [], []
                        stub_kind: Dict[str, str] = {}      # target -> abstract | empty (review C5 policy)
                        for t in s.targets:
                            if _OVERRIDES_RE.match(t):
                                continue          # the engine follows the override set
                            node, rel = defs.lookup(t)
                            if node is not None and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                triv, why = _def_body_trivial(node)
                                if triv:
                                    stub.append((t, why))
                                    stub_kind[t] = _stub_kind(node)
                                    continue
                            m = models.get(t)
                            if m and "Obscure" in (m.get("modes") or []) and rel:
                                obscure.append(t)
                        if stub and len(stub) == len([t for t in s.targets if not _OVERRIDES_RE.match(t)]):
                            status, reason = "resolved_stub", "; ".join(f"{t}: {w}" for t, w in stub)
                            eng_targets, confidence = [t for t, _ in stub], "confirmed"
                            # the engine's own override graph names the implementations of the
                            # stub method: the destination set of this wall from the engine's
                            # data — restricted (review C5) to the classes a receiver of the
                            # recorded static type can actually be: the receiver_class itself or
                            # a transitive subclass (class hierarchy from override-graph.json +
                            # the in-repo ClassDef bases). A receiver whose subclasses override
                            # nothing (``ChatAgent`` for ``Agent._validate_tools``) has no
                            # candidate: the bare resolution was exact — not a wall.
                            recv = s.receiver_class
                            # a ``typing.Protocol`` receiver / owner (SK's
                            # ``self.definition.deserialize``) is structural: no
                            # override rows exist and the nominal class is not the
                            # runtime type — treated as an unknown receiver
                            if recv and (hierarchy.is_protocol(recv)
                                         or any(hierarchy.is_protocol(t.rsplit(".", 1)[0]) for t, _w in stub)):
                                recv = ""
                            n_all = 0
                            for t, _w in stub:
                                meth = t.rsplit(".", 1)[-1]
                                owner = t.rsplit(".", 1)[0]
                                subs = list(overrides.get(t, []))
                                n_all += len(subs)
                                if recv and recv != owner and not hierarchy.is_subclass(owner, recv):
                                    subs = [c for c in subs if hierarchy.is_subclass(c, recv)]
                                disp_targets += [f"{c}.{meth}" for c in subs]
                            disp_targets = sorted(set(disp_targets))
                            if not recv:
                                s2_reason = "receiver_unknown"
                            elif disp_targets:
                                s2_reason = "receiver_subclasses"
                            else:
                                s2_reason = "receiver_subclass_no_overrides"
                                abstract = [t for t, _w in stub if stub_kind.get(t) == "abstract"]
                                if abstract:
                                    # review C5 policy: an ABSTRACT stub (@abstractmethod /
                                    # raises NotImplementedError) whose receiver — the owner
                                    # itself or a subclass that never implements it — has no
                                    # in-tree override candidate is still a wall (the engine
                                    # names a callee it cannot carry taint into), just an
                                    # UNLOWERABLE one: it stays resolved_stub with no
                                    # dispatch target, proposed and off (``_suggest``), and
                                    # residual() keeps counting it (``residual_unlowerable``)
                                    confidence = "proposed"
                                    reason = ("unlowerable: no in-tree implementation of " + ", ".join(abstract)
                                              + f" (receiver {recv}"
                                              + (f"; {n_all} override(s) of the base belong to other branches)" if n_all else ")"))
                                else:
                                    # an EMPTY stub (pass / docstring / ...) on a concrete
                                    # receiver nothing overrides: the bare resolution was
                                    # exact — not a wall
                                    status = "resolved"
                                    reason = (f"resolved_stub: receiver {recv} has no overriding subclass "
                                              f"({n_all} override(s) of the base belong to other branches)"
                                              if n_all else f"resolved_stub: receiver {recv} — no override of the stub anywhere")
                        elif obscure:
                            status, reason = "resolved_obscure", "Obscure model (no analysable body)"
                            eng_targets, confidence = obscure, "confirmed"
            if (("S1" in disable and status.startswith("unresolved:"))
                    or ("S2" in disable and status in ("resolved_stub", "resolved_obscure"))
                    or ("S3" in disable and status.startswith("resolved_dispatch"))):
                status, reason, eng_targets, disp_targets = "resolved", "", [], []
            counts["status:" + status.split(":")[0]] += 1
            site_row = {"line": s.line, "col": s.col, "end_line": s.end_line, "end_col": s.end_col,
                        "status": status, "targets": s.targets, "callable": r.callable,
                        "receiver_class": s.receiver_class, "target_form": s.target_form}
            if s2_reason:
                site_row["s2_reason"] = s2_reason
            if status == "resolved" and reason:
                site_row["note"] = reason
            sites_by_file[run.src_rel(r.file)].append(site_row)
            if status == "resolved":
                continue

            kind = _reason_kind(s.unresolved) if s.unresolved else "wall"
            fx = fidx(r.file)
            call, exact = (fx.find(s.line, s.col, s.end_line, s.end_col) if fx else (None, False))
            desc = describe_call(call, fx) if call is not None else {
                "idiom": "?", "resolver": "", "key_expr": "", "receiver_binding": "",
                "members": [], "members_open": False}
            if status in ("resolved_stub", "resolved_obscure") and call is not None and (
                    desc["idiom"] == "name_call" or ast.unparse(call.func).startswith("super()")):
                # a stub reached by its own static name (``error_deprecation()``,
                # ``super().m()``) has nothing to dispatch to: the engine loses
                # taint there because the function raises, not because the
                # callee is selected at runtime — not a wall
                sites_by_file[run.src_rel(r.file)][-1]["status"] = "resolved"
                sites_by_file[run.src_rel(r.file)][-1]["note"] = f"{status}: static callee, not a dispatch"
                counts["status:" + status.split(":")[0]] -= 1
                counts["status:resolved"] += 1
                continue
            if kind == "receiver" and desc["receiver_binding"] not in _RECEIVER_DISPATCH_BINDINGS:
                # ``x.m(...)`` where x came from a call / parameter / loop / an
                # untyped import: a type gap, not a runtime selection
                kind = "env"
            if kind == "dispatch" and desc["idiom"] == "name_call" and desc["receiver_binding"]:
                kind = "env"           # a statically bound name (import / def / class) the engine
                                       # could not type: an import gap. A Name with NO binding in
                                       # sight (star import, global assigned elsewhere) stays a
                                       # proposed / review row (review M1)
            if kind == "dispatch" and desc["idiom"] == "param_call" and call is not None \
                    and isinstance(call.func, ast.Name) and call.func.id in ("cls", "self"):
                kind = "env"           # ``cls(...)`` in a classmethod: the engine's own gap
            if kind == "dispatch" and desc["idiom"] == "attr_call" and s.unresolved != "NonMethodAttribute" \
                    and desc["receiver_binding"] != "attr":
                kind = "env"           # ``self.m(...)`` the engine could not type: not a callable attribute
            if kind == "env" and not include_all:
                env_gaps.append({"file": run.src_rel(r.file), "line": s.line, "col": s.col,
                                 "reason": s.unresolved, "callable": r.callable,
                                 "callee": ast.unparse(call.func) if call is not None else
                                 (fx.lines[s.line - 1].strip() if fx and s.line <= len(fx.lines) else "")})
                continue

            module = module_cache.get(r.file)
            if module is None:
                module = module_cache[r.file] = run.module_of_file(r.file)
            st = fx.stmts.get(id(call)) if (fx and call is not None) else None
            w = EngineWall(
                id=f"E{wid}", file=run.src_rel(r.file), line=s.line, col=s.col,
                end_line=s.end_line, end_col=s.end_col, callable=r.callable,
                callee=(ast.unparse(call.func) if call is not None else ""),
                idiom=desc["idiom"], resolver=desc["resolver"], key_expr=desc["key_expr"],
                receiver_binding=desc["receiver_binding"], members=desc["members"],
                members_open=desc["members_open"],
                engine_status=status, engine_reason=reason or (UNRESOLVED_REASONS.get(s.unresolved, ("", ""))[1] if s.unresolved else ""),
                engine_targets=eng_targets, dispatch_targets=disp_targets,
                receiver_class=s.receiver_class, target_form=s.target_form, s2_reason=s2_reason,
                engine_tier=tier_of(r.callable, s.line, s.end_line),
                confidence=confidence,
                stmt_line=(st.lineno if st is not None else s.line),
                stmt_end_line=((st.end_lineno or st.lineno) if st is not None else s.end_line),
                stmt_kind=(type(st).__name__ if st is not None else ""),
                in_async=bool(fx and call is not None and fx.def_chain(call)
                              and isinstance(fx.def_chain(call)[0], ast.AsyncFunctionDef)),
                taint_args=(dl._taint_args(call) if call is not None else []),
                aligned=(call is not None and exact),
                callable_match=(fx.qualname(call, module) == r.callable) if (fx and call is not None) else False,
            )
            wid += 1
            _suggest(w, kind)
            walls.append(w)

    walls.sort(key=lambda w: ({"T1": 0, "T2": 1, "T3": 2}.get(w.engine_tier, 3), not w.accept,
                              w.file, w.line, w.col))
    for i, w in enumerate(walls):
        w.id = f"E{i}"

    meta = run.metadata()
    stats = meta.get("stats") or {}
    mve = stats.get("model_verification_errors") or []
    gap_by_reason = collections.Counter(g["reason"] for g in env_gaps)
    decorators_in_repo = []
    mod_paths = run.modules()
    for d in run.decorator_counts():
        dec = d.get("decorator", "")
        mod = dec.rsplit(".", 1)[0] if "." in dec else ""
        while mod and mod not in mod_paths:
            mod = mod.rsplit(".", 1)[0] if "." in mod else ""
        if mod and run.in_repo_rel("*", mod_paths.get(mod, "")):
            decorators_in_repo.append({"decorator": dec, "count": d.get("count", 0)})
    functions = run.functions()

    def _in_repo_callable(name: str) -> bool:
        # functions.json carries names only: a callable is in-repo when the
        # longest module prefix of its name maps to an in-repo file
        parts = name.split(".")
        for i in range(len(parts) - 1, 0, -1):
            if defs.in_repo_module(".".join(parts[:i])):
                return True
        return False

    # review M4: "present" used to mean "somewhere on the analysis search path
    # (venv included)", so a framework installed in the venv never made the
    # catalogue stale. ``catalog_status`` is now the IN-REPO status (the tree
    # under analysis; what catalog.stale() reads); ``catalog_status_search_path``
    # keeps the search-path view (venv included)
    matches = {row["api"]: [f for f in functions if f == row["api"] or f.endswith("." + row["api"])] for row in catalog}
    catalog_status = {api: ("present" if any(_in_repo_callable(f) for f in fs) else "absent")
                      for api, fs in matches.items()}
    catalog_status_search_path = {api: ("present" if fs else "absent") for api, fs in matches.items()}
    accepted = [w for w in walls if w.accept]
    if mstats["source_models"] == 0 or (not t2 and mstats["source_models_in_repo"] == 0
                                        and not any(tt in return_source_models for a in adjacency.values() for tt in a)):
        outcome = "no_sources"
    elif not walls:
        outcome = "no_surface"
    elif not accepted:
        outcome = "no_walls"
    else:
        outcome = "ok"
    env = {
        "cond_dir": run.cond_dir, "src_root": run.src_root, "repo": run.repo,
        "pysa_tool": meta.get("tool", ""), "pysa_version": meta.get("version", ""),
        "pysa_version_known": meta.get("version", "") == PYSA_VERSION_KNOWN,
        "files_in_repo": len(run._files), "callables_in_repo": len(in_repo_callables),
        "sites_in_repo": counts["sites"], "unresolved_in_repo": counts["unresolved"],
        "unresolved_by_reason": dict(by_reason),
        "unknown_reasons": sorted(r for r in by_reason if r not in UNRESOLVED_REASONS),
        "env_gaps": len(env_gaps), "env_gaps_by_reason": dict(gap_by_reason),
        "env_gap_rows": env_gaps[:500],
        "model_verification_errors": len(mve),
        "model_verification_error_rows": [{"description": e.get("description", ""), "path": e.get("path", ""),
                                           "line": e.get("line", 0)} for e in mve][:200],
        "skipped_overrides": stats.get("skipped_overrides", []),
        "issues_cond": mstats["issues"] or len(run.errors()),
        "models": mstats["models"], "obscure_models": mstats["obscure_models"],
        "source_models": mstats["source_models"], "source_models_in_repo": mstats["source_models_in_repo"],
        "callables_with_source_taint_in_repo": len(t2), "callables_reachable_from_source_in_repo": len(reach),
        "tier_sidecar": bool(sidecar),
        "decorators_in_repo": decorators_in_repo,
        "catalog_hits": dict(catalog_hits), "catalog_status": catalog_status,
        "catalog_status_search_path": catalog_status_search_path,
        "generated_sites": counts["generated"],
        "outcome": outcome,
    }
    cnt = {"sites": counts["sites"], "unresolved": counts["unresolved"],
           "generated": counts["generated"],
           "walls": len(walls), "accepted": len(accepted),
           "by_status": dict(collections.Counter(w.engine_status.split(":")[0] for w in walls)),
           "by_idiom": dict(collections.Counter(w.idiom for w in walls)),
           "by_tier": dict(collections.Counter(w.engine_tier for w in walls)),
           "env_gaps": len(env_gaps)}
    return ScanResult(walls=walls, env=env, counts=cnt, sites_by_file=dict(sites_by_file))


def _suggest(w: EngineWall, kind: str) -> None:
    """Pre-set the review flag: confirmed rows on, proposed / unexplained rows off."""
    st = w.engine_status
    if st.startswith("unresolved:"):
        reason = st.split(":", 1)[1]
        static_key = _key_is_constant(w.key_expr) and w.idiom != "boolop"
        if kind == "dispatch" and w.idiom in _DISPATCH_IDIOMS and not static_key:
            w.accept, w.confidence = True, "confirmed"
            w.note = f"{reason}; {w.idiom}"
        elif kind == "dispatch" and static_key:
            w.accept, w.confidence = False, "proposed"
            w.note = f"{reason}; {w.idiom} with a constant key — not a runtime selection"
        elif kind == "dispatch" and w.idiom in _DEFERRED_IDIOMS:
            w.accept, w.confidence = False, "proposed"
            w.note = f"{reason}; {w.idiom} — candidates come from callers / the iterated collection (anchoring)"
        elif kind == "receiver" and w.receiver_binding == "boolop" and (w.members_open or not w.members):
            # ``x = kwargs.get('k') or {}`` selects among a call and a literal,
            # not among named callables: an untyped value, not a dispatch
            w.accept, w.confidence = False, "proposed"
            w.note = f"{reason}; receiver bound by an open BoolOp (call / literal alternative)"
        elif kind == "receiver" and w.receiver_binding in _RECEIVER_DISPATCH_BINDINGS and not static_key:
            w.accept, w.confidence = True, "confirmed"
            w.note = f"{reason}; receiver bound by {w.receiver_binding}"
        elif kind == "receiver" and static_key:
            w.accept, w.confidence = False, "proposed"
            w.note = f"{reason}; receiver selected by a constant key"
        elif kind == "env":
            w.accept, w.confidence = False, "proposed"
            w.note = "environment gap (--all)"
        else:
            w.accept, w.confidence = False, "proposed"
            w.note = f"{reason}; idiom {w.idiom} — review"
        if not w.aligned:
            w.accept = False
            w.note += "; position not aligned with the AST"
    elif st == "resolved_stub" or st == "resolved_obscure":
        if st == "resolved_stub" and not w.dispatch_targets and w.s2_reason == "receiver_subclass_no_overrides":
            # review C5 policy: an unlowerable abstract stub — its destination
            # set is empty BY CONSTRUCTION (known receiver type, no in-tree
            # implementation reachable from it): never pre-accepted, nothing
            # to link. Deliberately NOT the ``receiver_unknown`` case (review
            # C5 policy, repair): a typing.Protocol / untyped receiver has no
            # override row by construction and its candidates come from the
            # draft's recovery (decorators / anchors), so that row is
            # pre-accepted like an S1 wall — the draft's ``no_candidates``
            # hint, not this rule, reports a recovery that found nothing
            # (test_suggest_stub_boundary / test_sk_real pin both sides)
            w.accept, w.confidence = False, "proposed"
        else:
            w.accept, w.confidence = True, "confirmed"
        w.note = w.engine_reason
    elif st.startswith("resolved_dispatch:"):
        w.accept = (w.confidence == "confirmed")
        w.note = w.engine_reason
        if not w.accept and not w.engine_reason.startswith("catalog:"):
            w.note += " — no catalogue row; review"
    if w.members_open and w.idiom == "boolop":
        w.note += "; BoolOp has an open alternative (no narrowing)"


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
def render_md(res: ScanResult, title: str = "Engine-discovered walls") -> str:
    out = [f"# {title}", "",
           f"outcome: **{res.env.get('outcome')}** — sites {res.counts['sites']}, unresolved {res.counts['unresolved']}, "
           f"walls {res.counts['walls']} (accepted {res.counts['accepted']}), env gaps {res.counts['env_gaps']}; "
           f"pysa {res.env.get('pysa_version', '')[:7]}" + ("" if res.env.get("pysa_version_known") else " (unverified version)"),
           "",
           "| # | position | callee | idiom | resolver[key] | engine | receiver | tier | origin | conf | accept | note |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for w in res.walls:
        rk = w.resolver + (f"[{w.key_expr}]" if w.key_expr else "")
        if w.members:
            rk = " or ".join(w.members) + (" (open)" if w.members_open else "")
        eng = w.engine_status
        if w.dispatch_targets:
            eng += " -> " + ", ".join(w.dispatch_targets[:3])
        # the receiver's static type, how the engine resolved (plain / overrides)
        # and the S2 candidate restriction (review C5 / K3)
        recv = (w.receiver_class.rsplit(".", 1)[-1] if w.receiver_class else "")
        recv += (f" ({w.target_form})" if w.target_form and recv else (w.target_form or ""))
        recv += (f"; {w.s2_reason}" if w.s2_reason else "")
        out.append(f"| {w.id} | `{w.position}` | `{w.callee}` | {w.idiom} | `{rk}` | {eng} | {recv} | {w.engine_tier} | "
                   f"{w.origin} | {w.confidence} | {'x' if w.accept else ' '} | {w.note} |")
    e = res.env
    out += ["", "## environment", "",
            f"- unresolved by reason: {e.get('unresolved_by_reason')}",
            f"- env gaps (not walls): {e.get('env_gaps')} {e.get('env_gaps_by_reason')}",
            f"- generated sites (lowering blocks / redirector modules, excluded): {res.counts.get('generated', 0)}",
            f"- model verification errors: {e.get('model_verification_errors')}",
            f"- source models: {e.get('source_models')} (in-repo {e.get('source_models_in_repo')}); "
            f"in-repo callables carrying source taint: {e.get('callables_with_source_taint_in_repo')}, "
            f"reachable: {e.get('callables_reachable_from_source_in_repo')}",
            f"- catalogue: hits {e.get('catalog_hits')}; present in the tree "
            f"{[k for k, v in (e.get('catalog_status') or {}).items() if v == 'present']}; "
            f"present on the search path (venv incl.) "
            f"{[k for k, v in (e.get('catalog_status_search_path') or {}).items() if v == 'present']}",
            f"- in-repo decorators: {[(d['decorator'], d['count']) for d in e.get('decorators_in_repo', [])][:12]}"]
    return "\n".join(out) + "\n"


def write_outputs(res: ScanResult, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    json.dump(res.to_dict(), open(os.path.join(out_dir, "engine_walls.json"), "w"), indent=2)
    json.dump(res.env, open(os.path.join(out_dir, "env_report.json"), "w"), indent=2)
    open(os.path.join(out_dir, "walls.md"), "w").write(render_md(res))


# --------------------------------------------------------------------------- #
# residual (cond_B): walls the lowering left behind
# --------------------------------------------------------------------------- #
def residual(cond_b: str, links_json: str = "", src_root: str = "", catalog_path: str = "") -> dict:
    """Taint-reaching (T1/T2) walls still unresolved / stub / obscure in
    cond_B, net of the walls that carry a lowered link (the original call is
    kept by design, so it stays unresolved even when its targets were
    connected).

    Review C1: the sites inside generated blocks are excluded by ``scan``
    (``generated_excluded``); walls are keyed by the source-root-relative
    file, and every cond_B line is mapped back to its cond_A line through the
    generated spans of its file (``cond_a_line``), so a lowered wall whose
    block was inserted BEFORE its statement (line shifted) is still netted.
    A ``links.json`` written before C1 holds basename ``file`` values: such
    records are accepted by basename + line (with a warning) only when the
    record's file has no ``/``. ``WallRecord.lowered_line`` (K2), when
    present, nets the wall in cond_B coordinates directly.

    Returns raw / net counts plus, per residual wall: ``file`` (relative),
    ``line_cond_b``, ``line_cond_a``, ``col``, ``callee``, ``engine_status``,
    ``receiver_class`` / ``s2_reason``, ``tier``, ``confidence``.
    ``residual_confirmed`` = net walls whose confidence is ``confirmed`` — the
    walls the draft pre-accepts, i.e. lowerable in principle: the engine (S2
    override set, S3 dispatch) or the draft's candidate recovery (S1, and S2
    ``receiver_unknown`` rows, whose override set is empty by construction)
    names their candidates, and the lowering left them (nothing recovered by
    that name, every candidate unreasonable, a fan-out demotion, or the
    reviewer's off) — review C5 policy (repair): NOT "the lowering had
    candidates". ``residual_unlowerable`` = net walls with ``s2_reason ==
    receiver_subclass_no_overrides`` (review C5 policy: abstract stubs with no
    in-tree implementation — nothing to link by construction). The per-row
    ``confidence`` / ``s2_reason`` / ``engine_status`` tell the two apart."""
    res = scan(cond_b, src_root=src_root, catalog_path=catalog_path)
    lowered_a: Set[Tuple[str, int]] = set()          # (relative file, cond_A line)
    lowered_b: Set[Tuple[str, int]] = set()          # (relative file, cond_B line) from lowered_line
    legacy_a: Set[Tuple[str, int]] = set()           # (basename, cond_A line) — pre-C1 links.json
    lowered_ids: Set[str] = set()
    legacy = False
    src_root_abs = res.env.get("src_root") or ""
    if links_json and os.path.exists(links_json):
        walls, links = L.load_links(links_json)
        ok = {l.wall_id for l in links if l.status == "lowered"}
        for w in walls:
            if w.id not in ok:
                continue
            lowered_ids.add(w.id)
            f = (w.file or "").replace("\\", "/")
            top_level = os.path.isfile(os.path.join(src_root_abs, f))   # flat tree: the basename IS the relative path
            if "/" in f or top_level:
                lowered_a.add((f, w.line))
            else:
                legacy = True
                legacy_a.add((os.path.basename(f), w.line))
            if getattr(w, "lowered_line", 0):
                lowered_b.add((f, int(w.lowered_line)))
        if legacy:
            print(f"[engine_walls] warning: legacy links.json (basename keys): {links_json}", file=sys.stderr)
    raw = [w for w in res.walls if w.engine_tier in ("T1", "T2")
           and (w.engine_status.startswith("unresolved:") or w.engine_status in ("resolved_stub", "resolved_obscure"))]
    ranges_cache: Dict[str, List[Tuple[int, int]]] = {}

    def ranges_of(rel: str) -> List[Tuple[int, int]]:
        if rel not in ranges_cache:
            try:
                ranges_cache[rel] = _FileIndex(os.path.join(src_root_abs, rel)).generated_ranges()
            except Exception:
                ranges_cache[rel] = []
        return ranges_cache[rel]

    net, remapped = [], 0
    rows = []
    for w in raw:
        f = w.file.replace("\\", "/")
        line_a = cond_a_line(w.line, ranges_of(f))
        if line_a is None:
            continue                       # inside a generated span (scan should have excluded it)
        if line_a != w.line:
            remapped += 1
        netted = ((f, line_a) in lowered_a or (f, w.line) in lowered_b
                  or (legacy and (os.path.basename(f), line_a) in legacy_a))
        if netted:
            continue
        net.append(w)
        rows.append({"position": w.position, "file": f, "line_cond_b": w.line, "line_cond_a": line_a,
                     "col": w.col, "callee": w.callee, "engine_status": w.engine_status,
                     "receiver_class": w.receiver_class, "s2_reason": w.s2_reason, "tier": w.engine_tier,
                     "confidence": w.confidence})
    # review C5 policy: split the net residual into walls the lowering could have
    # taken (confirmed) and the unlowerable abstract stubs (no in-tree implementation)
    return {"residual_raw": len(raw), "residual": len(net), "lowered_walls": len(lowered_ids),
            "generated_excluded": res.counts.get("generated", 0), "remapped": remapped,
            "legacy_links": legacy,
            "residual_confirmed": sum(1 for w in net if w.confidence == "confirmed"),
            "residual_unlowerable": sum(1 for w in net if w.s2_reason == "receiver_subclass_no_overrides"),
            "rows": rows}


# --------------------------------------------------------------------------- #
# dataset-scan: count-only pass over a call graph without its source tree
# --------------------------------------------------------------------------- #
def dataset_scan(call_graph: str, repo: str = "", limit: int = 30) -> dict:
    """Unresolved in-repo calls per file in a ``call-graph.json`` shipped without
    its tree (TaintP2X dataset: old schema, ``unresolved: true`` without a
    reason). Needs no environment; answers "is there a surface at all?"."""
    hdr = next(_iter_jsonl(call_graph), {})
    repo = repo or (hdr.get("config") or {}).get("repo", "") or ""
    per_file = collections.Counter()
    calls_per_file = collections.Counter()
    by_reason = collections.Counter()
    rows: List[dict] = []
    n_records = 0
    schema = "?"          # decided by the first record's shape, not the header
                          # (both schemas carry ``file_version`` — review minor)
    with open(call_graph, encoding="utf-8", errors="replace") as f:
        for line in f:
            head = line[:600]
            if not head.startswith('{"kind":"call_graph"'):
                continue
            if schema == "?":
                schema = "old" if ('"singleton"' in line or '"compound"' in line) else "new"
            fm = _FILENAME_RE.search(head)
            pm = _PATH_RE.search(head)
            fn = fm.group(1) if fm else ""
            pt = pm.group(1) if pm else ""
            if fn == "*":
                if not (repo and pt.startswith(repo.rstrip("/") + "/")):
                    continue
                rel = pt[len(repo.rstrip("/")) + 1:]
            else:
                rel = fn or pt
            if not rel or "site-packages" in rel:
                continue
            try:
                d = json.loads(line.strip().rstrip(","))["data"]
            except Exception:
                continue
            n_records += 1
            for s in _sites_of(d.get("calls") or {}):
                if s.artificial or s.constructor:
                    continue
                calls_per_file[rel] += 1
                if s.unresolved is not None:
                    per_file[rel] += 1
                    by_reason[s.unresolved] += 1
                    if len(rows) < 5000:
                        rows.append({"file": rel, "line": s.line, "col": s.col,
                                     "reason": s.unresolved, "callable": d.get("callable", "")})
    top = [{"file": f, "unresolved": n, "calls": calls_per_file[f]} for f, n in per_file.most_common(limit)]
    return {"call_graph": os.path.abspath(call_graph), "repo": repo, "schema": schema,
            "records_in_repo": n_records, "calls_in_repo": sum(calls_per_file.values()),
            "unresolved_in_repo": sum(per_file.values()), "files_with_unresolved": len(per_file),
            "by_reason": dict(by_reason), "top_files": top, "rows": rows}


# --------------------------------------------------------------------------- #
# extract: a minimal, committable ``r/`` for tests
# --------------------------------------------------------------------------- #
def build_tier_sidecar(run: EngineRun, records: List[CGRecord], names: Set[str]) -> dict:
    """The ``engine-tiers.json`` side file of an excerpt: the T2 / T3
    membership of ``names`` computed on the FULL tree (``records`` = all of
    its in-repo call-graph records) exactly as ``scan`` computes it. The
    excerpt keeps the records of its own files only — no callers — so without
    this file every T3 wall of the excerpt scans as ``none``."""
    in_repo = {r.callable for r in records}
    targets: Set[str] = set()
    for r in records:
        for s in r.sites:
            if s.artificial or s.constructor:
                continue
            for t in s.targets:
                targets.add(_strip_overrides(t))
    models, _ = run.models(in_repo | targets)
    t2, reach, _adj, _rs = _source_reach(records, models, run.override_graph())
    return {"kind": "engine_tiers", "generated_by": "engine_walls.extract",
            "note": "T2 / T3 membership of the excerpt's callables as scanned on the full tree; "
                    "scan() unions it in because the excerpt keeps no caller records",
            "t2": sorted(t2 & names), "reach": sorted(reach & names)}


def extract(cond_dir: str, out_dir: str, files: List[str], src_root: str = "",
            tiers_only: bool = False) -> dict:
    """Copy the records that ``scan`` needs for ``files`` (cond-relative) into
    ``out_dir/r`` plus the files themselves under the same relative paths, so a
    test can run without the 100+ MB originals. ``r/engine-tiers.json`` (see
    ``build_tier_sidecar``) is written beside them; ``tiers_only`` rewrites just that
    file for an existing excerpt."""
    run = EngineRun(cond_dir, src_root=src_root)
    files = [f.replace("\\", "/") for f in files]
    want_files = set(files)
    os.makedirs(os.path.join(out_dir, "r"), exist_ok=True)
    # 1. call-graph records of the files (+ their resolved targets)
    cg_keep, targets, callables = [], set(), set()
    records = list(run.iter_call_graph(in_repo_only=True))
    for rec in records:
        if rec.file in want_files:
            callables.add(rec.callable)
            for s in rec.sites:
                for t in s.targets:
                    targets.add(_strip_overrides(t))
    names = callables | targets
    side = build_tier_sidecar(run, records, names)
    json.dump(side, open(os.path.join(out_dir, "r", TIER_SIDECAR), "w"), indent=1)
    if tiers_only:
        return {TIER_SIDECAR: len(side["t2"]) + len(side["reach"])}

    def copy_jsonl(name: str, keep, slim=None):
        src = os.path.join(run.r_dir, name)
        dst = os.path.join(out_dir, "r", name)
        n = 0
        with open(dst, "w") as w:
            if not os.path.exists(src):
                return 0
            with open(src, encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f):
                    if i == 0 and line.startswith('{"file_version"'):
                        w.write(line if line.endswith("\n") else line + "\n")
                        continue
                    if keep(line):
                        text = line.rstrip("\n").rstrip(",")
                        if slim:
                            try:
                                text = json.dumps(slim(json.loads(text)), separators=(",", ":"))
                            except Exception:
                                pass
                        w.write(text + "\n")
                        n += 1
        return n

    def slim_model(o: dict) -> dict:
        """Keep the model fields ``scan`` reads: modes, and of ``sources`` /
        ``parameter_sources`` only their positions (``tier_of`` reads nothing
        else; the taint frames of a big callable run to a megabyte). Issues
        are kept as a count-only stub (``scan`` counts them)."""
        if o.get("kind") == "issue":
            d = o.get("data") or {}
            return {"kind": "issue", "data": {k: d[k] for k in ("callable", "code", "line", "filename", "path") if k in d}}
        if o.get("kind") != "model":
            return o
        d = o.get("data") or {}
        out = {k: d[k] for k in ("callable", "filename", "path", "callable_line", "modes") if k in d}
        for k in ("sources", "parameter_sources"):
            if d.get(k):
                acc: List[Tuple[int, int, int]] = []
                _positions_in(d[k], acc)
                out[k] = [{"line": ln, "start": s, "end": e} for ln, s, e in sorted(set(acc))] or [{"kept": True}]
        return {"kind": "model", "data": out}

    def by_callable(line: str) -> bool:
        m = _CALLABLE_RE.search(line[:600])
        return bool(m and m.group(1) in names)

    def by_file(line: str) -> bool:
        head = line[:600]
        fm = _FILENAME_RE.search(head)
        pm = _PATH_RE.search(head)
        rel = run.in_repo_rel(fm.group(1) if fm else "", pm.group(1) if pm else "")
        return rel in want_files or by_callable(line)

    n = {TIER_SIDECAR: len(side["t2"]) + len(side["reach"])}
    n["call-graph.json"] = copy_jsonl("call-graph.json", by_file)
    n["higher-order-call-graph.json"] = copy_jsonl("higher-order-call-graph.json", by_callable)
    # models of the involved callables (+ the source models, slimmed): issues
    # are not needed by scan() and dominate the size on big targets
    n["taint-output.json"] = copy_jsonl("taint-output.json", by_callable, slim=slim_model)
    n["functions.json"] = copy_jsonl("functions.json", lambda l: any(f'"name":"{x}"' in l for x in names))
    mods = set()
    for x in names:
        parts = x.split(".")
        for i in range(1, len(parts)):
            mods.add(".".join(parts[:i]))
    n["modules.json"] = copy_jsonl("modules.json", lambda l: any(f'"name":"{m}"' in l for m in mods))
    n["decorator-counts.json"] = copy_jsonl("decorator-counts.json", lambda l: True)
    og = run.override_graph()
    # keep every override row of the classes involved (the dispatch impl
    # ``BaseTool._run`` is reached through ``Overrides{..}``, never as a target)
    owners = {n.rsplit(".", 1)[0] for n in names if "." in n}
    json.dump({k: v for k, v in og.items()
               if k in names or k.rsplit(".", 1)[0] in owners},
              open(os.path.join(out_dir, "r", "override-graph.json"), "w"), indent=1)
    json.dump(run.metadata(), open(os.path.join(out_dir, "r", "taint-metadata.json"), "w"), indent=1)
    json.dump(run.errors(), open(os.path.join(out_dir, "r", "errors.json"), "w"))
    for rel in files:
        if not os.path.exists(run.abs_path(rel)):
            continue
        dst = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(run.abs_path(rel), dst)
    for extra in ("links.json", "stats.json"):
        if os.path.exists(os.path.join(run.cond_dir, extra)):
            shutil.copyfile(os.path.join(run.cond_dir, extra), os.path.join(out_dir, extra))
    # relative to the excerpt dir (EngineRun joins it with cond_dir), so the
    # committed excerpt does not carry the extracting machine's absolute path
    json.dump({"source_directories": [run.source_dirs[0]]},
              open(os.path.join(out_dir, ".pyre_configuration"), "w"), indent=2)
    return n


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="engine-discovered walls of a cond dir (cond/r + cond/src)")
    s.add_argument("cond")
    s.add_argument("--src", default="", help="source root (default: .pyre_configuration or cond/src)")
    s.add_argument("--r-dir", default="", help="results dir (default: cond/r)")
    s.add_argument("--out", default="", help="write engine_walls.json / env_report.json / walls.md here")
    s.add_argument("--catalog", default="", help="spec.presets.json with dispatch rows")
    s.add_argument("--all", action="store_true", help="also list environment-gap unresolved calls as rows")
    s.add_argument("--disable", default="", help="leave-one-out: comma list of S1,S2,S3 to treat as resolved")
    s.add_argument("--json", action="store_true", help="print the JSON result instead of the table")
    d = sub.add_parser("dataset-scan", help="count unresolved in-repo calls in a call-graph.json (no tree needed)")
    d.add_argument("call_graph")
    d.add_argument("--repo", default="", help="in-repo path prefix (default: the file's config.repo)")
    d.add_argument("--limit", type=int, default=30)
    d.add_argument("--out", default="")
    r = sub.add_parser("residual", help="walls left in cond_B, net of lowered ones")
    r.add_argument("cond_b")
    r.add_argument("--links", default="")
    r.add_argument("--src", default="")
    r.add_argument("--catalog", default="")
    x = sub.add_parser("extract", help="minimal r/ + files for tests")
    x.add_argument("cond")
    x.add_argument("--out", required=True)
    x.add_argument("--files", nargs="+", required=True, help="cond-relative files (src/agent.py ...)")
    x.add_argument("--src", default="")
    x.add_argument("--tiers-only", action="store_true",
                   help="only (re)write r/engine-tiers.json of an existing excerpt (--files as extracted)")
    a = ap.parse_args(argv)

    if a.cmd == "scan":
        res = scan(a.cond, src_root=a.src, catalog_path=a.catalog, include_all=a.all, r_dir=a.r_dir,
                   disable=a.disable.split(","))
        if a.out:
            write_outputs(res, a.out)
        if a.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print(render_md(res))
        return 0 if res.env.get("outcome") == "ok" else {"no_sources": 4, "no_surface": 2, "no_walls": 5}.get(res.env.get("outcome"), 1)
    if a.cmd == "dataset-scan":
        out = dataset_scan(a.call_graph, repo=a.repo, limit=a.limit)
        if a.out:
            json.dump(out, open(a.out, "w"), indent=2)
        print(f"repo={out['repo']} records={out['records_in_repo']} calls={out['calls_in_repo']} "
              f"unresolved={out['unresolved_in_repo']} files_with_unresolved={out['files_with_unresolved']} "
              f"by_reason={out['by_reason']}")
        for t in out["top_files"]:
            print(f"  {t['unresolved']:5d} / {t['calls']:5d}  {t['file']}")
        return 0 if out["unresolved_in_repo"] else 2
    if a.cmd == "residual":
        out = residual(a.cond_b, links_json=a.links, src_root=a.src, catalog_path=a.catalog)
        # review C5 policy: the summary names both splits of the net residual;
        # stdout stays the JSON document (README: ``engine_walls.py residual``)
        print(f"residual: raw {out['residual_raw']} net {out['residual']} "
              f"(confirmed {out['residual_confirmed']}, unlowerable {out['residual_unlowerable']}); "
              f"lowered_walls {out['lowered_walls']} remapped {out['remapped']} "
              f"generated_excluded {out['generated_excluded']} legacy_links {out['legacy_links']}", file=sys.stderr)
        print(json.dumps(out, indent=2))
        return 0
    if a.cmd == "extract":
        n = extract(a.cond, a.out, a.files, src_root=a.src, tiers_only=a.tiers_only)
        print(json.dumps(n, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
