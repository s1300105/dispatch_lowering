"""Lowering pipeline driver — the ``AndroidIPCManager.updateJimpleForICC`` analogue.

Ordered passes over a copied source tree (cond_B):

    pre-passes  -> links provider -> filters (in build_links) -> instrument -> post-passes

* ``AutoLinksProvider``  recovers candidates from ``cand_dir`` with the spec and
  joins them with the walls detected in each wall file (Epicc/IC3 analogue).
* ``FileLinksProvider``  reads a hand-written / previously emitted ``links.json``
  (``ICCLinksConfigFileProvider`` analogue) — the same instrumentation runs on
  externally supplied links, which isolates the resolver from the emitter in
  an ablation and lets an analyst pin a link the resolver cannot find.
* ``stages``            a spec may be ``{"stages": [spec1, spec2, ...]}``; each
  stage is a full lowering over the *output* of the previous one (two-hop
  chains such as Semantic Kernel's BoolOp wall -> ``self.search`` wall).

Every run can persist ``links.json`` (walls + links + per-link decision) and
``stats.json`` (``LoweringStats``), and in ``emit="redirector"`` mode writes the
synthetic module ``__ctaudit_redirect.py`` at ``src_root``.

Identity and coordinates (review C1 / M3):

* ``WallRecord.file`` / ``DispatchLink.file`` are the wall file's path relative
  to ``src_root`` (POSIX separators) — never a bare basename. A hand-written
  ``links.json`` names its wall file the same way.
* ``wall_positions`` / ``reject_walls`` pins name lines of the ORIGINAL (cond_A)
  text. When an earlier stage or group already rewrote a wall file, the pins
  are translated through those insertions and the emitted records are
  translated back, so ``links.json`` stays in cond_A coordinates;
  ``WallRecord.lowered_line`` is the wall call's line in the final text.
  A pin whose line is not an original line (it names a line inside a
  generated block, or a post-stage line number) is refused as
  ``unmatched_position`` — never re-located by the on-line fallback. A
  pin-less detect stage after a rewrite is translated back the same way (it
  re-detects and re-lowers the earlier stage's wall, bench
  ``stages_idempotent``); only a position that is not an original line — a
  call inside a generated block — stays in the rewritten file's coordinates.

CLI::

    python3 pipeline.py --src-root cond_B/src --spec spec.json \
        [--cand-dir DIR] --walls agent.py [more.py ...] \
        [--emit inline|redirector] [--links-in links.manual.json] \
        [--links-out links.json] [--stats-out stats.json] [--dry-run]
"""
from __future__ import annotations

import argparse
import filecmp
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import dispatch_lowering as dl   # noqa: E402
import links as L                # noqa: E402
import toolver                   # noqa: E402


# --------------------------------------------------------------------------- #
# Wall-file identity and line bookkeeping (review C1 / C4 / M3)
# --------------------------------------------------------------------------- #
def _rel_file(path: str, src_root: str) -> str:
    """K1: the identity of a wall file across every artifact — its path relative
    to ``src_root`` with POSIX separators (``langchain/prompts/base.py``), never a
    bare basename (``base.py`` names several files of one tree). Without a root
    the absolute path is returned, POSIX-normalised."""
    p = os.path.abspath(path)
    if src_root:
        p = os.path.relpath(p, os.path.abspath(src_root))
    return p.replace(os.sep, "/")


def _extra_registry_roots(cand_dir: str, wall_paths: List[str], src_root: str,
                          originals: Optional[Dict[str, str]] = None) -> tuple:
    """Wall files ``index_registries`` must scan besides ``cand_dir`` (review C4 /
    K6). The lowering stage's cand_dir is the wall tree itself, so wall files
    normally lie inside it and are scanned once. A wall file outside cand_dir
    is an extra root ONLY when cand_dir holds no byte-identical twin at the same
    src_root-relative path: cond_B/src is a copy of the candidate tree, and
    seeing one dict literal through two roots looked like a second definition
    (``bindings == 2``), which untrusted every registry the real run needed.

    ``originals`` (the pre-rewrite snapshot ``run_spec`` / ``run_plan`` keep for
    review M3) is what the twin is compared against when present: a wall file
    an earlier group or stage already rewrote no longer matches its twin on
    disk, yet its registry literal is still the same one — comparing the
    rewritten text would re-add the file as a root and count the literal
    twice for every later group (review C4)."""
    cand_real = os.path.realpath(cand_dir)
    out = set()
    for p in wall_paths:
        rp = os.path.realpath(p)
        if rp == cand_real or rp.startswith(cand_real + os.sep):
            continue
        if src_root:
            rel = os.path.relpath(os.path.abspath(p), os.path.abspath(src_root))
            twin = os.path.join(cand_dir, rel)
            if not rel.startswith("..") and os.path.isfile(twin) and _same_text(twin, p, originals):
                continue
        out.add(rp)
    return tuple(sorted(out))


def _same_text(twin: str, wall_path: str, originals: Optional[Dict[str, str]]) -> bool:
    """Whether ``twin`` holds the wall file's text — its pre-rewrite snapshot
    when ``originals`` has one, else the file as it is on disk."""
    snap = (originals or {}).get(os.path.abspath(wall_path))
    if snap is None:
        return filecmp.cmp(twin, wall_path, shallow=False)
    try:
        return open(twin, encoding="utf-8").read() == snap
    except (OSError, UnicodeDecodeError):
        return False


def _line_map(original: str, current: str) -> Dict[int, int]:
    """original line -> line in ``current`` for a wall file the lowering rewrote
    (review M3). The pass only ever INSERTS lines (guard blocks, the
    TYPE_CHECKING import), so the original lines survive in order: walk
    ``current`` matching them greedily; every other line is generated. A
    guard-block line never equals the next original line (its header names
    ``__ctaudit_unreachable__``, its body is indented one level deeper than the
    statement it is anchored on), so the map is exact around every block."""
    olds, curs = original.splitlines(), current.splitlines()
    if olds == curs:
        return {i: i for i in range(1, len(olds) + 1)}
    out: Dict[int, int] = {}
    k = 0
    for j, text in enumerate(curs):
        if k < len(olds) and text == olds[k]:
            out[k + 1] = j + 1
            k += 1
    return out


def _remap_positions(sp: "dl.LoweringSpec", wall_file: str, lm: Dict[int, int]) -> "dl.LoweringSpec":
    """Translate the pins of ``wall_file`` (``wall_positions`` / ``reject_walls``
    — cond_A lines) into the current text through ``lm`` (review M3). The
    ``at`` / ``end`` strings stay as the reviewer wrote them; only the internal
    ``_line`` / ``_end`` the matcher reads move. A pin whose line is not an
    original line cannot be re-located: it is forced unmatched (line 0) instead
    of being left to the on-line fallback, which would pick a call inside a
    generated block."""
    entries = []
    for e in sp.wall_positions:
        if not dl._path_matches(e["_path"], wall_file):
            entries.append(e)
            continue
        e = dict(e)
        e["_line"] = lm.get(e["_line"], 0)
        if e.get("_end"):
            el, ec = e["_end"]
            e["_end"] = (lm.get(el, el), ec)
        entries.append(e)
    rejects = []
    for r in sp.reject_walls:
        path, line, col = dl._parse_at(r)
        if dl._path_matches(path, wall_file):
            line = lm.get(line, 0)
        rejects.append(f"{path}:{line}" + (f":{col}" if col is not None else ""))
    return dl.LoweringSpec(**{**sp.__dict__, "wall_positions": tuple(entries), "reject_walls": tuple(rejects)})


_HEADER_RE = re.compile(r"^(\s*if " + re.escape(dl.GUARD_NAME)
                        + r":\s+# \[ctaudit\] resolved dynamic dispatch -> \d+ targets \| wall=)(.+):(\d+)\s*$")


def _finish_records(r, rel: str, src: str, out: str, back: Optional[Dict[int, int]]) -> str:
    """Bookkeeping after one wall file was lowered: K1 relative-path identity of
    every record, K2 ``lowered_line`` of every wall that carries a lowered link,
    and — when the pins were remapped (review M3) — the translation of the
    records and of the ``wall=<file>:<line>`` header tags emitted in this stage
    back into cond_A line numbers. Returns the (possibly re-tagged) text."""
    lowered_walls = {l.wall_id for l in r.links if l.status == "lowered"}
    fwd = _line_map(src, out) if out != src else None
    for w in r.walls:
        w.file = rel
        if w.id in lowered_walls:
            w.lowered_line = fwd.get(w.line, w.line) if fwd else w.line
    for l in r.links:
        l.file = rel
    if not back:
        return out
    for w in r.walls:
        for k in ("line", "end_line", "stmt_line", "stmt_end_line", "chain_line"):
            v = getattr(w, k)
            if v:
                setattr(w, k, back.get(v, v))
    for l in r.links:
        l.line = back.get(l.line, l.line)
    if fwd:
        kept = set(fwd.values())
        lines = out.splitlines()
        changed = False
        for i, text in enumerate(lines):
            if (i + 1) in kept:
                continue
            m = _HEADER_RE.match(text)
            if m and int(m.group(3)) in back:
                lines[i] = f"{m.group(1)}{m.group(2)}:{back[int(m.group(3))]}"
                changed = True
        if changed:
            out = "\n".join(lines) + ("\n" if out.endswith("\n") else "")
    return out


# --------------------------------------------------------------------------- #
# Link providers
# --------------------------------------------------------------------------- #
class LinksProvider:
    """Yields, per wall file, the pre-built links to instrument (or None to let
    ``lower_wall_file_ex`` build them from candidates)."""

    def candidates(self):
        return []

    def registry_index(self):
        return None

    def links_for(self, wall_path: str):
        return None

    def describe(self) -> dict:
        return {}


# keys of LoweringSpec that decide WHAT candidate recovery finds; anything
# else (wall selection, precision, emission) leaves the recovered set unchanged
_RECOVERY_KEYS = ("tool_decorators", "register_methods", "tool_list_names", "tool_wrappers",
                  "tool_base_classes", "tool_impl_methods", "wrapper_func_kwargs", "registry_vars",
                  "scan_all_callables", "candidate_module_root", "candidates", "exclude_paths", "_legacy")


def _recovery_key(cand_dir: str, sp) -> tuple:
    def freeze(v):
        if isinstance(v, (list, tuple)):
            return tuple(freeze(x) for x in v)
        if isinstance(v, dict):
            return tuple(sorted((k, freeze(x)) for k, x in v.items()))
        return v
    return (cand_dir,) + tuple(freeze(getattr(sp, k)) for k in _RECOVERY_KEYS)


class AutoLinksProvider(LinksProvider):
    # a draft dry-runs one group per wall file over the same tree: the
    # codebase-wide scans (candidates, registry index, recovery diagnostics)
    # are memoised so 50 groups cost one scan, not fifty
    _cand_cache: Dict[tuple, list] = {}
    _reg_cache: Dict[tuple, dict] = {}
    _desc_cache: Dict[tuple, dict] = {}

    def __init__(self, cand_dir: str, spec, wall_paths: List[str], src_root: str = "",
                 originals: Optional[Dict[str, str]] = None):
        self.sp = dl._coerce_spec(spec)
        self.cand_dir = os.path.abspath(cand_dir)
        key = _recovery_key(self.cand_dir, self.sp)
        if key not in self._cand_cache:
            self._cand_cache[key] = dl.collect_candidates(self.cand_dir, self.sp)
        self._cands = self._cand_cache[key]
        self._key = key
        # trusted static registries over the candidate tree AND the wall files
        # (the registry a wall reads is often defined next to the wall).
        # review C4 (K6): a wall file is never indexed twice — inside cand_dir
        # it is part of the scan, outside it only when cand_dir has no identical
        # twin at its src_root-relative path (see _extra_registry_roots); and
        # links.index_registries itself de-duplicates definitions by path
        # relative to each root and by content hash (not by realpath), so a
        # copied tree or a copied wall file never counts as a second binding.
        # Only a DIFFERENT revision of a registry file seen through two roots
        # still untrusts it — correctly.
        if self.sp.narrow and not self.sp._legacy:
            outside = _extra_registry_roots(self.cand_dir, wall_paths, src_root, originals)
            rkey = (self.cand_dir, outside)
            if rkey not in self._reg_cache:
                self._reg_cache[rkey] = L.index_registries([self.cand_dir] + list(outside))
            self._reg = self._reg_cache[rkey]
        else:
            self._reg = {}

    def candidates(self):
        return self._cands

    def registry_index(self):
        return self._reg

    def describe(self) -> dict:
        d = {"provider": "auto", "cand_dir": self.cand_dir,
             "candidates": len(self._cands),
             "trusted_registries": {k: sorted(v) for k, v in self._reg.items()}}
        if not self.sp._legacy and not self.sp.candidates:
            if self._key not in self._desc_cache:
                try:
                    self._desc_cache[self._key] = dl.describe_candidates(self.cand_dir, self.sp)
                except Exception as e:      # diagnostics only
                    self._desc_cache[self._key] = {"recovery_error": str(e)}
            rec = self._desc_cache[self._key]
            if "recovery_error" in rec:
                d["recovery_error"] = rec["recovery_error"]
            else:
                d["recovery"] = rec
        return d


class FileLinksProvider(LinksProvider):
    def __init__(self, path: str, src_root: str = ""):
        self.path = path
        self.src_root = src_root
        self._walls, self._links = L.load_links(path)

    def links_for(self, wall_path: str):
        # review C1 (K1): a link names its wall file by the src_root-relative
        # path (or an absolute path). An entry for ``prompts/base.py`` must never
        # be adopted by ``chains/base.py``, so basenames are not compared.
        # ``file`` omitted = the link applies to every wall file.
        rel = _rel_file(wall_path, self.src_root)
        wp = os.path.abspath(wall_path)
        mine = []
        for l in self._links:
            f = (l.file or "").replace("\\", "/")
            if not f or f == rel or (os.path.isabs(l.file) and os.path.abspath(l.file) == wp):
                mine.append(l)
        return mine

    def describe(self) -> dict:
        return {"provider": "file", "path": self.path, "links": len(self._links)}


# --------------------------------------------------------------------------- #
# Passes
# --------------------------------------------------------------------------- #
Pass = Callable[[str, str], str]     # (source, wall_path) -> source


@dataclass
class PipelineResult:
    walls: list = field(default_factory=list)
    links: list = field(default_factory=list)
    stats: L.LoweringStats = field(default_factory=L.LoweringStats)
    provider: dict = field(default_factory=dict)
    redirect_module_path: str = ""
    sources: Dict[str, str] = field(default_factory=dict)   # wall_path -> lowered source


class LoweringPipeline:
    def __init__(self, src_root: str, spec, provider: LinksProvider,
                 pre_passes: Optional[List[Pass]] = None,
                 post_passes: Optional[List[Pass]] = None,
                 emit: Optional[str] = None,
                 redirect: Optional["dl.RedirectModuleBuilder"] = None,
                 id_prefix: str = "",
                 originals: Optional[Dict[str, str]] = None):
        self.src_root = os.path.abspath(src_root)
        self.sp = dl._coerce_spec(spec)
        if emit:
            self.sp = dl.LoweringSpec(**{**self.sp.__dict__, "emit": emit})
        self.provider = provider
        self.pre_passes = pre_passes or []
        self.post_passes = post_passes or []
        # a shared builder keeps every stage's redirectors in ONE synthetic
        # module; a per-stage builder would restart the numbering and the
        # module written by the last stage would replace the earlier ones
        self.redirect = redirect
        self.id_prefix = id_prefix
        # review M3: text of every wall file before ANY lowering of this run
        # (absolute path -> source). Position pins name cond_A lines; when an
        # earlier stage / group rewrote the file they are translated into the
        # current text and the records translated back
        self.originals = originals or {}

    def run(self, wall_paths: List[str], write: bool = True) -> PipelineResult:
        res = PipelineResult(provider=self.provider.describe())
        redirect = self.redirect
        if redirect is None and self.sp.emit == "redirector":
            redirect = dl.RedirectModuleBuilder()
        cands = self.provider.candidates()
        reg = self.provider.registry_index()
        id_offset = 0
        for wp in wall_paths:
            wp = os.path.abspath(wp)
            rel = _rel_file(wp, self.src_root)
            src = open(wp, encoding="utf-8").read()
            for p in self.pre_passes:
                src = p(src, wp)
            sp, back = self.sp, None
            orig = self.originals.get(wp)
            if orig is not None and orig != src:
                # review M3: an earlier stage / group already rewrote this file.
                # Pins name cond_A lines -> translate them into the current
                # text; _finish_records translates every record and header tag
                # of this stage back. The back-map is built even for a pin-less
                # (detect) stage, so a wall it re-detects is recorded at its
                # cond_A line too and ``_remap_lowered_lines`` (which reads
                # ``line`` as a cond_A line) yields its real ``lowered_line``
                lm = _line_map(orig, src)
                if sp.wall_positions or sp.reject_walls:
                    sp = _remap_positions(sp, wp, lm)
                back = {v: k for k, v in lm.items()}
            r = dl.lower_wall_file_ex(src, cands, sp, wall_file=wp,
                                      registry_index=reg,
                                      links=self.provider.links_for(wp),
                                      redirect=redirect, id_offset=id_offset,
                                      id_prefix=self.id_prefix,
                                      # review C1 (K1): build_links keys the records
                                      # and the ``wall=`` header by this relative path
                                      src_root=self.src_root)
            id_offset += max(len(r.walls), len(r.links))
            out = r.source
            for p in self.post_passes:
                out = p(out, wp)
            out = _finish_records(r, rel, src, out, back)
            res.sources[wp] = out
            res.walls += r.walls
            res.links += r.links
            res.stats = res.stats.merge(r.stats)
            if write and out != src:
                open(wp, "w", encoding="utf-8").write(out)
        res.stats.files = len(wall_paths)
        res.stats.candidates_total = len(cands)
        rec = res.provider.get("recovery") or {}
        res.stats.unresolved_refs = list(rec.get("unresolved_refs", []))
        if redirect is not None and redirect.count:
            res.stats.redirectors = redirect.count
            res.redirect_module_path = os.path.join(self.src_root, dl.REDIRECT_MODULE + ".py")
            if write:
                open(res.redirect_module_path, "w", encoding="utf-8").write(redirect.render())
        return res


# --------------------------------------------------------------------------- #
# Convenience: run a (possibly staged) spec
# --------------------------------------------------------------------------- #
def run_spec(src_root: str, spec: dict, wall_paths: List[str], *, cand_dir: str = "",
             links_in: str = "", emit: str = "", write: bool = True,
             redirect: Optional["dl.RedirectModuleBuilder"] = None, id_prefix: str = "",
             originals: Optional[Dict[str, str]] = None) -> PipelineResult:
    stages = spec.get("stages") if isinstance(spec, dict) else None
    if not stages:
        stages = [spec]
    if not write and len(stages) > 1:
        raise SystemExit("staged specs require writing (each stage lowers the previous stage's output)")
    total = PipelineResult()
    max_cands = 0
    emit_mode = emit or (stages[0].get("emit") if isinstance(stages[0], dict) else "")
    # one builder for the whole run: every stage appends to the same module
    # (``run_plan`` hands in a builder shared by every group)
    if redirect is None and emit_mode == "redirector":
        redirect = dl.RedirectModuleBuilder()
    wall_paths = [os.path.abspath(p) for p in wall_paths]
    # review M3: pins are cond_A positions — snapshot the wall files before the
    # first stage so later stages translate them through earlier insertions
    # (``run_plan`` hands in the snapshot taken before its first group)
    if originals is None:
        originals = {p: open(p, encoding="utf-8").read() for p in wall_paths if os.path.isfile(p)}
    for i, st in enumerate(stages):
        st = dict(st)
        if emit:
            st["emit"] = emit
        if links_in:
            provider: LinksProvider = FileLinksProvider(links_in, src_root)
        else:
            provider = AutoLinksProvider(cand_dir or src_root, st, wall_paths, src_root=src_root,
                                         originals=originals)
        # stage-tagged ids so the `# <id>` comment in the emitted code and the
        # id in links.json are the same string
        pipe = LoweringPipeline(src_root, st, provider, redirect=redirect,
                                id_prefix=(f"{id_prefix}S{i}" if len(stages) > 1 else id_prefix),
                                originals=originals)
        r = pipe.run(wall_paths, write=write)
        total.walls += r.walls
        total.links += r.links
        total.stats = total.stats.merge(r.stats)      # review M2: LoweringStats().merge(x) == x
        total.provider = r.provider if not i else {"stages": len(stages), "last": r.provider}
        total.redirect_module_path = r.redirect_module_path or total.redirect_module_path
        total.sources.update(r.sources)
        max_cands = max(max_cands, r.stats.candidates_total)
    # a later stage shifts the lines an earlier stage recorded: re-locate every
    # inserted call by its `# <id>` tag and every wall by the line map
    if len(stages) > 1:
        _remap_lowered_lines(total, src_root, originals)
    # these describe the run, not a per-stage quantity, so they must not be summed
    # (the builder is shared across stages, so its count is already the total)
    total.stats.files = len(wall_paths)
    total.stats.candidates_total = max_cands
    if redirect is not None:
        total.stats.redirectors = redirect.count
    return total


def run_plan(src_root: str, plan: dict, *, cand_dir: str = "", emit: str = "", write: bool = True,
             only_files: Optional[List[str]] = None) -> PipelineResult:
    """Lower every group of a reviewed ``plan.json`` (``draft.py``). Each group
    is a ``run_spec`` over its own wall files with its spec — ``wall_positions``
    carry the accept flags, so rejected walls are recorded as
    ``rejected_by_review`` and never linked; an optional ``stages`` list on the
    group replaces the single spec by a staged one (analyst-pinned second
    hop). Ids are ``G<i>W..`` / ``G<i>S<j>W..``; one ``RedirectModuleBuilder``
    serves every group so redirector mode writes a single synthetic module."""
    total = PipelineResult()
    redirect = dl.RedirectModuleBuilder() if (emit or "") == "redirector" or any(
        (g.get("spec") or {}).get("emit") == "redirector" for g in plan.get("groups", [])) else None
    files: set = set()
    max_cands = 0
    n_groups = 0
    # review M3: every group's pins are cond_A positions — snapshot each wall
    # file once, before any group rewrites it
    originals: Dict[str, str] = {}
    for g in plan.get("groups", []):
        for f in list(g.get("wall_files") or (g.get("spec") or {}).get("wall_files") or []):
            p = os.path.abspath(os.path.join(src_root, f))
            if p not in originals and os.path.isfile(p):
                originals[p] = open(p, encoding="utf-8").read()
    for gi, g in enumerate(plan.get("groups", [])):
        spec = dict(g.get("spec") or {})
        if g.get("stages"):
            stages = [dict(spec)] + [dict(x) for x in g["stages"]]
            spec = {"stages": stages}
        wall_files = list(g.get("wall_files") or spec.get("wall_files") or [])
        if only_files:
            wall_files = [f for f in wall_files if f in only_files or os.path.basename(f) in only_files]
        if not wall_files:
            continue
        if not g.get("accepted", 1) and not g.get("stages"):
            # nothing accepted: still record the rows (rejected_by_review) —
            # cheap, and the statistics stay honest — but skip if the group
            # has no positions at all
            if not spec.get("wall_positions"):
                continue
        wall_paths = [os.path.join(src_root, f) for f in wall_files]
        r = run_spec(src_root, spec, wall_paths, cand_dir=cand_dir, emit=emit, write=write,
                     redirect=redirect, id_prefix=f"G{gi}", originals=originals)
        n_groups += 1
        total.walls += r.walls
        total.links += r.links
        # review M2: merge unconditionally — a first group holding only an
        # unmatched pin (no wall, no link) used to be REPLACED by the next
        # group's stats, dropping walls_unmatched / walls_by_origin['review']
        total.stats = total.stats.merge(r.stats)
        total.provider = {"plan": True, "groups": n_groups, "last": r.provider}
        total.redirect_module_path = r.redirect_module_path or total.redirect_module_path
        total.sources.update(r.sources)
        files.update(wall_paths)
        max_cands = max(max_cands, r.stats.candidates_total)
    _remap_lowered_lines(total, src_root, originals)
    total.stats.files = len(files)
    total.stats.candidates_total = max_cands
    if redirect is not None:
        total.stats.redirectors = redirect.count
    return total


def _remap_lowered_lines(res: PipelineResult, src_root: str,
                         originals: Optional[Dict[str, str]] = None) -> None:
    """Final line numbers once every stage / group ran — a later insertion
    shifts what an earlier one recorded. Links are re-located by their
    ``# <id>`` tag; walls (K2 ``lowered_line``) through the original -> final
    line map of their file. Keyed by the src_root-relative path (review C1),
    never by basename."""
    by_file: Dict[str, tuple] = {}
    for path, text in res.sources.items():
        by_file[_rel_file(path, src_root)] = (os.path.abspath(path), text)
    for l in res.links:
        if l.status != "lowered" or not l.lowered_line:
            continue
        ent = by_file.get(l.file)
        if not ent:
            continue
        tag = f"# {l.id}"
        for i, text in enumerate(ent[1].splitlines()):
            if text.rstrip().endswith(tag) or f"{tag} ->" in text:
                l.lowered_line = i + 1
                break
    maps: Dict[str, Dict[int, int]] = {}
    for w in res.walls:
        if not getattr(w, "lowered_line", 0):
            continue
        ent = by_file.get(w.file)
        orig = (originals or {}).get(ent[0]) if ent else None
        if orig is None:
            continue
        if w.file not in maps:
            maps[w.file] = _line_map(orig, ent[1])
        w.lowered_line = maps[w.file].get(w.line, w.lowered_line)


def write_links(path: str, res: PipelineResult) -> None:
    """``links.json`` of a run, stamped with the tool-version fingerprint
    (review C7 / K4) so a row can be matched to the code that produced it."""
    L.dump_links(path, res.walls, res.links, res.stats,
                 extra={"tool_version": toolver.tool_version()})


def _print_report(res: PipelineResult) -> None:
    s = res.stats
    print(f"[ctaudit] candidates={s.candidates_total} walls={s.walls_detected} "
          f"(by idiom {s.walls_by_idiom}) skipped_no_args={s.walls_skipped_no_args}")
    print(f"[ctaudit] links built={s.links_built} lowered={s.links_lowered} "
          f"filtered_registry={s.links_filtered_registry} unreasonable={s.links_unreasonable} "
          f"lines_added={s.lines_added} redirectors={s.redirectors}")
    if s.unresolved_refs:
        print(f"[ctaudit] unresolved registration refs (gap in R): {s.unresolved_refs}")
    s2 = res.stats
    if s2.walls_rejected or s2.walls_unmatched or s2.walls_by_engine_status:
        print(f"[ctaudit] walls rejected={s2.walls_rejected} unmatched={s2.walls_unmatched} "
              f"by_engine_status={s2.walls_by_engine_status} by_origin={s2.walls_by_origin}")
    for w in res.walls:
        print(f"  {w.id} {w.file}:{w.line}" + (f":{w.col}" if w.col else "") + f" [{w.idiom}] {w.callee}  status={w.status}"
              + (f" ({w.reason})" if w.reason else "")
              + (f" origin={w.origin}" if w.origin and w.origin != "ast" else "")
              + (f" engine={w.engine_status}/{w.engine_tier}" if w.engine_status else "")
              + (f" registry={w.registry}" if w.registry else "")
              + (f" members={w.members}" if w.members else ""))
        for l in res.links:
            if l.wall_id == w.id:
                extra = f" -> line {l.lowered_line}" if l.lowered_line else ""
                extra += f" via {l.redirector}" if l.redirector else ""
                print(f"     {l.id} {l.qualname}  {l.status}" + (f" ({l.reason})" if l.reason else "") + extra)
    if res.redirect_module_path:
        print(f"[ctaudit] redirect module: {res.redirect_module_path}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src-root", required=True, help="analysis source root (cond_B/src); redirect module is written here")
    ap.add_argument("--spec", default="", help="lowering spec JSON (may contain 'stages'); or use --plan")
    ap.add_argument("--plan", default="", help="reviewed plan.json from draft.py (groups of pinned walls)")
    ap.add_argument("--cand-dir", default="", help="candidate recovery root (default: --src-root)")
    ap.add_argument("--walls", nargs="*", default=[], help="wall files (absolute, or relative to --src-root); "
                    "optional with --plan or spec.wall_files")
    ap.add_argument("--emit", choices=["inline", "redirector"], default="", help="override spec.emit")
    ap.add_argument("--links-in", default="", help="hand-written / saved links.json instead of auto resolution")
    ap.add_argument("--links-out", default="", help="write walls+links+stats JSON")
    ap.add_argument("--stats-out", default="", help="write stats JSON")
    ap.add_argument("--dry-run", action="store_true", help="do not write lowered files")
    a = ap.parse_args(argv)

    if a.plan:
        plan = json.load(open(a.plan))
        res = run_plan(a.src_root, plan, cand_dir=a.cand_dir, emit=a.emit, write=not a.dry_run,
                       only_files=a.walls or None)
    else:
        if not a.spec:
            raise SystemExit("--spec or --plan is required")
        spec = json.load(open(a.spec))
        wall_names = a.walls or list(spec.get("wall_files") or [])
        if not wall_names:
            raise SystemExit("--walls is required (or spec.wall_files)")
        walls = [p if os.path.isabs(p) else os.path.join(a.src_root, p) for p in wall_names]
        res = run_spec(a.src_root, spec, walls, cand_dir=a.cand_dir, links_in=a.links_in,
                       emit=a.emit, write=not a.dry_run)
    _print_report(res)
    if a.links_out:
        write_links(a.links_out, res)
        print(f"[ctaudit] wrote {a.links_out}")
    if a.stats_out:
        json.dump(res.stats.to_dict(), open(a.stats_out, "w"), indent=2)
        print(f"[ctaudit] wrote {a.stats_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
