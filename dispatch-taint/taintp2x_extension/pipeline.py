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

CLI::

    python3 pipeline.py --src-root cond_B/src --spec spec.json \
        [--cand-dir DIR] --walls agent.py [more.py ...] \
        [--emit inline|redirector] [--links-in links.manual.json] \
        [--links-out links.json] [--stats-out stats.json] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import dispatch_lowering as dl   # noqa: E402
import links as L                # noqa: E402


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


class AutoLinksProvider(LinksProvider):
    def __init__(self, cand_dir: str, spec, wall_paths: List[str]):
        self.sp = dl._coerce_spec(spec)
        self.cand_dir = os.path.abspath(cand_dir)
        self._cands = dl.collect_candidates(self.cand_dir, self.sp)
        # trusted static registries over the candidate tree AND the wall files
        # (the registry a wall reads is often defined next to the wall).
        # index_registries de-duplicates by realpath, so a wall file that is
        # already inside cand_dir is not seen twice — being scanned twice would
        # look like a second definition and untrust the registry.
        scan = [self.cand_dir] + [os.path.abspath(p) for p in wall_paths]
        self._reg = L.index_registries(scan) if (self.sp.narrow and not self.sp._legacy) else {}

    def candidates(self):
        return self._cands

    def registry_index(self):
        return self._reg

    def describe(self) -> dict:
        d = {"provider": "auto", "cand_dir": self.cand_dir,
             "candidates": len(self._cands),
             "trusted_registries": {k: sorted(v) for k, v in self._reg.items()}}
        if not self.sp._legacy and not self.sp.candidates:
            try:
                d["recovery"] = dl.describe_candidates(self.cand_dir, self.sp)
            except Exception as e:      # diagnostics only
                d["recovery_error"] = str(e)
        return d


class FileLinksProvider(LinksProvider):
    def __init__(self, path: str):
        self.path = path
        self._walls, self._links = L.load_links(path)

    def links_for(self, wall_path: str):
        base = os.path.basename(wall_path)
        mine = [l for l in self._links if not l.file or os.path.basename(l.file) == base]
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
                 id_prefix: str = ""):
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
            src = open(wp, encoding="utf-8").read()
            for p in self.pre_passes:
                src = p(src, wp)
            r = dl.lower_wall_file_ex(src, cands, self.sp, wall_file=wp,
                                      registry_index=reg,
                                      links=self.provider.links_for(wp),
                                      redirect=redirect, id_offset=id_offset,
                                      id_prefix=self.id_prefix)
            id_offset += max(len(r.walls), len(r.links))
            out = r.source
            for p in self.post_passes:
                out = p(out, wp)
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
             links_in: str = "", emit: str = "", write: bool = True) -> PipelineResult:
    stages = spec.get("stages") if isinstance(spec, dict) else None
    if not stages:
        stages = [spec]
    if not write and len(stages) > 1:
        raise SystemExit("staged specs require writing (each stage lowers the previous stage's output)")
    total = PipelineResult()
    max_cands = 0
    emit_mode = emit or (stages[0].get("emit") if isinstance(stages[0], dict) else "")
    # one builder for the whole run: every stage appends to the same module
    redirect = dl.RedirectModuleBuilder() if emit_mode == "redirector" else None
    for i, st in enumerate(stages):
        st = dict(st)
        if emit:
            st["emit"] = emit
        if links_in:
            provider: LinksProvider = FileLinksProvider(links_in)
        else:
            provider = AutoLinksProvider(cand_dir or src_root, st, wall_paths)
        # stage-tagged ids so the `# <id>` comment in the emitted code and the
        # id in links.json are the same string
        pipe = LoweringPipeline(src_root, st, provider, redirect=redirect,
                                id_prefix=(f"S{i}" if len(stages) > 1 else ""))
        r = pipe.run(wall_paths, write=write)
        total.walls += r.walls
        total.links += r.links
        total.stats = total.stats.merge(r.stats) if i else r.stats
        total.provider = r.provider if not i else {"stages": len(stages), "last": r.provider}
        total.redirect_module_path = r.redirect_module_path or total.redirect_module_path
        total.sources.update(r.sources)
        max_cands = max(max_cands, r.stats.candidates_total)
    # a later stage shifts the lines an earlier stage recorded: re-locate every
    # inserted call by its `# <id>` tag in the final text
    if len(stages) > 1:
        _remap_lowered_lines(total)
    # these describe the run, not a per-stage quantity, so they must not be summed
    # (the builder is shared across stages, so its count is already the total)
    total.stats.files = len(wall_paths)
    total.stats.candidates_total = max_cands
    if redirect is not None:
        total.stats.redirectors = redirect.count
    return total


def _remap_lowered_lines(res: PipelineResult) -> None:
    by_file: Dict[str, List[str]] = {}
    for path, text in res.sources.items():
        by_file[os.path.basename(path)] = text.splitlines()
    for l in res.links:
        if l.status != "lowered" or not l.lowered_line:
            continue
        lines = by_file.get(os.path.basename(l.file))
        if not lines:
            continue
        tag = f"# {l.id}"
        for i, text in enumerate(lines):
            if text.rstrip().endswith(tag) or f"{tag} ->" in text:
                l.lowered_line = i + 1
                break


def _print_report(res: PipelineResult) -> None:
    s = res.stats
    print(f"[ctaudit] candidates={s.candidates_total} walls={s.walls_detected} "
          f"(by idiom {s.walls_by_idiom}) skipped_no_args={s.walls_skipped_no_args}")
    print(f"[ctaudit] links built={s.links_built} lowered={s.links_lowered} "
          f"filtered_registry={s.links_filtered_registry} unreasonable={s.links_unreasonable} "
          f"lines_added={s.lines_added} redirectors={s.redirectors}")
    if s.unresolved_refs:
        print(f"[ctaudit] unresolved registration refs (gap in R): {s.unresolved_refs}")
    for w in res.walls:
        print(f"  {w.id} {w.file}:{w.line} [{w.idiom}] {w.callee}  status={w.status}"
              + (f" ({w.reason})" if w.reason else "")
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
    ap.add_argument("--spec", required=True, help="lowering spec JSON (may contain 'stages')")
    ap.add_argument("--cand-dir", default="", help="candidate recovery root (default: --src-root)")
    ap.add_argument("--walls", nargs="+", required=True, help="wall files (absolute, or relative to --src-root)")
    ap.add_argument("--emit", choices=["inline", "redirector"], default="", help="override spec.emit")
    ap.add_argument("--links-in", default="", help="hand-written / saved links.json instead of auto resolution")
    ap.add_argument("--links-out", default="", help="write walls+links+stats JSON")
    ap.add_argument("--stats-out", default="", help="write stats JSON")
    ap.add_argument("--dry-run", action="store_true", help="do not write lowered files")
    a = ap.parse_args(argv)

    spec = json.load(open(a.spec))
    walls = [p if os.path.isabs(p) else os.path.join(a.src_root, p) for p in a.walls]
    res = run_spec(a.src_root, spec, walls, cand_dir=a.cand_dir, links_in=a.links_in,
                   emit=a.emit, write=not a.dry_run)
    _print_report(res)
    if a.links_out:
        L.dump_links(a.links_out, res.walls, res.links, res.stats)
        print(f"[ctaudit] wrote {a.links_out}")
    if a.stats_out:
        json.dump(res.stats.to_dict(), open(a.stats_out, "w"), indent=2)
        print(f"[ctaudit] wrote {a.stats_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
