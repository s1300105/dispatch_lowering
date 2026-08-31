"""run_benchmark — the 23 TaintP2X Benchmark targets (+ 3 derived rows: the
committed AutoGPT subset and two import-closure subsets, ``"derived": true``
in the manifest) through the engine-driven workflow, resumably, one row.json
per target and one summary at the end.

    fetch  -> env -> draft (cond_A + pyre once + review bundle; STOPS) -> [review] -> condB -> row
                                                                          \\-- --accept-draft skips the review
    aggregate: work/*/row.json -> summary.jsonl / summary.csv / summary.md
    ablate:    leave-one-out drafts (--disable S1 / S2 / S3 / anchoring), no pyre unless --ablate-pyre;
               ablation.json records the plan it was made against (created / tool version) and a
               failed pyre pass (rc != 0 / no cond_B results) leaves the stage undone (review C3)

Everything target-specific that the design keeps manual stays manual: the
manifest names a ``pysa_models`` file per target (source / extra sink
declarations; optional — TaintP2X's own LLM-SDK source models apply anyway)
and the environment (``search_venv``, ``pkg_root``, subset entries). Every
stage writes ``work/<name>/state.json`` and is skipped when done (``--force``
redoes it; ``--force`` on ``draft`` also discards cond_B / row / ablate and —
after a backup under ``work/<name>/reviewed_plans/`` — a reviewed plan.json
(run_ablation.sh FORCE_DRAFT=1), so the plan on disk is always one the current
code drafted (review C7); ``--keep-cond-a`` reuses cond_A's Pysa results for
the re-draft); pyre runs are bounded by ``pyre_timeout`` (TaintP2X's 1200 s).
Every plan, row and ablation records the tool version
(``toolver.tool_version()``) and ``aggregate`` flags rows made by another
version; ``--stage all --from draft --force --accept-draft`` re-drafts, lowers
and rows a target at ONE tool version without re-fetching it.

    python3 run_benchmark.py --manifest benchmark.json --work WORK --stage draft [--only NAME ...]
    python3 run_benchmark.py --manifest benchmark.json --work WORK --stage all --accept-draft
    python3 run_benchmark.py --manifest benchmark.json --work WORK --stage aggregate
"""
from __future__ import annotations

import argparse
import ast
import csv
import datetime as _dt
import glob
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import zipfile
from typing import Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))            # dispatch-taint-system/
M2 = os.path.join(ROOT, "dispatch-taint", "taintp2x_m2_verification")
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import catalog as CAT      # noqa: E402  (review M4: the one framework-attribution rule, catalog.framework_of)
STAGES = ["fetch", "env", "draft", "condB", "row"]
AXES = ("none", "S1", "S2", "S3", "anchoring")


def _now() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


def _tool_version() -> Optional[dict]:
    """toolver.tool_version() (contract K4); None when toolver is unavailable."""
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    try:
        import toolver
        return toolver.tool_version()
    except Exception:
        return None


def _same_version(a, b) -> bool:
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    try:
        import toolver
        return toolver.same_version(a, b)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #
class Target:
    def __init__(self, spec: dict, defaults: dict, work: str):
        self.spec = dict(defaults, **spec)
        self.name = spec["name"]
        self.work = os.path.join(work, self.name)
        os.makedirs(self.work, exist_ok=True)
        self.state_path = os.path.join(self.work, "state.json")
        self.state = self._load()

    def _load(self) -> dict:
        try:
            return json.load(open(self.state_path))
        except Exception:
            return {"stages": {}, "outcome": "", "errors": []}

    def save(self) -> None:
        json.dump(self.state, open(self.state_path, "w"), indent=2, ensure_ascii=False)

    def done(self, stage: str) -> bool:
        return bool(self.state["stages"].get(stage, {}).get("done"))

    def mark(self, stage: str, **info) -> None:
        self.state["stages"][stage] = dict(info, done=True, at=_now())
        self.save()

    def fail(self, stage: str, why: str, outcome: str = "") -> None:
        self.state["stages"][stage] = {"done": False, "error": why, "at": _now()}
        self.state["errors"].append(f"{stage}: {why}")
        if outcome:
            self.state["outcome"] = outcome
        self.save()

    def reset(self, *stages: str) -> None:
        """Forget stages (their artifacts are gone): they run again next time."""
        for st in stages:
            self.state["stages"].pop(st, None)
        self.save()

    def log(self, text: str) -> None:
        with open(os.path.join(self.work, "log.txt"), "a") as f:
            f.write(f"[{_now()}] {text}\n")
        print(f"[{self.name}] {text}")

    @property
    def src(self) -> str:
        return os.path.join(self.work, "src")

    @property
    def abl(self) -> str:
        return os.path.join(self.work, "abl")

    @property
    def models(self) -> str:
        return os.path.join(self.work, "models", "target.pysa")


def _run(cmd: List[str], cwd: str = "", env: Optional[dict] = None, log=None, timeout: int = 0) -> int:
    if log:
        log("$ " + " ".join(cmd))
    try:
        p = subprocess.run(cmd, cwd=cwd or None, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=(timeout or None))
    except subprocess.TimeoutExpired:
        if log:
            log(f"timeout after {timeout}s")
        return 124
    if log and p.stdout:
        for line in p.stdout.splitlines()[-40:]:
            log("  " + line)
    return p.returncode


# --------------------------------------------------------------------------- #
# stages
# --------------------------------------------------------------------------- #
def stage_fetch(t: Target, force: bool) -> bool:
    if t.done("fetch") and not force:
        return True
    f = t.spec.get("fetch") or {}
    dst = os.path.join(t.work, "fetch")
    if force:
        shutil.rmtree(dst, ignore_errors=True)
    os.makedirs(dst, exist_ok=True)
    if f.get("git"):
        repo = os.path.join(dst, "repo")
        if not os.path.isdir(os.path.join(repo, ".git")):
            cmd = ["git", "clone", "--depth", "1"] + (["--branch", f["ref"]] if f.get("ref") else []) + [f["git"], repo]
            if _run(cmd, log=t.log, timeout=900) != 0:
                t.fail("fetch", f"git clone failed: {f}", "fetch_failed")
                return False
        rc = subprocess.run(["git", "-C", repo, "log", "-1", "--format=%H %ci"], stdout=subprocess.PIPE, text=True)
        t.mark("fetch", kind="git", ref=f.get("ref", ""), commit=rc.stdout.strip(), tree=repo)
        return True
    if f.get("pypi"):
        pkg, ver = f["pypi"], f.get("version", "")
        have = glob.glob(os.path.join(dst, f"{pkg.replace('-', '_')}-{ver}*")) + glob.glob(os.path.join(dst, f"{pkg}-{ver}*"))
        have = [h for h in have if os.path.isdir(h)]
        if not have:
            spec = f"{pkg}=={ver}" if ver else pkg
            if _run([sys.executable, "-m", "pip", "download", "--no-deps", "--no-binary", ":all:", "-d", dst, spec],
                    log=t.log, timeout=900) != 0:
                t.fail("fetch", f"pip download failed: {spec}", "fetch_failed")
                return False
            for arc in glob.glob(os.path.join(dst, "*.tar.gz")) + glob.glob(os.path.join(dst, "*.zip")):
                if arc.endswith(".tar.gz"):
                    tarfile.open(arc).extractall(dst)
                else:
                    zipfile.ZipFile(arc).extractall(dst)
            have = [h for h in glob.glob(os.path.join(dst, "*")) if os.path.isdir(h)]
        if not have:
            t.fail("fetch", "sdist did not unpack to a directory", "fetch_failed")
            return False
        t.mark("fetch", kind="pypi", version=ver, tree=have[0])
        return True
    if f.get("path"):
        tree = f["path"] if os.path.isabs(f["path"]) else os.path.join(ROOT, f["path"])
        if not os.path.isdir(tree):
            t.fail("fetch", f"path missing: {tree}", "fetch_failed")
            return False
        t.mark("fetch", kind="path", tree=tree)
        return True
    t.fail("fetch", "no fetch spec (git / pypi / path)", "fetch_failed")
    return False


def stage_env(t: Target, force: bool) -> bool:
    if t.done("env") and not force:
        return True
    tree = t.state["stages"].get("fetch", {}).get("tree", "")
    if not tree or not os.path.isdir(tree):
        t.fail("env", "fetch tree missing", "env_failed")
        return False
    shutil.rmtree(t.src, ignore_errors=True)
    os.makedirs(t.src, exist_ok=True)
    copied = []
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "tests", "test", ".git", "node_modules")
    for rel in t.spec.get("pkg_root") or []:
        srcdir = os.path.join(tree, rel)
        if not os.path.isdir(srcdir):
            t.fail("env", f"pkg_root missing in the fetched tree: {rel}", "env_failed")
            return False
        if t.spec.get("flatten"):
            # the dir IS the source root (quivr's backend/): its children become top-level packages
            for child in os.listdir(srcdir):
                cs = os.path.join(srcdir, child)
                if os.path.isdir(cs) and child not in ("tests", "test", "__pycache__", ".git", "node_modules"):
                    shutil.copytree(cs, os.path.join(t.src, child), ignore=ignore, dirs_exist_ok=True)
                elif cs.endswith(".py"):
                    shutil.copy(cs, t.src)
        else:
            dst = os.path.join(t.src, os.path.basename(rel.rstrip("/")))
            shutil.copytree(srcdir, dst, ignore=ignore, dirs_exist_ok=True)
        copied.append(rel)
    for rel in t.spec.get("extra_files") or []:
        s = os.path.join(tree, rel)
        if os.path.isfile(s):
            shutil.copy(s, os.path.join(t.src, os.path.basename(rel)))
    n_py = sum(len([f for f in fs if f.endswith(".py")]) for _r, _d, fs in os.walk(t.src))
    if n_py == 0:
        t.fail("env", "no .py under src", "env_failed")
        return False
    # optional subset: keep only the target-package modules reachable (by
    # import) from the entry files, and isolate the external deps the way the
    # Semantic Kernel subset was built (subset_extractor: deps_iso / stubs_min)
    sub = t.spec.get("subset") or {}
    if sub:
        try:
            info = _build_subset(t, sub)
        except Exception as e:
            t.fail("env", f"subset failed: {type(e).__name__}: {e}", "env_failed")
            return False
        n_py = info["kept_files"]
        t.state["subset"] = info
        t.save()
    os.makedirs(os.path.dirname(t.models), exist_ok=True)
    pm = t.spec.get("pysa_models") or ""
    if pm:
        pm = pm if os.path.isabs(pm) else os.path.join(ROOT, pm)
        if not os.path.exists(pm):
            t.fail("env", f"pysa_models missing: {pm}", "needs_models")
            return False
        shutil.copy(pm, t.models)
    else:
        open(t.models, "w").write(f"# {t.name}: no target-specific models — TaintP2X's LLM-SDK source models apply\n")
    # dataset pre-check: is there a surface at all (count-only, no environment)
    ds = t.spec.get("dataset_dir") or ""
    if ds:
        ds = ds if os.path.isabs(ds) else os.path.join(ROOT, "..", ds)
        cg = os.path.join(ds, "call-graph.json")
        if os.path.exists(cg):
            sys.path.insert(0, _HERE)
            import engine_walls
            d = engine_walls.dataset_scan(cg, limit=10)
            d.pop("rows", None)
            json.dump(d, open(os.path.join(t.work, "dataset_scan.json"), "w"), indent=2)
            t.state["dataset_reference_issues"] = sum(
                1 for o in engine_walls._iter_jsonl(os.path.join(ds, "taint-output.json")) if o.get("kind") == "issue")
    t.mark("env", pkg_root=copied, py_files=n_py, models=(pm or "generic"))
    return True


def _build_subset(t: Target, sub: dict) -> dict:
    """Transitive import closure of ``sub['pkg']`` from ``sub['entries']``
    (paths relative to src), pruning every other module of the package from
    ``t.src``; external deps go to <work>/subset/{deps_iso,stubs_min}."""
    sys.path.insert(0, _HERE)
    import subset_extractor as SE
    pkg = sub["pkg"]
    pkg_dir = os.path.join(t.src, pkg)
    if not os.path.isdir(pkg_dir):
        raise RuntimeError(f"package dir missing: {pkg_dir}")

    def mod_to_file(mod: str, allow_parent: bool = True) -> Optional[str]:
        """File of an absolute module name inside the package, or None."""
        parts = mod.split(".")
        if parts[0] != pkg:
            return None
        base = os.path.join(t.src, *parts)
        for cand in (base + ".py", os.path.join(base, "__init__.py")):
            if os.path.exists(cand):
                return cand
        # ``from pkg.a import name`` where name is a symbol of module pkg.a
        if allow_parent and len(parts) > 2:
            base2 = os.path.join(t.src, *parts[:-1])
            for cand in (base2 + ".py", os.path.join(base2, "__init__.py")):
                if os.path.exists(cand):
                    return cand
        return None

    def imports_of(path: str):
        """Absolute module names imported by ``path``; relative imports are
        resolved against the importing file's own package."""
        try:
            tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
        except Exception:
            return []
        here = os.path.relpath(os.path.dirname(path), t.src).replace(os.sep, ".").split(".")
        out = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                out += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = here[: len(here) - (node.level - 1)] if node.level > 1 else here
                    mod = ".".join([x for x in base if x] + ([node.module] if node.module else []))
                else:
                    mod = node.module or ""
                if mod:
                    out.append(mod)
                    out += [f"{mod}.{a.name}" for a in node.names]      # ``from pkg.a import submodule``
        return out

    def path_inits(f: str):
        d = os.path.dirname(f)
        while d.startswith(pkg_dir):
            init = os.path.join(d, "__init__.py")
            if os.path.exists(init):
                yield init
            d = os.path.dirname(d)

    keep: set = set()
    frontier = [os.path.join(t.src, e) for e in sub["entries"]]
    missing = [f for f in frontier if not os.path.exists(f)]
    if missing:
        raise RuntimeError(f"entry files missing: {missing}")
    max_depth = int(sub.get("depth", 12))
    depth = 0
    heavy = set(sub.get("heavy") or []) or None
    all_cls = SE.Classification()
    # closure to a fixpoint: the package __init__ files on a kept file's path
    # are kept AND followed (their re-exports pull in submodules), and relative
    # imports are resolved against the importing file — a bare-name fallback
    # used to resolve ``from .deprecation import x`` to the package root
    while frontier and depth <= max_depth:
        srcs = {}
        for f in frontier:
            for init in path_inits(f):
                if init not in keep:
                    keep.add(init)
                    try:
                        srcs[init] = open(init, encoding="utf-8", errors="replace").read()
                    except Exception:
                        pass
            if f in keep:
                continue
            keep.add(f)
            try:
                srcs[f] = open(f, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
        if not srcs:
            break
        c = SE.classify_imports(srcs, pkg, heavy)
        all_cls.heavy |= c.heavy
        all_cls.isolate |= c.isolate
        for m, names in c.used_symbols.items():
            all_cls.used_symbols.setdefault(m, set()).update(names)
        nxt = []
        for src_file in srcs:
            for m in imports_of(src_file):
                if m.split(".")[0] != pkg:
                    continue
                f = mod_to_file(m)
                if f and f not in keep and f not in nxt:
                    nxt.append(f)
        frontier = nxt
        depth += 1
    removed = 0
    for root, _dirs, files in os.walk(pkg_dir):
        for f in files:
            fp = os.path.join(root, f)
            if f.endswith(".py") and fp not in keep:
                os.remove(fp)
                removed += 1
    # honesty check: a kept file must not import a package module we deleted
    broken = []
    for f in sorted(keep):
        for m in imports_of(f):
            if m.split(".")[0] == pkg and mod_to_file(m) is None:
                broken.append(f"{os.path.relpath(f, t.src)} -> {m}")
    if broken:
        t.log(f"subset: {len(broken)} import(s) of pruned package modules remain (recorded in state)")
    # external deps: deps_iso symlinks + heavy stubs, TaintP2X-shaped config
    out = os.path.join(t.work, "subset")
    site = os.path.join(os.environ.get("VIRTUAL_ENV", os.path.join(ROOT, ".venv")), "lib",
                        f"python{sys.version_info.major}.{sys.version_info.minor}", "site-packages")
    tp2x_taint = os.path.join(ROOT, "TaintP2X", "Taint_Propagation", "taint")
    typeshed = os.environ.get("TYPESHED", os.path.join(ROOT, ".venv", "lib", "pyre_check", "typeshed"))
    entries = [os.path.join(t.src, e) for e in sub["entries"]]
    SE.build_subset(out, entries, pkg, site, tp2x_taint, typeshed, heavy=heavy)
    # isolate what the WHOLE kept subset imports, not only the entry files
    deps_iso = os.path.join(out, "deps_iso")
    for top in sorted(all_cls.isolate):
        for cand in (top, top.replace("-", "_")):
            srcp = os.path.join(site, cand)
            dstp = os.path.join(deps_iso, cand)
            if os.path.exists(srcp) and not os.path.lexists(dstp):
                os.symlink(srcp, dstp)
    t.state["search_extra"] = [deps_iso, os.path.join(out, "stubs_min")]
    return {"pkg": pkg, "entries": sub["entries"], "kept_files": len(keep), "removed_files": removed,
            "depth": depth, "isolated": sorted(all_cls.isolate), "heavy": sorted(all_cls.heavy),
            "broken_imports": len(broken), "broken_import_rows": broken[:50]}


def _ablation_env(t: Target, **extra) -> dict:
    env = dict(os.environ)
    env.update({
        "TARGET_SRC": t.src, "PYSA_MODELS": t.models, "WORK": t.abl,
        "PYRE_SEARCH_VENV": str(t.spec.get("search_venv", 1)),
        "PYRE_TIMEOUT": str(t.spec.get("pyre_timeout", 1200)),
        "EMIT": t.spec.get("emit", "inline") or "inline",
        "REUSE_COND_A": "1",
    })
    if t.state.get("search_extra"):
        env["PYRE_EXTRA_SEARCH"] = ":".join(t.state["search_extra"])
        env["PYRE_SEARCH_VENV"] = "0"
    if t.spec.get("preset"):
        env["DRAFT_ARGS"] = f"--preset {t.spec['preset']} " + (t.spec.get("draft_args") or "")
    elif t.spec.get("draft_args"):
        env["DRAFT_ARGS"] = t.spec["draft_args"]
    env.update({k: str(v) for k, v in extra.items()})
    return env


def _draft_args(t: Target) -> List[str]:
    """The draft.py options the runner passes (preset + manifest draft_args) —
    the same for stage_draft (via DRAFT_ARGS) and stage_ablate (review C3)."""
    args = ["--preset", t.spec["preset"]] if t.spec.get("preset") else []
    return args + shlex.split(t.spec.get("draft_args") or "")


def _preset_name(spec: dict) -> str:
    """The explicit preset a target is drafted with: the manifest ``preset``,
    else a ``--preset X`` inside its ``draft_args`` (review M10: the impl-map
    check must see the same preset the draft saw)."""
    if spec.get("preset"):
        return spec["preset"]
    args = shlex.split(spec.get("draft_args") or "")
    if "--preset" in args and args.index("--preset") + 1 < len(args):
        return args[args.index("--preset") + 1]
    return ""


def _impl_map_stale(work: str, spec: dict, presets: Dict[str, dict]):
    """``catalog.impl_map_stale`` on the target's draft AS THE CODE PRODUCED IT
    (abl/draft/plan.draft.json, the read-only original; plan.json for a pre-C7
    draft): the reason string when the plan carries a pre-M10 impl map (merged
    all-framework / none), False when the map is the catalogue fold of the
    plan's own frameworks, None when the target has no plan."""
    d = os.path.join(work, spec["name"], "abl", "draft")
    for base in ("plan.draft.json", "plan.json"):
        path = os.path.join(d, base)
        if not os.path.exists(path):
            continue
        try:
            plan = json.load(open(path))
        except Exception as e:
            return f"{base}: unreadable ({e.__class__.__name__})"
        return CAT.impl_map_stale(plan, presets, _preset_name(spec)) or False
    return None


def _dry_run_links(plan: dict, acc: List[dict]) -> int:
    """Dry-run links of the walls accepted in the plan AS IT STANDS: the sum
    over accepted rows. On an unedited version-2 plan this equals
    ``plan.dry_run.stats.links_lowered`` (agent C: after the FANOUT_MAX
    demotion the group is dry-run again, so demoted walls are in neither);
    the per-row sum is used because it also follows a reviewer's accept flips,
    which is what the leave-one-out staleness check compares against."""
    return sum((w.get("dry_run") or {}).get("lowered", 0) for w in acc)


def _plan_summary(plan: dict) -> dict:
    """Counts of a plan.json as the runner records them: walls, accepted,
    per-wall dry-run fan-out (``lowered_links`` = redirector dry-run links of
    the accepted walls — NOT the real cond_B links_lowered), provenance."""
    rows = [w for g in plan.get("groups", []) for w in g.get("walls", [])]
    acc = [w for w in rows if w.get("accept")]
    by_status: Dict[str, int] = {}
    for w in acc:
        k = (w.get("engine_status") or "").split(":")[0]
        by_status[k] = by_status.get(k, 0) + 1
    return {"outcome": plan.get("outcome"), "walls": len(rows), "accepted": len(acc),
            "lowered_walls": sum(1 for w in acc if (w.get("dry_run") or {}).get("lowered")),
            "lowered_links": _dry_run_links(plan, acc),
            "by_status": by_status, "stages": sum(1 for g in plan.get("groups", []) if g.get("stages")),
            "catalog": (plan.get("catalog") or {}).get("detected", [])[:3],
            "anchors": (plan.get("anchors") or {}).get("counts", {}),
            "accepted_by_tier": (plan.get("counts") or {}).get("accepted_by_tier"),
            "created": plan.get("created"), "tool_version": plan.get("tool_version")}


DRAFT_OUTCOME = {0: "ok", 2: "no_surface", 3: "catalog_stale", 4: "no_sources", 5: "no_walls"}


def _discard_downstream(t: Target, *, cond_a: bool) -> None:
    """A re-draft (or a re-run cond_B) invalidates what was derived from the
    old plan (review C3 / M5): cond_B, row.json, the ablation and their stages."""
    if cond_a:
        shutil.rmtree(os.path.join(t.abl, "cond_A"), ignore_errors=True)
    shutil.rmtree(os.path.join(t.abl, "cond_B"), ignore_errors=True)
    shutil.rmtree(os.path.join(t.abl, "ablate"), ignore_errors=True)
    for p in (os.path.join(t.abl, "row.json"), os.path.join(t.work, "row.json"), os.path.join(t.work, "ablation.json")):
        if os.path.exists(p):
            os.remove(p)
    t.reset("condB", "row", "ablate")


def _reviewed_plan(t: Target) -> Optional[str]:
    """abl/draft/plan.json when it carries review work — it differs from the
    read-only original plan.draft.json that draft.write_bundle keeps beside it
    (review C7); None when there is no review work (or no original)."""
    d = os.path.join(t.abl, "draft")
    p, o = os.path.join(d, "plan.json"), os.path.join(d, "plan.draft.json")
    if not (os.path.exists(p) and os.path.exists(o)):
        return None
    try:
        return p if open(p, "rb").read() != open(o, "rb").read() else None
    except OSError:
        return None


def _backup_reviewed_plan(t: Target) -> Optional[str]:
    """Copy a reviewed plan.json (and its plan.draft.json original, so the
    review diff stays reproducible) to work/<name>/reviewed_plans/plan.<created>.json
    before a forced re-draft discards it (review C7). Returns the backup path,
    None when the plan on disk carries no review work."""
    p = _reviewed_plan(t)
    if not p:
        return None
    try:
        stamp = str(json.load(open(p)).get("created") or _now())
    except Exception:
        stamp = _now()
    d = os.path.join(t.work, "reviewed_plans")
    os.makedirs(d, exist_ok=True)
    base = os.path.join(d, "plan." + stamp.replace(":", "-"))
    dst, n = base + ".json", 1
    while os.path.exists(dst):
        n += 1
        dst = f"{base}.{n}.json"
    shutil.copy(p, dst)
    # copyfile: the copy stays writable (the original is mode 0444)
    shutil.copyfile(os.path.join(os.path.dirname(p), "plan.draft.json"), dst[:-5] + ".draft.json")
    return dst


def stage_draft(t: Target, force: bool, keep_cond_a: bool = False) -> bool:
    if t.done("draft") and not force:
        return True
    backup = None
    if force:
        # review C7 (repair): a forced re-draft must leave a plan THIS code
        # drafted. run_ablation.sh keeps a plan.json that differs from
        # plan.draft.json (review work) unless FORCE_DRAFT=1 — the runner
        # backs that plan up and passes FORCE_DRAFT, instead of keeping it and
        # marking the stage done with a stale plan_tool_version
        backup = _backup_reviewed_plan(t)
        if backup:
            t.log(f"draft --force: reviewed plan.json backed up to {backup} and discarded "
                  "(re-apply the review to the new plan.json)")
        _discard_downstream(t, cond_a=not keep_cond_a)
        t.state["outcome"] = ""
        t.save()
    t0 = time.time()
    env = _ablation_env(t, DRAFT="1", **({"FORCE_DRAFT": "1"} if force else {}))
    rc = _run(["bash", os.path.join(M2, "run_ablation.sh")], cwd=M2, env=env, log=t.log,
              timeout=int(t.spec.get("pyre_timeout", 1200)) + 600)
    secs = int(time.time() - t0)
    if not os.path.exists(os.path.join(t.abl, "cond_A", "r", "taint-output.json")):
        t.fail("draft", f"cond_A produced no results (rc={rc}, {secs}s)", "env_failed")
        return False
    plan = os.path.join(t.abl, "draft", "plan.json")
    # review M5: an rc outside the draft's outcome codes (draft.py exception ->
    # 1, the outer timeout -> 124) is a failure, never a done stage
    if rc not in DRAFT_OUTCOME:
        t.fail("draft", f"draft did not complete (rc={rc}, {secs}s): see log.txt", "draft_failed")
        return False
    if not os.path.exists(plan):
        t.fail("draft", f"draft exited {rc} but wrote no plan.json ({secs}s)", "draft_failed")
        return False
    outcome = DRAFT_OUTCOME[rc]
    p = json.load(open(plan))
    ps = _plan_summary(p)
    tv_now = _tool_version()
    # review C7: the stage records whether the plan it leaves behind is one the
    # current code drafted — a reviewed plan.json kept by run_ablation.sh (no
    # FORCE_DRAFT) may carry an older or no tool_version; aggregate shows it as
    # versions_match no / plan unversioned, and --force re-drafts it
    kept = _reviewed_plan(t) is not None
    match = _same_version(ps["tool_version"], tv_now)
    info = {"rc": rc, "outcome": outcome, "seconds": secs, "plan": plan,
            "walls": ps["walls"], "accepted": ps["accepted"], "lowered_links": ps["lowered_links"],
            "catalog": ps["catalog"], "anchors": ps["anchors"],
            "plan_created": ps["created"], "plan_tool_version": ps["tool_version"], "tool_version": tv_now,
            "versions_match": match, "plan_kept_reviewed": kept, "reviewed_plan_backup": backup}
    if kept:
        t.log("draft: reviewed plan.json kept as it is (differs from plan.draft.json; not re-drafted — "
              "--force backs it up and re-drafts)")
    if not match:
        t.log("draft: plan.json was not drafted by the current code (plan tool_version "
              f"{(((ps['tool_version'] or {}).get('combined')) or 'none')[:12]} vs "
              f"{(((tv_now or {}).get('combined')) or '?')[:12]}); --stage draft --force re-drafts it")
    t.state["tool_version"] = info["tool_version"]
    t.state["outcome"] = outcome if outcome != "ok" else "drafted"
    t.mark("draft", **info)
    return True


def stage_condB(t: Target, force: bool, accept_draft: bool) -> bool:
    if t.done("condB") and not force:
        return True
    d = t.state["stages"].get("draft", {})
    if not d.get("done"):
        t.fail("condB", "draft not done (run --stage draft first)")
        return False
    plan = d.get("plan") or os.path.join(t.abl, "draft", "plan.json")
    if not plan or not os.path.exists(plan):
        t.fail("condB", "no plan.json (run --stage draft first)")
        return False
    p = json.load(open(plan))
    ps = _plan_summary(p)
    # review M5: whether there is anything to lower is decided from the plan's
    # content (accepted walls or analyst stages), never from the recorded
    # draft verdict — a reviewer may flip accepts on a no_walls draft
    if not ps["accepted"] and not ps["stages"]:
        verdict = p.get("outcome") or d.get("outcome") or ""
        t.mark("condB", skipped=True, reason=verdict if verdict not in ("", "ok", "drafted") else "no_walls",
               plan_created=ps["created"], plan_tool_version=ps["tool_version"])
        return True
    reviewed = (p.get("review") or {}).get("minutes") is not None
    if not reviewed and not accept_draft:
        t.log("plan.json not reviewed (review.minutes is null): pass --accept-draft to lower it as is")
        t.fail("condB", "awaiting review")
        return False
    # review C7: the lowering is tied to the plan's tool version; a plan another
    # (or no) version drafted is lowered as asked but the mismatch is recorded
    # here, in row.json (plan_tool_version) and in the summary (versions_match)
    tv_now = _tool_version()
    match = _same_version(ps["tool_version"], tv_now)
    if not match:
        t.log("condB: plan.json was not drafted by the current code (plan tool_version "
              f"{(((ps['tool_version'] or {}).get('combined')) or 'none')[:12]}): the row will show versions_match no; "
              "--stage all --from draft --force re-drafts and re-lowers at one version")
    # a fresh cond_B invalidates the old row (run_ablation.sh rebuilds cond_B itself)
    for pth in (os.path.join(t.abl, "row.json"), os.path.join(t.work, "row.json")):
        if os.path.exists(pth):
            os.remove(pth)
    t.reset("row")
    t0 = time.time()
    rc = _run(["bash", os.path.join(M2, "run_ablation.sh")], cwd=M2, env=_ablation_env(t, PLAN_JSON=plan), log=t.log,
              timeout=int(t.spec.get("pyre_timeout", 1200)) + 600)
    secs = int(time.time() - t0)
    if not os.path.exists(os.path.join(t.abl, "cond_B", "r", "taint-output.json")):
        t.fail("condB", f"cond_B produced no results (rc={rc}, {secs}s)", "env_failed")
        _write_row(t)        # best effort: the row records the failure with its statistics
        return False
    t.mark("condB", rc=rc, seconds=secs, reviewed=reviewed, accept_draft=accept_draft,
           accepted=ps["accepted"], plan_created=ps["created"], plan_tool_version=ps["tool_version"],
           tool_version=tv_now, versions_match=match)
    return True


def _write_row(t: Target, force: bool = False) -> Optional[dict]:
    """abl/row.json via ablation_helpers row (recomputed when forced or
    missing), merged with the runner's state into work/row.json."""
    src = os.path.join(t.abl, "row.json")
    if force and os.path.exists(src):
        os.remove(src)
    if not os.path.exists(src):
        rc = _run([sys.executable, os.path.join(M2, "ablation_helpers.py"), "row", t.abl, src],
                  env=dict(os.environ, EXT=_HERE), log=t.log)
        if rc != 0 or not os.path.exists(src):
            return None
    row = json.load(open(src))
    plan = t.state["stages"].get("draft", {}).get("plan") or ""
    row.update({
        "name": t.name, "category": t.spec.get("category", ""),
        "derived": bool(t.spec.get("derived")), "derived_from": t.spec.get("derived_from") or "",
        "version": t.state["stages"].get("fetch", {}).get("ref") or t.state["stages"].get("fetch", {}).get("version", ""),
        "commit": t.state["stages"].get("fetch", {}).get("commit", ""),
        "py_files": t.state["stages"].get("env", {}).get("py_files"),
        "models": t.state["stages"].get("env", {}).get("models"),
        "dataset_reference_issues": t.state.get("dataset_reference_issues"),
        "draft_seconds": t.state["stages"].get("draft", {}).get("seconds"),
        "condB_seconds": t.state["stages"].get("condB", {}).get("seconds"),
        "review": (json.load(open(plan)).get("review") if plan and os.path.exists(plan) else None),
    })
    if not row.get("outcome"):
        row["outcome"] = t.state.get("outcome", "")
    json.dump(row, open(os.path.join(t.work, "row.json"), "w"), indent=2, ensure_ascii=False)
    return row


def _condB_failed_after_lowering(t: Target) -> bool:
    """condB ran, lowered the tree and produced no results (env_failed): the
    runner wrote its best-effort row then; ``--force`` may re-derive that row
    under the current definitions (review C2) — the same failure, re-recorded."""
    cb = t.state["stages"].get("condB", {})
    return bool(cb.get("error")) and not cb.get("done") and t.state.get("outcome") == "env_failed" \
        and os.path.exists(os.path.join(t.abl, "cond_B"))


def stage_row(t: Target, force: bool) -> bool:
    # review M5: a row is derived from cond_B (or its skip); never from a stale one
    if not t.done("condB") and not (force and _condB_failed_after_lowering(t)):
        t.fail("row", "condB not done (run --stage condB first)")
        return False
    row = _write_row(t, force=force)
    if row is None:
        t.fail("row", "row.json not produced")
        return False
    t.state["outcome"] = row["outcome"]
    t.mark("row", outcome=row["outcome"], outcome_reason=row.get("outcome_reason", ""),
           versions_match=row.get("versions_match"), tool_version=row.get("tool_version"))
    return True


def stage_ablate(t: Target, force: bool, with_pyre: bool) -> bool:
    out_path = os.path.join(t.work, "ablation.json")
    if t.done("ablate") and not force and os.path.exists(out_path):
        return True
    cond_a = os.path.join(t.abl, "cond_A")
    if not os.path.exists(os.path.join(cond_a, "r", "taint-output.json")):
        t.fail("ablate", "no cond_A results (run --stage draft first)")
        return False
    if force:
        shutil.rmtree(os.path.join(t.abl, "ablate"), ignore_errors=True)
    dargs = _draft_args(t)
    axes: Dict[str, dict] = {}
    pyre_failed: Dict[str, str] = {}
    for axis in AXES:
        d = os.path.join(t.abl, "ablate", axis)
        cmd = [sys.executable, os.path.join(_HERE, "draft.py"), cond_a, "--out", d]
        if axis != "none":
            cmd += ["--disable", axis]
        cmd += dargs                                # review C3: the same options as the draft stage
        rc = _run(cmd, log=None)
        plan = os.path.join(d, "plan.json")
        if not os.path.exists(plan):
            axes[axis] = {"rc": rc, "error": "no plan"}
            continue
        ps = _plan_summary(json.load(open(plan)))
        axes[axis] = {"rc": rc, "outcome": ps["outcome"], "walls": ps["walls"], "accepted": ps["accepted"],
                      "lowered_walls": ps["lowered_walls"], "lowered_links": ps["lowered_links"],
                      "by_status": ps["by_status"], "created": ps["created"], "tool_version": ps["tool_version"]}
        if with_pyre and axis != "none" and ps["lowered_links"]:
            work = os.path.join(t.abl, "ablate", axis, "abl")
            os.makedirs(work, exist_ok=True)
            # a real copy, never a symlink: run_ablation.sh does
            # ``cp -r cond_A cond_B; rm -rf cond_B/r`` and through a symlink that
            # would delete the shared cond_A/r
            if not os.path.exists(os.path.join(work, "cond_A", "r", "taint-output.json")):
                shutil.rmtree(os.path.join(work, "cond_A"), ignore_errors=True)
                shutil.copytree(cond_a, os.path.join(work, "cond_A"), symlinks=False)
            # review C3 (repair): an axis is measured by THIS pass only — the row.json /
            # cond_B an earlier pass left behind are removed first, and the pass counts
            # only when run_ablation.sh exited 0 and cond_B has results (a timed-out or
            # failed pyre used to be read as the leftover row and the stage marked done)
            shutil.rmtree(os.path.join(work, "cond_B"), ignore_errors=True)
            rj = os.path.join(work, "row.json")
            if os.path.exists(rj):
                os.remove(rj)
            env = _ablation_env(t, PLAN_JSON=plan, WORK=work)
            rc = _run(["bash", os.path.join(M2, "run_ablation.sh")], cwd=M2, env=env, log=t.log,
                      timeout=int(t.spec.get("pyre_timeout", 1200)) + 600)
            axes[axis]["pyre_rc"] = rc
            axes[axis]["pyre_seconds"] = _int_file(os.path.join(work, "cond_B", "pyre_seconds"))
            out_b = os.path.join(work, "cond_B", "r", "taint-output.json")
            if rc != 0 or not os.path.exists(out_b) or not os.path.exists(rj):
                why = f"run_ablation.sh rc={rc}" + ("" if os.path.exists(out_b) else "; cond_B has no taint-output.json") \
                    + ("" if os.path.exists(rj) else "; no row.json")
                axes[axis]["pyre_error"] = why
                pyre_failed[axis] = why
                t.log(f"ablate {axis}: pyre pass failed ({why})")
                continue
            r = json.load(open(rj))
            axes[axis]["issues"] = r.get("issues")
            axes[axis]["sink_pairs"] = {k: r["sink_pairs"][k] for k in ("cond_A", "cond_B")} if r.get("sink_pairs") else None
            axes[axis]["links_lowered_real"] = (r.get("links") or {}).get("links_lowered")
            axes[axis]["outcome_measured"] = r.get("outcome")
    # the plan the runner lowers (abl/draft/plan.json), so aggregate can tell a
    # stale ablation (review C3); the draft stage of state.json is refreshed
    # from that plan on disk (it may have been re-drafted or reviewed since)
    plan_info = None
    plan_path = os.path.join(t.abl, "draft", "plan.json")
    if os.path.exists(plan_path):
        ps = _plan_summary(json.load(open(plan_path)))
        plan_info = {"path": plan_path, "created": ps["created"], "tool_version": ps["tool_version"],
                     "walls": ps["walls"], "accepted": ps["accepted"], "lowered_links": ps["lowered_links"]}
        ds = t.state["stages"].get("draft") or {}
        if ds.get("done"):
            ds.update(walls=ps["walls"], accepted=ps["accepted"], lowered_links=ps["lowered_links"],
                      plan_created=ps["created"], plan_tool_version=ps["tool_version"],
                      catalog=ps["catalog"], anchors=ps["anchors"], refreshed_by="ablate", refreshed_at=_now())
            t.save()
    out = {"axes": axes, "plan": plan_info, "tool_version": _tool_version(), "draft_args": dargs,
           "pyre": with_pyre, "at": _now(), "complete": not pyre_failed, "pyre_errors": pyre_failed,
           "units": "accepted walls / dry-run links (redirector; draft.py per-wall dry run) — with pyre also "
                    "links_lowered_real (stats.links_lowered of the real run) and issues A->B"}
    json.dump(out, open(out_path, "w"), indent=2)
    if pyre_failed:
        # the partial ablation.json stays on disk (aggregate shows it as incomplete);
        # the stage is not done, so the next run repeats it
        t.fail("ablate", "pyre pass failed for " + "; ".join(f"{k} ({v})" for k, v in pyre_failed.items()))
        return False
    t.mark("ablate", axes=list(axes), pyre=with_pyre, tool_version=out["tool_version"],
           plan_created=(plan_info or {}).get("created"))
    return True


def _int_file(path: str) -> Optional[int]:
    """The integer a run_ablation.sh side file holds (pyre_seconds / pyre_rc); None when absent."""
    try:
        return int(open(path).read().strip())
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# aggregate
# --------------------------------------------------------------------------- #
COLUMNS = ["name", "category", "derived_from", "version", "outcome", "outcome_reason", "py_files", "models",
           "pyre_A", "pyre_B", "unresolved", "env_gaps", "draft_walls", "draft_accepted",
           "accepted_tier_T1", "accepted_tier_T2", "accepted_tier_T3", "accepted_tier_none",
           "review_flips", "review_minutes", "walls_accepted", "walls_lowered",
           "links_lowered", "links_unreasonable", "links_phantom",
           "issues_A", "issues_B", "delta", "sinks_A", "sinks_B", "sinks_new", "sinks_lost", "residual_net",
           "residual_confirmed", "residual_unlowerable",   # review C5 policy: lowerable-but-left vs abstract stubs
           "versions_match", "dataset_ref_issues_whole_repo"]
M10_FOOTER_PREFIX = "- rows whose plan's dispatch_impl_map"     # review M10: the summary footer line naming pre-fix plans
SINK_PAIR_KEY = "(sink kind, issue callable)"     # review C2 / K5: the key ablation_helpers.cmd_row records
FW_MIN_SCORE = CAT.FW_MIN_SCORE   # review M4: import / base-class evidence below this is "(none)" (MetaGPT: 9
                                  # semantic_kernel imports in 170 files; litellm: one @click.command) — a preset
                                  # may set match.min_score; one constant, catalog.py, for every table


def _versions_cell(row: dict, tv_now: Optional[dict]) -> Optional[str]:
    """'yes' when the row, its plan and the current code share one tool
    version; 'no' when any differs; 'plan unversioned' when the plan predates
    the fingerprint; None when nothing was recorded."""
    row_tv, plan_tv = row.get("tool_version"), row.get("plan_tool_version")
    if not row_tv and not plan_tv:
        return None
    if not plan_tv:
        return "plan unversioned"
    ok = bool(row_tv) and _same_version(row_tv, plan_tv)
    if tv_now is not None:
        ok = ok and _same_version(row_tv, tv_now)
    return "yes" if ok else "no"


ENV_OUTCOMES = ("no_sources", "no_surface", "catalog_stale")   # environment verdicts of the draft


def _table_outcome(row: dict) -> Tuple[Optional[str], Optional[str]]:
    """Outcome shown in the table, with the environment verdicts taking precedence.

    review C2/M5 follow-up: ``cmd_row`` overrides the draft verdict by the measured outcome as
    soon as cond_B exists (so a reviewer's accept flips on a no_walls draft are measured). For
    a draft that found NO in-repo sources (``no_sources`` / ``no_surface`` / ``catalog_stale``)
    a measured ``delta0`` of 0 -> 0 issues is vacuous — nothing can flow in either condition —
    so the table keeps the environment verdict and records the vacuous measurement as the
    reason. Rows with a real measurement (issues_A > 0 or a non-zero delta) are left alone.
    """
    outcome, reason = row.get("outcome"), row.get("outcome_reason") or None
    env = row.get("draft_outcome") or row.get("engine_outcome")
    issues = row.get("issues") or {}
    if env in ENV_OUTCOMES and outcome == "delta0" and not issues.get("cond_A") and not issues.get("cond_B"):
        return env, f"cond_B ran: 0 -> 0 issues (vacuous; draft verdict {env} kept)"
    return outcome, reason


def _flat(row: dict, tv_now: Optional[dict] = None) -> dict:
    st = row.get("links") or {}
    tiers = row.get("accepted_by_tier") or {}
    sp = row.get("sink_pairs") or {}
    outcome, outcome_reason = _table_outcome(row)
    return {
        "name": row.get("name"), "category": row.get("category"), "derived_from": row.get("derived_from") or None,
        "version": row.get("version") or (row.get("commit") or "")[:10] or None,
        "outcome": outcome, "outcome_reason": outcome_reason,
        "py_files": row.get("py_files"),
        "models": os.path.basename(row.get("models") or "") or None,
        "pyre_A": (row.get("pyre_seconds") or {}).get("cond_A"), "pyre_B": (row.get("pyre_seconds") or {}).get("cond_B"),
        "unresolved": sum((row.get("unresolved_by_reason") or {}).values()) or None,
        "env_gaps": row.get("env_gaps"), "draft_walls": row.get("draft_walls"), "draft_accepted": row.get("draft_accepted"),
        "accepted_tier_T1": tiers.get("T1"), "accepted_tier_T2": tiers.get("T2"),
        "accepted_tier_T3": tiers.get("T3"), "accepted_tier_none": tiers.get("none"),
        "review_flips": (row.get("review_edits") or {}).get("accept_flips"),
        "review_minutes": (row.get("review_edits") or {}).get("minutes"),
        # accepted at lowering time (walls the plan let through) vs walls that got a lowered link (review M6)
        "walls_accepted": (st.get("walls_detected") or 0) - (st.get("walls_rejected") or 0) if st else None,
        "walls_lowered": st.get("walls_lowered"),
        "links_lowered": st.get("links_lowered"), "links_unreasonable": st.get("links_unreasonable"),
        "links_phantom": st.get("links_phantom"),
        "issues_A": (row.get("issues") or {}).get("cond_A"), "issues_B": (row.get("issues") or {}).get("cond_B"),
        "delta": (row.get("issues") or {}).get("delta"),
        "sinks_A": sp.get("cond_A"), "sinks_B": sp.get("cond_B"),
        "sinks_new": len(sp.get("new") or []) if sp.get("cond_B") is not None else None,
        "sinks_lost": len(sp.get("lost") or []) if sp.get("cond_B") is not None else None,
        "residual_net": (row.get("residual") or {}).get("net") if row.get("residual") else None,
        # review C5 policy: net residual split into confirmed walls and unlowerable abstract stubs
        # (row.json residual.confirmed / residual.unlowerable; blank for rows made before the split)
        "residual_confirmed": (row.get("residual") or {}).get("confirmed") if row.get("residual") else None,
        "residual_unlowerable": (row.get("residual") or {}).get("unlowerable") if row.get("residual") else None,
        # review C1: residual() netted through a pre-C1 links.json (basename keys) — kept
        # out of the table, listed in the footer (jsonl only)
        "residual_legacy_links": bool((row.get("residual") or {}).get("legacy_links")) if row.get("residual") else None,
        # review C2 / K5: a row.json written before the (sink kind, issue callable) key
        # (no sink_pairs.key) embodies the old first-hop definition — jsonl + footer only
        "sink_pairs_legacy_key": (sp.get("key") != SINK_PAIR_KEY) if sp else None,
        "versions_match": _versions_cell(row, tv_now),
        "dataset_ref_issues_whole_repo": row.get("dataset_reference_issues"),
    }


def _framework_of(plan: dict, spec: dict, presets: Dict[str, dict]) -> str:
    """The framework a draft is attributed to (review M4): the manifest's
    explicit preset (what the draft used), else ``catalog.framework_of`` —
    the seeding preset (``plan.catalog.top``: import or discriminating
    base-class evidence, never a decorator alone; version-1 plans: recomputed
    from their scores) only when its score reaches the preset's
    ``match.min_score`` (default FW_MIN_SCORE). The threshold applies to
    every plan version (review M4 repair: a version-2 plan used to return
    ``top`` unthresholded, so MetaGPT — semantic_kernel score 9 — was
    attributed to semantic_kernel once re-drafted while its version-1 plan
    said "(none)"); row.json ``draft_framework`` uses the same function."""
    if spec.get("preset"):
        return spec["preset"]
    return CAT.framework_of(plan.get("catalog") or {}, presets)


def _load_presets() -> Dict[str, dict]:
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    try:
        import catalog
        return catalog.load()
    except Exception:
        return {}


def _md_table(rows: List[dict], cols: List[str]) -> List[str]:
    md = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        md.append("| " + " | ".join("" if r.get(c) is None else str(r.get(c)) for c in cols) + " |")
    return md


def _outcome_counts(rows: List[dict]) -> str:
    oc: Dict[str, int] = {}
    for r in rows:
        oc[r.get("outcome") or "pending"] = oc.get(r.get("outcome") or "pending", 0) + 1
    return ", ".join(f"{k}: {v}" for k, v in sorted(oc.items())) or "-"


def aggregate(work: str, manifest: dict) -> None:
    tv_now = _tool_version()
    presets = _load_presets()
    rows_main, rows_derived = [], []
    blank = {c: None for c in COLUMNS if c not in ("name", "category", "outcome")}
    for t in manifest["targets"]:
        rj = os.path.join(work, t["name"], "row.json")
        st = os.path.join(work, t["name"], "state.json")
        if os.path.exists(rj):
            r = _flat(json.load(open(rj)), tv_now)
        elif os.path.exists(st):
            s = json.load(open(st))
            r = dict(blank, outcome=s.get("outcome") or "pending")
        else:
            # review M11: every manifest target gets a row — a target never
            # started is "pending", not silently absent
            r = dict(blank, outcome="pending")
        r["name"], r["category"] = t["name"], t.get("category", "")
        if t.get("derived"):
            r["derived_from"] = t.get("derived_from") or "(derived)"
            # the dataset count is the whole repository's (shown on the parent row)
            r["dataset_ref_issues_whole_repo"] = None
            rows_derived.append(r)
        else:
            rows_main.append(r)
    rows = rows_main + rows_derived
    # review M10: a plan drafted before the framework-restricted impl map (the
    # merged all-framework map, or none) is named per row — jsonl + footer,
    # never a column — until it is re-drafted; its counts are not current
    spec_by_name = {t["name"]: t for t in manifest["targets"]}
    for r in rows:
        r["impl_map_stale"] = _impl_map_stale(work, spec_by_name[r["name"]], presets)
    with open(os.path.join(work, "summary.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(os.path.join(work, "summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c) for c in COLUMNS})
    # per-framework aggregates from the drafts
    fw: Dict[str, dict] = {}
    for t in manifest["targets"]:
        plan = os.path.join(work, t["name"], "abl", "draft", "plan.json")
        if not os.path.exists(plan):
            continue
        p = json.load(open(plan))
        key = _framework_of(p, t, presets)
        e = fw.setdefault(key, {"targets": 0, "names": [], "catalog_hits": 0, "anchors": 0, "anchors_closed": 0,
                                "confirmed": 0, "proposed": 0, "accepted": 0})
        e["targets"] += 1
        e["names"].append(t["name"])
        e["catalog_hits"] += sum((p.get("env") or {}).get("catalog_hits", {}).values())
        e["anchors"] += (p.get("anchors") or {}).get("counts", {}).get("anchors", 0)
        e["anchors_closed"] += (p.get("anchors") or {}).get("counts", {}).get("closed", 0)
        for g in p["groups"]:
            for r in g["walls"]:
                e["confirmed" if r["confidence"] == "confirmed" else "proposed"] += 1
                e["accepted"] += 1 if r["accept"] else 0
    md = ["# Benchmark summary", "",
          f"generated {_now()}; {len(rows_main)} TaintP2X targets + {len(rows_derived)} derived rows "
          f"({len(manifest['targets'])} manifest rows)", "",
          "Outcome vocabulary: env_failed | no_sources | no_surface | catalog_stale | no_walls (draft accepted 0) | "
          "no_candidates (accepted > 0, links_lowered 0) | drafted (no cond_B yet) | delta_pos (new sink pairs, none lost) | "
          "delta_mixed | delta_neg | delta0; sink pair = (sink kind, issue callable); walls_lowered = walls with a "
          "lowered link (walls_accepted = accepted at lowering time); versions_match = row, plan and current code "
          "share one tool version.", ""]
    md += ["## TaintP2X targets", ""] + _md_table(rows_main, COLUMNS)
    if rows_derived:
        md += ["", "## derived rows (subsets; not TaintP2X targets)", ""] + _md_table(rows_derived, COLUMNS)
    md += ["", "## by framework (explicit manifest preset first; else catalog.framework_of: the preset that seeded the draft "
           "(plan.catalog.top — import / discriminating base-class evidence, never a decorator alone; version-1 plans: "
           f"recomputed from their scores) when its score reaches match.min_score, default {FW_MIN_SCORE}; else '(none)')", "",
           "| framework | targets | catalogue hits | anchors (closed) | confirmed | proposed | accepted | targets (names) |",
           "|---|---|---|---|---|---|---|---|"]
    for k, e in sorted(fw.items()):
        md.append(f"| {k} | {e['targets']} | {e['catalog_hits']} | {e['anchors']} ({e['anchors_closed']}) | "
                  f"{e['confirmed']} | {e['proposed']} | {e['accepted']} | {', '.join(e['names'])} |")
    md += ["", "## outcomes", "", f"- TaintP2X targets ({len(rows_main)}): {_outcome_counts(rows_main)}"]
    if rows_derived:
        md.append(f"- derived rows ({len(rows_derived)}): {_outcome_counts(rows_derived)}")
    abl = []
    for t in manifest["targets"]:
        aj = os.path.join(work, t["name"], "ablation.json")
        if os.path.exists(aj):
            abl.append((t["name"], json.load(open(aj))))
    if abl:
        md += ["", "## leave-one-out", "",
               "cells: accepted walls / dry-run links (redirector, draft.py per-wall dry run — not the real "
               "links_lowered); with pyre: [real links_lowered; issues A->B]. stale: the 'none' axis differs from "
               "the current plan.json (accepted / dry-run links), the plan.json was (re-)drafted after the ablation "
               "(created stamp / tool version of the plan the ablation recorded), the ablation was made by another "
               "tool version, or a pyre pass failed (incomplete).", "",
               "| target | full | -S1 | -S2 | -S3 | -anchoring | stale |", "|---|---|---|---|---|---|---|"]
        for name, a in abl:
            axes = a.get("axes") if isinstance(a.get("axes"), dict) else {k: a.get(k) for k in AXES if isinstance(a.get(k), dict)}

            def cell(x):
                if not x or "accepted" not in x:
                    return "-"
                s = f"{x['accepted']} / {x['lowered_links']}"
                if x.get("issues"):
                    real = x.get("links_lowered_real")
                    s += f" [{'' if real is None else f'{real} links; '}{x['issues']['cond_A']}->{x['issues']['cond_B']}]"
                elif x.get("pyre_error"):
                    s += f" [pyre failed: {x['pyre_error']}]"
                return s
            stale = []
            plan = os.path.join(work, name, "abl", "draft", "plan.json")
            none = axes.get("none") or {}
            rec = a.get("plan") if isinstance(a.get("plan"), dict) else None
            if os.path.exists(plan) and "accepted" in none:
                cur = _plan_summary(json.load(open(plan)))
                if (none.get("accepted"), none.get("lowered_links")) != (cur["accepted"], cur["lowered_links"]):
                    stale.append(f"plan.json now {cur['accepted']} / {cur['lowered_links']}")
                # review C3 (repair): the ablation belongs to ONE draft — the plan whose
                # created stamp / tool version stage_ablate recorded. A plan re-drafted
                # since is another draft even when its counts happen to coincide, and a
                # legacy ablation.json (no plan recorded) cannot be tied to any plan
                if not rec or not rec.get("created"):
                    stale.append("plan provenance not recorded (re-run --stage ablate --force)")
                elif rec.get("created") != cur.get("created"):
                    stale.append(f"plan.json re-drafted {cur.get('created')} (ablation used {rec['created']})")
                elif (rec.get("tool_version") or cur.get("tool_version")) \
                        and not _same_version(rec.get("tool_version"), cur.get("tool_version")):
                    stale.append("plan.json tool version changed since the ablation")
            none_plan = os.path.join(work, name, "abl", "ablate", "none", "plan.json")
            if os.path.exists(none_plan):
                try:
                    why = CAT.impl_map_stale(json.load(open(none_plan)), presets, _preset_name(spec_by_name.get(name, {})))
                except Exception:
                    why = "unreadable"
                if why:      # review M10: the axes were dry-run under a pre-fix impl map
                    stale.append("dispatch_impl_map predates review M10 (re-run --stage ablate --force)")
            atv = a.get("tool_version")
            if tv_now is not None and (not atv or not _same_version(atv, tv_now)):
                stale.append("tool version differs" if atv else "no tool version recorded")
            if a.get("complete") is False or a.get("pyre_errors"):
                stale.append("incomplete: pyre pass failed for " + ", ".join(sorted(a.get("pyre_errors") or {}) or ["?"]))
            md.append(f"| {name} | {cell(none)} | {cell(axes.get('S1'))} | {cell(axes.get('S2'))} | "
                      f"{cell(axes.get('S3'))} | {cell(axes.get('anchoring'))} | {'; '.join(stale) or ''} |")
    # tool version footer (K4)
    mism = [r["name"] for r in rows if r.get("versions_match") == "no"]
    unversioned = [r["name"] for r in rows if r.get("versions_match") == "plan unversioned"]
    unknown = [r["name"] for r in rows if r.get("versions_match") is None and r.get("outcome") not in (None, "pending")
               and os.path.exists(os.path.join(work, r["name"], "row.json"))]
    # review C1: a residual_net netted through a pre-C1 links.json (basename keys) is
    # indicative — its cond_B was lowered before the relative-path keys existed
    legacy = [r["name"] for r in rows if r.get("residual_legacy_links")]
    # review C2: a row made before the K5 sink-pair key mixes definitions in the table
    legacy_key = [r["name"] for r in rows if r.get("sink_pairs_legacy_key")]
    impl_stale = [r["name"] for r in rows if r.get("impl_map_stale")]
    md += ["", "## tool version", "",
           f"- current: {(tv_now or {}).get('combined', '?')[:16]}",
           f"- rows whose plan / row tool_version differ from the current code: {', '.join(mism) or '(none)'}",
           f"- rows whose plan predates the fingerprint (re-draft to version it: --stage all --from draft --force "
           f"[--keep-cond-a] --accept-draft): {', '.join(unversioned) or '(none)'}",
           f"- rows without a recorded tool_version: {', '.join(unknown) or '(none)'}",
           f"- rows whose residual_net was netted through a pre-C1 links.json (basename keys; re-run cond_B to "
           f"confirm): {', '.join(legacy) or '(none)'}",
           f"- rows whose sink pairs / outcome predate the (sink kind, issue callable) key (re-run --stage row "
           f"--force): {', '.join(legacy_key) or '(none)'}",
           f"{M10_FOOTER_PREFIX} predates the framework-restricted fold (review M10: merged "
           f"all-framework map / no map — links_unreasonable, links_lowered and the dry-run counts are not current; "
           f"re-draft: --stage all --from draft --force [--keep-cond-a] --accept-draft): {', '.join(impl_stale) or '(none)'}"]
    open(os.path.join(work, "summary.md"), "w").write("\n".join(md) + "\n")
    print("\n".join(md))


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def _stage_sequence(stage: str, from_stage: str = "fetch") -> List[str]:
    """The stages one invocation runs: ``all`` runs STAGES from ``from_stage``
    on (``--from draft``: draft -> condB -> row, the one-version re-run of
    review C7 without re-fetching); a single stage is itself."""
    if stage == "all":
        return STAGES[STAGES.index(from_stage):]
    return [stage]


def _effective_sequence(t: Target, stage: str, from_stage: str) -> List[str]:
    """``_stage_sequence`` with the prerequisite fallback for ``--stage all --from <stage>``.

    A target whose earlier stages never ran (one the previous batch did not reach, so its
    fetch / env are missing) must start at the first stage that is not done instead of
    failing in the draft preflight with "TARGET_SRC missing" (vanna-0.3.3 / 0.3.4 on the
    2026-08-31 re-run). Stages before ``from_stage`` that are done are still skipped.
    """
    seq = _stage_sequence(stage, from_stage)
    if stage == "all" and from_stage != "fetch":
        missing = [s for s in STAGES[:STAGES.index(from_stage)] if not t.done(s)]
        if missing:
            t.log(f"--from {from_stage}: prerequisite stage(s) {missing} not done — starting from {missing[0]}")
            seq = _stage_sequence("all", missing[0])
    return seq


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", default=os.path.join(_HERE, "benchmark.json"))
    ap.add_argument("--work", default=os.path.join(ROOT, "benchmark_out"))
    ap.add_argument("--stage", default="draft", choices=STAGES + ["all", "aggregate", "ablate"])
    ap.add_argument("--only", nargs="*", default=[])
    ap.add_argument("--force", action="store_true",
                    help="redo the requested stage even if done (draft: discards cond_B / row / ablate and, after a backup "
                         "under work/<name>/reviewed_plans/, a reviewed plan.json — review C7)")
    ap.add_argument("--from", dest="from_stage", default="fetch", choices=STAGES,
                    help="with --stage all: start at this stage (--from draft --force --accept-draft = re-draft, "
                         "lower and row at one tool version without re-fetching)")
    ap.add_argument("--keep-cond-a", action="store_true",
                    help="draft --force: keep cond_A's Pysa results (REUSE_COND_A) instead of re-analysing the baseline")
    ap.add_argument("--accept-draft", action="store_true", help="condB lowers the draft as is (unattended)")
    ap.add_argument("--ablate-pyre", action="store_true", help="ablate: also analyse cond_B per axis")
    ap.add_argument("--continue-on-error", action="store_true", default=True)
    a = ap.parse_args(argv)
    manifest = json.load(open(a.manifest))
    os.makedirs(a.work, exist_ok=True)
    if a.stage == "aggregate":
        aggregate(a.work, manifest)
        return 0
    defaults = manifest.get("defaults", {})
    targets = [t for t in manifest["targets"] if not a.only or t["name"] in a.only]
    if not targets:
        print("no targets selected")
        return 1
    ok_all = True
    for spec in targets:
        t = Target(spec, defaults, a.work)
        t.log(f"=== stage {a.stage} ===")
        seq = _effective_sequence(t, a.stage, a.from_stage)
        for st in seq:
            if st == "fetch":
                ok = stage_fetch(t, a.force)
            elif st == "env":
                ok = stage_env(t, a.force)
            elif st == "draft":
                ok = stage_draft(t, a.force, keep_cond_a=a.keep_cond_a)
            elif st == "condB":
                ok = stage_condB(t, a.force, a.accept_draft)
            elif st == "row":
                ok = stage_row(t, a.force)
            elif st == "ablate":
                ok = stage_ablate(t, a.force, a.ablate_pyre)
            else:
                ok = False
            if not ok:
                ok_all = False
                t.log(f"stage {st} failed: {t.state['errors'][-1] if t.state['errors'] else '?'}")
                break
        t.log(f"outcome: {t.state.get('outcome') or 'pending'}")
    aggregate(a.work, manifest)
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
