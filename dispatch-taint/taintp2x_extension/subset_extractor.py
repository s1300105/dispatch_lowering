#!/usr/bin/env python3
"""subset_extractor.py — build a self-contained Pysa-analyzable subset of a real
package around the code path that carries a source→sink flow.

Automates the manual "subset" work done by hand for Semantic Kernel:
  1. transitively collect the target package's own modules reachable (by import)
     from the entry files  -> these are copied into <out>/src (caller does the copy);
  2. classify every *external* (non-target, non-stdlib) import into
       - HEAVY libs (numpy, scipy, torch, ...) -> emit a minimal .pyi stub skeleton
         under <out>/stubs_min  (hand-fill the few used symbols; heavy bodies would
         blow up / hang the type environment);
       - everything else (pydantic, typing_extensions, ...) -> symlink the real
         package into <out>/deps_iso so its *types* resolve without dragging in the
         whole site-packages (which caused a 268-min hang);
  3. emit a TaintP2X-shaped .pyre_configuration.

stdlib modules are left to typeshed (never stubbed or isolated).

This module is import-safe and testable without pyre. Filesystem side effects
(symlinks, dirs) happen only in build_subset(); analysis pieces are pure.
"""
from __future__ import annotations

import ast
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# stdlib detection: modules typeshed resolves; never stub/isolate these.
# ---------------------------------------------------------------------------
_STDLIB = set(getattr(sys, "stdlib_module_names", set())) | {
    # a few that predate stdlib_module_names or are commonly split
    "collections", "typing", "abc", "ast", "json", "sys", "os", "logging",
    "copy", "contextlib", "dataclasses", "enum", "inspect", "operator",
    "types", "functools", "itertools", "re", "math", "pathlib", "io",
    "asyncio", "warnings", "datetime", "uuid", "hashlib", "base64",
}

# Heavy libs whose *bodies* should NOT be analyzed (stub the used symbols instead).
# Extend as needed; this is the "known heavy library" list (case Y).
DEFAULT_HEAVY = {
    "numpy", "scipy", "pandas", "torch", "tensorflow", "sklearn",
    "cv2", "matplotlib", "transformers", "sentence_transformers",
    "faiss", "sympy",
}


def _top(mod: str) -> str:
    """Top-level package name of a dotted module ('scipy.spatial.distance'->'scipy')."""
    return (mod or "").split(".", 1)[0]


def _iter_imports(tree: ast.AST):
    """Yield (module_dotted, level) for every import in a module AST.
    level>0 means a relative import (from . / from ..)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name, 0
        elif isinstance(node, ast.ImportFrom):
            yield (node.module or ""), (node.level or 0)


@dataclass
class Classification:
    internal_modules: Set[str] = field(default_factory=set)   # target-package modules to include
    heavy: Set[str] = field(default_factory=set)              # top-level heavy pkgs -> stub
    isolate: Set[str] = field(default_factory=set)            # top-level ext pkgs -> symlink
    stdlib: Set[str] = field(default_factory=set)             # left to typeshed
    used_symbols: Dict[str, Set[str]] = field(default_factory=dict)  # heavy pkg -> imported names (for stub skeleton)


def classify_imports(
    entry_sources: Dict[str, str],
    target_pkg: str,
    heavy: Optional[Set[str]] = None,
) -> Classification:
    """Classify imports found across the given entry source files.

    entry_sources: {path_or_label: source_code}
    target_pkg:    top-level name of the package under analysis ('semantic_kernel')
    heavy:         override the heavy-lib set (default DEFAULT_HEAVY)

    NOTE: this classifies the imports *appearing in the entry files*. Full
    transitive closure over the target package is done by the caller walking
    included files back through classify_imports again (build_subset does one
    level; callers can iterate). Relative imports are treated as internal.
    """
    heavy = DEFAULT_HEAVY if heavy is None else heavy
    c = Classification()
    for label, src in entry_sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        # capture "from X import a, b" symbol names for heavy-stub skeletons
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and (node.level or 0) == 0:
                t = _top(node.module)
                if t in heavy:
                    names = {a.name for a in node.names}
                    c.used_symbols.setdefault(node.module, set()).update(names)
        for mod, level in _iter_imports(tree):
            if level and level > 0:
                # relative import -> internal to target package
                if mod:
                    c.internal_modules.add(mod)
                continue
            if not mod:
                continue
            t = _top(mod)
            if t == target_pkg:
                c.internal_modules.add(mod)
            elif t in _STDLIB:
                c.stdlib.add(t)
            elif t in heavy:
                c.heavy.add(t)
            else:
                c.isolate.add(t)
    return c


def _stub_skeleton(module: str, symbols: Set[str]) -> str:
    """Emit a .pyi skeleton with `def name(*a, **k) -> Any: ...` for each imported
    symbol. Hand-fill precise signatures if taint precision needs it; for TITO/
    reachability the permissive skeleton is usually enough."""
    lines = ["from typing import Any", ""]
    for s in sorted(symbols):
        # can't tell class vs func statically here; emit a permissive callable +
        # an assignable Any alias so both `X()` and `X.attr` type-check.
        lines.append(f"def {s}(*args: Any, **kwargs: Any) -> Any: ...")
    return "\n".join(lines) + "\n"


def _module_to_pyi_path(module: str) -> str:
    """'scipy.spatial.distance' -> 'scipy/spatial/distance.pyi' (+ package __init__.pyi)."""
    parts = module.split(".")
    return os.path.join(*parts) + ".pyi"


def plan_stubs(c: Classification, heavy_symbols_by_module: Dict[str, Set[str]]) -> Dict[str, str]:
    """Return {relative_pyi_path: content} for heavy modules, including empty
    __init__.pyi for intermediate packages so pyre treats them as packages."""
    out: Dict[str, str] = {}
    pkgs_needing_init: Set[str] = set()
    for module, syms in heavy_symbols_by_module.items():
        if _top(module) not in c.heavy:
            continue
        out[_module_to_pyi_path(module)] = _stub_skeleton(module, syms)
        # ensure __init__.pyi for each parent package
        parts = module.split(".")
        for i in range(1, len(parts)):
            pkgs_needing_init.add(os.path.join(*parts[:i]))
    for pkg in pkgs_needing_init:
        out[os.path.join(pkg, "__init__.pyi")] = ""
    # top-level heavy pkg with no submodule import (e.g. `import numpy`) -> numpy.pyi
    for t in c.heavy:
        if not any(_top(m) == t for m in heavy_symbols_by_module):
            out.setdefault(f"{t}.pyi", "from typing import Any\n")
    return out


def render_pyre_config(
    out_dir_abs: str,
    tp2x_taint_abs: str,
    typeshed_abs: str,
    models_rel: str = "models",
    extra_search: Optional[List[str]] = None,
) -> str:
    """TaintP2X-shaped .pyre_configuration matching the SK setup."""
    search = [
        os.path.join(out_dir_abs, "stubs_min"),
        os.path.join(out_dir_abs, "deps_iso"),
    ]
    if extra_search:
        search.extend(extra_search)
    cfg = {
        "source_directories": ["src"],
        "taint_models_path": [tp2x_taint_abs, models_rel],
        "search_path": search,
        "typeshed": typeshed_abs,
        "exclude": [".*/tests/.*", ".*/samples/.*"],
        "strict": False,
    }
    return json.dumps(cfg, indent=2)



import re as _re
import glob as _glob


def _pypi_to_import_name(pypi_name: str) -> str:
    """'annotated-types' -> 'annotated_types'. PyPI dist names use hyphens; the
    importable package dir uses underscores."""
    return pypi_name.strip().replace("-", "_")


def _read_requires(site_packages: str, import_pkg: str) -> Set[str]:
    """Read a package's *mandatory* runtime deps from its dist-info METADATA.
    Returns import-style top-level names. Skips extras (`; extra == ...`) and
    conditional markers (`; python_version ...`, `; platform_system ...`)."""
    deps: Set[str] = set()
    # dist-info dir name uses the PyPI name; try both hyphen/underscore spellings
    patterns = [
        os.path.join(site_packages, import_pkg + "-*.dist-info", "METADATA"),
        os.path.join(site_packages, import_pkg.replace("_", "-") + "-*.dist-info", "METADATA"),
    ]
    metas: List[str] = []
    for pat in patterns:
        metas.extend(_glob.glob(pat))
    for meta in metas:
        try:
            with open(meta) as fh:
                for line in fh:
                    if not line.startswith("Requires-Dist:"):
                        continue
                    spec = line[len("Requires-Dist:"):].strip()
                    # skip anything gated by a marker that isn't unconditionally true
                    if ";" in spec:
                        marker = spec.split(";", 1)[1]
                        # extras and platform/py-version gated deps -> optional, skip
                        if "extra ==" in marker or "platform_system" in marker or "sys_platform" in marker:
                            continue
                        # python_version gated: keep (usually satisfied); fall through
                    # dep name is the leading token before any version/space/[extra]
                    m = _re.match(r"^([A-Za-z0-9_.\-]+)", spec)
                    if not m:
                        continue
                    deps.add(_pypi_to_import_name(m.group(1)))
        except OSError:
            continue
    return deps


def resolve_transitive_isolates(
    seed_pkgs: Set[str],
    site_packages: str,
    heavy: Set[str],
) -> Set[str]:
    """Given seed external packages to isolate, transitively add their mandatory
    dependencies (via dist-info) that are present in site_packages. Heavy libs and
    stdlib are excluded. This mirrors the manual step of adding pydantic_core,
    annotated_types, typing_inspection alongside pydantic."""
    seen: Set[str] = set()
    queue = list(seed_pkgs)
    while queue:
        pkg = queue.pop()
        if pkg in seen:
            continue
        seen.add(pkg)
        for dep in _read_requires(site_packages, pkg):
            if dep in seen or dep in heavy or dep in _STDLIB:
                continue
            # only isolate deps that actually exist in this environment
            if (os.path.exists(os.path.join(site_packages, dep))
                    or os.path.exists(os.path.join(site_packages, dep + ".py"))):
                queue.append(dep)
    return seen


def build_subset(
    out_dir: str,
    entry_files: List[str],
    target_pkg: str,
    site_packages: str,
    tp2x_taint: str,
    typeshed: str,
    heavy: Optional[Set[str]] = None,
    dry_run: bool = False,
) -> Classification:
    """Create <out_dir>/{deps_iso, stubs_min, models} and .pyre_configuration.

    Does NOT copy the target package src (caller copies the real package into
    <out_dir>/src, mirroring the SK workflow). Returns the Classification so the
    caller can inspect/verify what was isolated vs stubbed.

    dry_run=True: compute & return classification without touching the filesystem.
    """
    heavy = DEFAULT_HEAVY if heavy is None else heavy
    entry_sources = {}
    for f in entry_files:
        with open(f) as fh:
            entry_sources[f] = fh.read()
    c = classify_imports(entry_sources, target_pkg, heavy)

    # expand isolate set with transitive mandatory deps (pydantic -> pydantic_core,
    # annotated_types, typing_inspection, ...) so pydantic types fully resolve and
    # taint doesn't over-approximate through obscure models.
    c.isolate = resolve_transitive_isolates(set(c.isolate), site_packages, heavy)

    if dry_run:
        return c

    out_abs = os.path.abspath(out_dir)
    deps_iso = os.path.join(out_abs, "deps_iso")
    stubs_min = os.path.join(out_abs, "stubs_min")
    models = os.path.join(out_abs, "models")
    for d in (deps_iso, stubs_min, models):
        os.makedirs(d, exist_ok=True)

    # 1) isolate external (non-heavy) packages via symlink into deps_iso
    for pkg in sorted(c.isolate):
        for cand in (pkg, pkg + ".py"):
            srcp = os.path.join(site_packages, cand)
            if os.path.exists(srcp):
                dstp = os.path.join(deps_iso, cand)
                if not os.path.lexists(dstp):
                    os.symlink(srcp, dstp)
                break

    # 2) heavy libs -> stub skeletons under stubs_min
    stub_files = plan_stubs(c, c.used_symbols)
    for rel, content in stub_files.items():
        dst = os.path.join(stubs_min, rel)
        os.makedirs(os.path.dirname(dst) or stubs_min, exist_ok=True)
        # don't overwrite a hand-tuned stub if it already exists
        if not os.path.exists(dst):
            with open(dst, "w") as fh:
                fh.write(content)

    # 3) config
    cfg = render_pyre_config(out_abs, os.path.abspath(tp2x_taint), os.path.abspath(typeshed))
    with open(os.path.join(out_abs, ".pyre_configuration"), "w") as fh:
        fh.write(cfg)

    return c


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Build a Pysa-analyzable subset around a code path.")
    p.add_argument("--out", required=True)
    p.add_argument("--pkg", required=True, help="top-level target package name, e.g. semantic_kernel")
    p.add_argument("--site-packages", required=True)
    p.add_argument("--tp2x-taint", required=True)
    p.add_argument("--typeshed", required=True)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("entry", nargs="+", help="entry source files carrying source/sink")
    a = p.parse_args()
    cls = build_subset(a.out, a.entry, a.pkg, a.site_packages, a.tp2x_taint, a.typeshed, dry_run=a.dry_run)
    print("internal modules:", len(cls.internal_modules))
    print("heavy (stub)   :", sorted(cls.heavy))
    print("isolate (symlink):", sorted(cls.isolate))
    print("stdlib (typeshed):", sorted(cls.stdlib))
    if cls.used_symbols:
        print("heavy symbols  :", {k: sorted(v) for k, v in cls.used_symbols.items()})