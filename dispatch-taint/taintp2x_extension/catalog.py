"""catalog — the ``IPCMethods.txt`` of this system: a few dispatch rows per
framework, kept in ``spec.presets.json`` next to each preset, plus what makes
a tree *use* that framework (``match``).

    "langchain": {
        "tool_decorators": ["tool"], ...,                  # candidate recovery (LoweringSpec keys)
        "match":    {"imports": ["langchain", "langchain_core"], "base_classes": ["BaseTool"],
                     "decorators": ["tool"]},
        "dispatch": [{"api": "BaseTool.run", "impl": ["_run"]}, ...]   # framework dispatch methods
    }

``detect(src_root)`` says which presets a tree matches (import / base-class /
decorator counts); ``top_preset(detected)`` names the one a draft may seed its
spec from (import or discriminating base-class evidence — a decorator alone
never wins); ``framework_of(detected, presets)`` is the framework a draft is
*attributed* to in every table (summary.md, row.json ``draft_framework``,
``plan.catalog.framework``): the seeding preset when its score reaches the
preset's ``match.min_score`` (default ``FW_MIN_SCORE`` = 20), else "(none)" —
nine incidental ``semantic_kernel`` imports in 170 files (MetaGPT) or one
``@click.command`` (litellm) attribute a tree to nothing (review M4);
``stale(...)`` tells "the catalogue is stale" (the ATTRIBUTED framework is
imported, none of its dispatch APIs is defined IN THE TREE — a definition
found only on the analysis search path, e.g. the venv, does not count and is
named as such) apart from "there is no surface" when a draft accepted nothing.
A framework below the threshold never makes the catalogue stale.

``match.imports`` entries are dotted prefixes: ``"app.tool"`` matches
``import app.tool.base`` and ``from app.tool import BaseTool`` (the imported
name is appended too, so ``"agents.function_tool"`` matches
``from agents import function_tool``); a bare top-level name such as ``"app"``
or ``"agents"`` would claim every project with a package of that name (review
M4). Relative imports (``from .agents import x``) are never counted.

    python3 catalog.py detect <src_root> [--presets spec.presets.json]
    python3 catalog.py rows   [--presets spec.presets.json]
"""
from __future__ import annotations

import argparse
import ast
import collections
import json
import os
import sys
from typing import Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATH = os.path.join(_HERE, "spec.presets.json")
NONE = "(none)"
# review M4: import / base-class evidence below this score attributes a tree
# to no framework (MetaGPT: 9 semantic_kernel imports in 170 files; litellm:
# one @click.command). A preset may override it with ``match.min_score``.
FW_MIN_SCORE = 20


def load(path: str = "") -> Dict[str, dict]:
    path = path or DEFAULT_PATH
    if not os.path.exists(path):
        return {}
    data = json.load(open(path))
    return {k: v for k, v in data.items() if isinstance(v, dict) and not k.startswith("_")}


def dispatch_rows(presets: Dict[str, dict]) -> List[dict]:
    rows = []
    for name, p in presets.items():
        for r in p.get("dispatch", []) or []:
            if isinstance(r, str):
                r = {"api": r}
            r = dict(r)
            r.setdefault("framework", name)
            r.setdefault("impl", [])
            rows.append(r)
    return rows


def _dec_last(dec) -> str:
    if isinstance(dec, ast.Call):
        dec = dec.func
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Name):
        return dec.id
    return ""


def _prefixes(dotted: str):
    """``a.b.c`` -> ``a``, ``a.b``, ``a.b.c``."""
    parts = [p for p in dotted.split(".") if p]
    for i in range(1, len(parts) + 1):
        yield ".".join(parts[:i])


def detect(src_root: str, presets: Dict[str, dict]) -> dict:
    """Which presets the tree matches and why (counts of matching imports,
    base classes and decorators). Only presets with a ``match`` block count.

    Imports are counted by every dotted prefix of the imported module (plus
    the imported name for ``from m import n``), so a ``match.imports`` entry
    may be as specific as the preset needs. Relative imports are skipped:
    ``from .agents import x`` says nothing about a framework (review M4)."""
    imports = collections.Counter()
    bases = collections.Counter()
    decs = collections.Counter()
    files = 0
    for root, dirs, fs in os.walk(src_root):
        dirs[:] = [d for d in dirs if d not in (".venv", "site-packages", "__pycache__")]
        for f in fs:
            if not f.endswith(".py"):
                continue
            files += 1
            try:
                tree = ast.parse(open(os.path.join(root, f), encoding="utf-8", errors="replace").read())
            except Exception:
                continue
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    for a in n.names:
                        for pre in _prefixes(a.name):
                            imports[pre] += 1
                elif isinstance(n, ast.ImportFrom):
                    # review M4: a relative import names a sibling of the
                    # importing module, never a framework
                    if n.level or not n.module:
                        continue
                    for pre in _prefixes(n.module):
                        imports[pre] += 1
                    for a in n.names:
                        if a.name != "*":
                            imports[n.module + "." + a.name] += 1
                elif isinstance(n, ast.ClassDef):
                    for b in n.bases:
                        bases[b.attr if isinstance(b, ast.Attribute) else (b.id if isinstance(b, ast.Name) else "")] += 1
                elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for d in n.decorator_list:
                        decs[_dec_last(d)] += 1
    out = {"files": files, "detected": [], "scores": {}}
    for name, p in presets.items():
        m = p.get("match") or {}
        if not m:
            continue
        hit = {"imports": {i: imports[i] for i in m.get("imports", []) if imports.get(i)},
               "base_classes": {b: bases[b] for b in m.get("base_classes", []) if bases.get(b)},
               "decorators": {d: decs[d] for d in m.get("decorators", []) if decs.get(d)}}
        score = sum(hit["imports"].values()) + 5 * sum(hit["base_classes"].values()) + 3 * sum(hit["decorators"].values())
        if score:
            out["scores"][name] = {"score": score, **hit}
            out["detected"].append(name)
    out["detected"].sort(key=lambda n: -out["scores"][n]["score"])
    return out


def top_preset(detected: dict) -> str:
    """The preset a draft may seed its spec from, or ``""``.

    Evidence order (review M4): the best-scoring preset the tree *imports*;
    else the best-scoring preset whose matched base class is not shared with
    another detected preset (``ToolCallAgent`` discriminates, ``BaseTool`` does
    not); never a preset matched by a decorator name alone (``@command`` in a
    click CLI made litellm an "autogpt" tree)."""
    scores = detected.get("scores") or {}
    order = list(detected.get("detected") or [])
    for n in order:
        if (scores.get(n) or {}).get("imports"):
            return n
    for n in order:
        mine = set((scores.get(n) or {}).get("base_classes") or {})
        others = {b for m in order if m != n for b in ((scores.get(m) or {}).get("base_classes") or {})}
        if mine - others:
            return n
    return ""


def min_score_of(name: str, presets: Dict[str, dict], default: int = FW_MIN_SCORE) -> int:
    """The evidence a preset demands before a tree is attributed to it:
    ``match.min_score`` of the preset, else ``default`` (FW_MIN_SCORE)."""
    try:
        return int((((presets or {}).get(name) or {}).get("match") or {}).get("min_score", default))
    except (TypeError, ValueError):
        return default


def framework_of(detected: dict, presets: Dict[str, dict], min_score: int = FW_MIN_SCORE) -> str:
    """The framework a draft is attributed to (review M4), or ``"(none)"``.

    One rule for every plan version: the seeding preset — ``detected["top"]``
    as a version-2 plan recorded it (``None`` = nothing seeded), else
    ``top_preset()`` recomputed from the scores of a version-1 plan — counts
    only when its score reaches ``min_score_of(preset)`` (``match.min_score``,
    default ``min_score``). A decorator-only match, a missing score or a weak
    one (MetaGPT: semantic_kernel 9) is "(none)". Seeding (``top``) and
    attribution (this) differ on purpose: a weak match may still supply
    recovery keys a draft could not derive, but it never names the tree's
    framework in a table and never makes the catalogue stale."""
    detected = detected or {}
    top = detected.get("top") if "top" in detected else top_preset(detected)
    if not top:
        return NONE
    score = ((detected.get("scores") or {}).get(top) or {}).get("score") or 0
    return top if score >= min_score_of(top, presets, min_score) else NONE


def impl_map_for(rows: List[dict], active) -> Dict[str, List[str]]:
    """The ``dispatch_impl_map`` the catalogue licenses for the ACTIVE
    frameworks (review M10 / K7): API method name -> impl method names, folded
    from the dispatch rows of those frameworks only, keys sorted, impl names
    deduplicated in row order. No active framework with rows -> ``{}`` (the
    plan then writes an empty map, never the lowering's built-in one).
    ``draft.derive_spec`` and ``impl_map_stale`` share this one fold."""
    active = set(active or ())
    out: Dict[str, List[str]] = {}
    for row in rows:
        if row.get("framework") not in active or not row.get("impl"):
            continue
        meth = row["api"].rsplit(".", 1)[-1]
        out.setdefault(meth, [])
        out[meth] += [x for x in row["impl"] if x not in out[meth]]
    return {k: v for k, v in sorted(out.items())}


def active_frameworks(detected: dict, rows: List[dict], preset: str = "") -> set:
    """The frameworks whose rows a draft folds into ``dispatch_impl_map``
    (review M10): the presets the tree IMPORTS (a base class shared by four
    presets is no evidence), the seeding preset (``detected["top"]`` as a
    version-2 plan recorded it, else ``top_preset()`` from the scores of a
    version-1 plan) and the explicit ``--preset`` — restricted to frameworks
    that have dispatch rows, so ``autogpt`` never contributes."""
    detected = detected or {}
    scores = detected.get("scores") or {}
    active = {n for n in (detected.get("detected") or []) if (scores.get(n) or {}).get("imports")}
    top = detected.get("top") if "top" in detected else top_preset(detected)
    active.update(n for n in (top, preset) if n)
    return active & {r.get("framework") for r in rows}


def impl_map_stale(plan: dict, presets: Dict[str, dict], preset: str = "") -> str:
    """Why a plan's ``dispatch_impl_map`` is not the one the current catalogue
    gives for the plan's own catalog evidence — ``""`` when it is. Review M10:
    a plan drafted before the framework-restricted fold carries the merged
    all-framework map (``call_tool -> run`` in an AutoGPT tree) or no map at
    all (the lowering fell back to its built-in one); such a plan has to be
    re-drafted before its row is cited. ``preset`` is the explicit --preset
    the draft ran with (the manifest's). Works offline, on the plan alone."""
    rows = dispatch_rows(presets)
    active = active_frameworks(plan.get("catalog") or {}, rows, preset)
    want = impl_map_for(rows, active)
    for g in plan.get("groups") or []:
        sp = g.get("spec") or {}
        if "dispatch_impl_map" not in sp:
            return f"{g.get('id', '?')}: no dispatch_impl_map (pre-M10 plan; the lowering fell back to its built-in map)"
        have = {k: list(v) for k, v in sorted((sp.get("dispatch_impl_map") or {}).items())}
        if have != want:
            extra, missing = sorted(set(have) - set(want)), sorted(set(want) - set(have))
            changed = sorted(k for k in set(have) & set(want) if have[k] != want[k])
            return (f"{g.get('id', '?')}: dispatch_impl_map is not the catalogue rows of "
                    f"{sorted(active) or 'no framework'}"
                    + (f"; extra keys {extra}" if extra else "") + (f"; missing keys {missing}" if missing else "")
                    + (f"; different impls for {changed}" if changed else ""))
    return ""


def _presence(v) -> Dict[str, bool]:
    """Normalise one ``catalog_status`` value. New shape (engine_walls):
    ``{"in_repo": bool, "search_path": bool}``; old shape: ``"present"`` /
    ``"absent"`` (present anywhere on the analysis search path, venv included,
    so it is taken as in-repo evidence — the old, weaker meaning)."""
    if isinstance(v, dict):
        return {"in_repo": bool(v.get("in_repo")), "search_path": bool(v.get("search_path"))}
    if isinstance(v, str):
        return {"in_repo": v == "present", "search_path": v == "present"}
    return {"in_repo": False, "search_path": False}


def merge_status(catalog_status: Dict[str, object],
                 catalog_status_search_path: Optional[Dict[str, object]] = None) -> Dict[str, dict]:
    """The per-API ``{"in_repo": bool, "search_path": bool}`` view from what
    ``engine_walls.scan`` emits (review M4): ``env["catalog_status"]`` —
    ``present`` means the API exists as an IN-REPO callable (the functions.json
    name's module prefix maps to a file of the tree) — and
    ``env["catalog_status_search_path"]`` — present anywhere on the analysis
    search path, venv included. Values already in the dict shape pass through."""
    cs, sp = catalog_status or {}, catalog_status_search_path or {}
    out = {}
    for api in set(cs) | set(sp):
        p = _presence(cs.get(api))
        q = _presence(sp.get(api)) if api in sp else {"in_repo": False, "search_path": False}
        out[api] = {"in_repo": p["in_repo"], "search_path": p["search_path"] or q["search_path"] or q["in_repo"]}
    return out


def status_for(detected: dict, catalog_status: Dict[str, object], presets: Dict[str, dict],
               catalog_status_search_path: Optional[Dict[str, object]] = None) -> dict:
    """Per detected framework: dispatch rows ``present`` (defined in the tree),
    ``search_path`` (found only outside the tree, e.g. the venv) and
    ``absent`` (nowhere). ``catalog_status`` is engine_walls' in-repo map (or
    the dict shape); ``catalog_status_search_path`` its venv-inclusive twin —
    see merge_status()."""
    rows = dispatch_rows(presets)
    status = merge_status(catalog_status, catalog_status_search_path)
    res = {}
    for name in detected.get("detected", []):
        mine = [r for r in rows if r["framework"] == name]
        present, on_path, absent = [], [], []
        for r in mine:
            p = status.get(r["api"]) or {"in_repo": False, "search_path": False}
            if p["in_repo"]:
                present.append(r["api"])
            elif p["search_path"]:
                on_path.append(r["api"])
            else:
                absent.append(r["api"])
        res[name] = {"present": present, "search_path": on_path, "absent": absent}
    return res


def stale(detected: dict, catalog_status: Dict[str, object], presets: Dict[str, dict] = None,
          catalog_status_search_path: Optional[Dict[str, object]] = None,
          min_score: int = FW_MIN_SCORE) -> List[str]:
    """Reasons the catalogue looks stale: the framework the tree is ATTRIBUTED
    to (``framework_of``: the seeding preset with import evidence of score >=
    ``match.min_score`` / ``min_score``) has no dispatch row defined in the
    tree itself (``env["catalog_status"]`` of engine_walls.scan: present =
    defined in an IN-REPO callable). A row that exists only on the analysis
    search path (the framework installed in the venv;
    ``env["catalog_status_search_path"]``) is named separately — "none of
    [...] is defined in the tree (on the analysis search path only: [...])" —
    so ``catalog_stale`` is distinguishable from "framework only installed"
    (review M4). Frameworks below the threshold or imported incidentally next
    to the attributed one (SuperAGI also imports llama_index / langchain)
    never make the catalogue stale: an accept-0 draft of such a tree is
    ``no_surface`` / ``no_walls``, not ``catalog_stale`` (review M4 repair)."""
    presets = presets if presets is not None else load()
    out = []
    fw = framework_of(detected, presets, min_score)
    if fw == NONE:
        return out
    for name, st in status_for(detected, catalog_status, presets, catalog_status_search_path).items():
        if name != fw:
            continue
        # only a framework the tree actually imports can make the catalogue
        # stale; a base-class name shared with another framework (BaseTool)
        # is not evidence that this one is in use
        if not (detected.get("scores", {}).get(name) or {}).get("imports"):
            continue
        if (st["absent"] or st["search_path"]) and not st["present"]:
            msg = f"{name}: none of {st['absent'] + st['search_path']} is defined in the tree"
            if st["search_path"]:
                msg += f" (on the analysis search path only: {st['search_path']})"
            out.append(msg)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("detect")
    d.add_argument("src_root")
    d.add_argument("--presets", default=DEFAULT_PATH)
    r = sub.add_parser("rows")
    r.add_argument("--presets", default=DEFAULT_PATH)
    a = ap.parse_args(argv)
    presets = load(a.presets)
    if a.cmd == "detect":
        print(json.dumps(detect(a.src_root, presets), indent=2))
    else:
        for row in dispatch_rows(presets):
            print(f"{row['framework']:16s} {row['api']:40s} -> {', '.join(row['impl']) or '-'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
