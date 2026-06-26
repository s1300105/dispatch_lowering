"""Independent-annotation infrastructure for the tool-classifier gold (external validity).

The RQ4 gold (``benchmark.labels.GOLD``) is single-annotator. To measure inter-annotator
agreement we need a fixed, reproducible *candidate pool* per repo and per-candidate label
sheets over it:

  * BLANK  — for an independent 2nd annotator to fill, blind (no gold, no model output);
  * GOLD   — auto-derived from ``GOLD`` (annotator #1);
  * MODEL  — derived from a classifier's ``RepoToolModel`` (annotator-vs-tool agreement).

``cohens_kappa`` / ``agreement_report`` then compute Cohen's kappa per label dimension
(tool-ness, role, sink-category, guard), matching rows by qualified name, so RQ4 can report
agreement instead of trusting one annotator. The human step is one 2nd annotator filling a
BLANK sheet; everything here (pool, GOLD/MODEL sheets, kappa) is deterministic.
"""
from __future__ import annotations

import ast
import csv
import os
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from .labels import CORPUS_BASE, GOLD

# label vocabularies (kept aligned with the model / engine)
ROLES = ("source", "sink", "both", "none")
CATS = ("network", "code_execution", "file_write", "sql", "deserialize", "none")
GUARDS = ("yes", "no", "na")
_SCHEMA_METHODS = {"openai_schema", "get_openai_schema", "function_schema", "tool_schema",
                   "to_openai_tool", "to_function_tool", "as_tool", "args_schema"}
SHEET_COLUMNS = ["id", "qualname", "kind", "file", "line", "signature",
                 "is_tool", "role", "sink_category", "guarded", "notes"]


@dataclass
class Candidate:
    qualname: str
    name: str
    kind: str                      # "function" | "method" | "class"
    file: str
    line: int
    signature: str
    match_names: Set[str] = field(default_factory=set)


# --------------------------------------------------------------------------- #
# candidate pool
# --------------------------------------------------------------------------- #
def _module_name(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = Path(path.name)
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _signature(node) -> str:
    if isinstance(node, ast.ClassDef):
        bases = ", ".join(_name(b) for b in node.bases if _name(b))
        return f"class {node.name}({bases})" if bases else f"class {node.name}"
    args = [a.arg for a in node.args.args]
    if node.args.vararg:
        args.append("*" + node.args.vararg.arg)
    if node.args.kwarg:
        args.append("**" + node.args.kwarg.arg)
    kw = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    return f"{kw} {node.name}({', '.join(args)})"


def _name(node) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _class_tool_names(cls: ast.ClassDef) -> Set[str]:
    """Names a class-based tool may be registered under: the class name, a class-level
    ``name = "..."`` / ``_name = "..."`` attribute, and the ``"name"`` key of a dict in a
    schema method (e.g. shell_gpt's ``openai_schema``)."""
    names = {cls.name}
    for n in cls.body:
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and t.id in ("name", "_name", "tool_name") and \
                   isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
                    names.add(n.value.value)
        elif isinstance(n, ast.AnnAssign):                       # name: str = "shell"
            if isinstance(n.target, ast.Name) and n.target.id in ("name", "_name", "tool_name") and \
               isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
                names.add(n.value.value)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if n.name in ("name", "_name", "tool_name"):         # @property def name(): return "shell"
                for s in ast.walk(n):
                    if isinstance(s, ast.Return) and isinstance(s.value, ast.Constant) \
                       and isinstance(s.value.value, str):
                        names.add(s.value.value)
            if n.name in _SCHEMA_METHODS:
                for d in ast.walk(n):
                    if isinstance(d, ast.Dict):
                        for k, v in zip(d.keys, d.values):
                            if isinstance(k, ast.Constant) and k.value == "name" and \
                               isinstance(v, ast.Constant) and isinstance(v.value, str):
                                names.add(v.value)
    return names


def candidate_pool(repo: str, src_rel: Optional[str] = None) -> List[Candidate]:
    """Every function/method/class in the repo source (tests / dunder excluded)."""
    root = Path(repo)
    base = (root / src_rel) if src_rel else root
    out: List[Candidate] = []
    for py in sorted(base.rglob("*.py")):
        if any(p in (".venv", "site-packages", "tests", "test", "__pycache__") for p in py.parts):
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except Exception:
            continue
        mod = _module_name(py, root)
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                cnames = _class_tool_names(node)
                out.append(Candidate(f"{mod}.{node.name}", node.name, "class",
                                      str(py), node.lineno, _signature(node), set(cnames)))
                for m in node.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and not m.name.startswith("_"):
                        out.append(Candidate(f"{mod}.{node.name}.{m.name}", m.name, "method",
                                             str(py), m.lineno, _signature(m), {m.name}))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                out.append(Candidate(f"{mod}.{node.name}", node.name, "function",
                                     str(py), node.lineno, _signature(node), {node.name}))
    return out


# --------------------------------------------------------------------------- #
# labels
# --------------------------------------------------------------------------- #
def _role_str(roles) -> str:
    s = "source" in roles
    k = "sink" in roles
    return "both" if (s and k) else "sink" if k else "source" if s else "none"


def _blank_label() -> Dict[str, str]:
    return {"is_tool": "", "role": "", "sink_category": "", "guarded": "", "notes": ""}


def _label_from_spec(roles, category, guard) -> Dict[str, str]:
    role = _role_str(roles)
    is_sink = role in ("sink", "both")
    return {
        "is_tool": "Y",
        "role": role,
        "sink_category": (category or "none") if is_sink else "none",
        "guarded": ("yes" if guard else "no") if is_sink else "na",
        "notes": "",
    }


def gold_tools(repo_key: str) -> Dict[str, dict]:
    return GOLD.get(repo_key, {}).get("tools", {})


def label_from_gold(cand: Candidate, tools: Dict[str, dict]) -> Dict[str, str]:
    for tname, spec in tools.items():
        if tname in cand.match_names:
            return _label_from_spec(spec.get("roles", []), spec.get("category"), spec.get("guard"))
    return {"is_tool": "N", **{k: ("none" if k in ("role", "sink_category") else "na" if k == "guarded" else "")
                               for k in ("role", "sink_category", "guarded", "notes")}}


def label_from_model(cand: Candidate, model) -> Dict[str, str]:
    for t in model.tools:
        cls_of_callable = t.callable.rsplit(".", 1)[0] if (t.callable and "." in t.callable) else None
        if t.name in cand.match_names or (cls_of_callable and cls_of_callable == cand.qualname):
            g = t.sink.guard if t.sink else None
            cat = t.sink.category if t.sink else None
            return _label_from_spec(t.roles, cat, g)
    return {"is_tool": "N", "role": "none", "sink_category": "none", "guarded": "na", "notes": ""}


# --------------------------------------------------------------------------- #
# sheets
# --------------------------------------------------------------------------- #
def _select(cands: List[Candidate], sample: Optional[int], seed: int,
            must_include: Optional[Set[str]] = None) -> List[Candidate]:
    if not sample or sample >= len(cands):
        return cands
    must = must_include or set()
    keep = [c for c in cands if c.match_names & must]
    rest = [c for c in cands if not (c.match_names & must)]
    rng = random.Random(seed)
    rng.shuffle(rest)
    chosen = keep + rest[: max(0, sample - len(keep))]
    chosen.sort(key=lambda c: (c.file, c.line))
    return chosen


def build_sheet(repo: str, src_rel: Optional[str], kind: str,
                repo_key: Optional[str] = None, model=None,
                sample: Optional[int] = None, seed: int = 0) -> List[Dict[str, str]]:
    """kind: 'blank' | 'gold' | 'model'. Same (sample, seed) -> aligned pools across kinds."""
    cands = candidate_pool(repo, src_rel)
    must = set(gold_tools(repo_key or "").keys()) if repo_key else set()
    cands = _select(cands, sample, seed, must)
    tools = gold_tools(repo_key or "") if kind == "gold" else {}
    rows: List[Dict[str, str]] = []
    for i, c in enumerate(cands, 1):
        if kind == "gold":
            lab = label_from_gold(c, tools)
        elif kind == "model":
            lab = label_from_model(c, model)
        else:
            lab = _blank_label()
        rows.append({"id": str(i), "qualname": c.qualname, "kind": c.kind,
                     "file": os.path.relpath(c.file, repo), "line": str(c.line),
                     "signature": c.signature, **lab})
    return rows


def write_csv(rows: List[Dict[str, str]], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SHEET_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in SHEET_COLUMNS})


def read_csv(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# --------------------------------------------------------------------------- #
# agreement
# --------------------------------------------------------------------------- #
def cohens_kappa(a: List[str], b: List[str]) -> Dict[str, float]:
    """Cohen's kappa for paired nominal labels a[i] vs b[i]."""
    n = len(a)
    if n == 0:
        return {"kappa": float("nan"), "po": float("nan"), "pe": float("nan"), "n": 0}
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    cats = set(a) | set(b)
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    if pe >= 1.0:                       # degenerate (single category) -> kappa undefined
        kappa = 1.0 if po == 1.0 else 0.0
    else:
        kappa = (po - pe) / (1.0 - pe)
    return {"kappa": kappa, "po": po, "pe": pe, "n": n}


def _norm(row: Dict[str, str], col: str) -> str:
    return (row.get(col) or "").strip().lower()


def agreement_report(rows_a: List[Dict[str, str]], rows_b: List[Dict[str, str]]) -> Dict[str, dict]:
    """Kappa per dimension over rows matched by qualname. 'role'/'sink_category'/'guarded'
    are also reported over the TOOLS-ONLY subset (either side marked is_tool=Y) since the
    full pool is dominated by non-tools."""
    by_a = {r["qualname"]: r for r in rows_a}
    by_b = {r["qualname"]: r for r in rows_b}
    keys = [q for q in by_a if q in by_b]
    out: Dict[str, dict] = {"n_matched": len(keys),
                            "n_only_a": len(by_a) - len(keys),
                            "n_only_b": len(by_b) - len(keys)}

    def col(rows, q, c):
        v = _norm(rows[q], c)
        return v if v else "none"

    out["is_tool"] = cohens_kappa([col(by_a, q, "is_tool") for q in keys],
                                  [col(by_b, q, "is_tool") for q in keys])
    tool_keys = [q for q in keys if "y" in (col(by_a, q, "is_tool"), col(by_b, q, "is_tool"))]
    for dim in ("role", "sink_category", "guarded"):
        out[dim] = cohens_kappa([col(by_a, q, dim) for q in keys],
                                [col(by_b, q, dim) for q in keys])
        out[dim + "_tools_only"] = cohens_kappa([col(by_a, q, dim) for q in tool_keys],
                                                [col(by_b, q, dim) for q in tool_keys])
    return out


def coverage_check(repo: str, src_rel: Optional[str], repo_key: str) -> Dict[str, list]:
    """Which gold tools map to a candidate (so the GOLD sheet is faithful), and which don't."""
    cands = candidate_pool(repo, src_rel)
    allnames: Set[str] = set()
    for c in cands:
        allnames |= c.match_names
    tools = gold_tools(repo_key)
    matched = [t for t in tools if t in allnames]
    missing = [t for t in tools if t not in allnames]
    return {"matched": sorted(matched), "missing": missing}
