#!/usr/bin/env python3
"""Post-process Pysa output into ctaudit cross-tool implicit-flow findings.

Pysa (run with `pyre analyze`) produces raw source->sink data flows. This script:

  1. reads Pysa's ``taint-output.json``;
  2. keeps the flows whose rule code is one of ours (9001–9005) and whose trace
     carries the ``llm_node`` feature -> these are the IMPLICIT (CWE-1426)
     cross-tool flows (the others are explicit/verbatim TITO);
  3. rebuilds them as ``ctaudit.report.Finding`` objects and runs the project's
     own §4.5 pruning (schema/role, using the capacity/role features Pysa
     attached) and §4.6 triage — reusing the exact code from the standalone tool.

So Pysa supplies the (now sound, inter-procedural, full-sink) data layer, and
the novel ctaudit layer rides on top, unchanged.

Usage:
    python postprocess.py path/to/pysa-results            # dir or taint-output.json
    python postprocess.py pysa-results --triage anthropic --show-pruned --json

The Pysa output schema varies across pyre-check versions; field extraction here
is deliberately defensive. If it cannot find issues, it prints the top-level
keys it saw so you can adjust ``_iter_issues`` in one place.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

# reuse the standalone tool's data structures + novel layer.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ast                                                             # noqa: E402
import re                                                              # noqa: E402

from ctaudit.analysis.pruning import PruneConfig, RolePolicy, prune   # noqa: E402
from ctaudit.labels import SourceMark                                  # noqa: E402
from ctaudit.models.aliases import AliasResolver                       # noqa: E402
from ctaudit.report import Finding, render_findings                    # noqa: E402
from ctaudit.triage.llm_triage import get_triager                      # noqa: E402

# our rule codes (must match models/taint.config) -> ctaudit sink category.
CODE_TO_CATEGORY = {
    9001: ("exec", "high"),
    9002: ("sql", "high"),
    9003: ("network", "medium"),
    9004: ("file", "medium"),
    9005: ("deserialize", "high"),
}
KNOWN_FEATURES = {"llm_node", "cap_bool", "cap_enum", "cap_string",
                  "role_readonly", "role_exec"}


# --------------------------------------------------------------------------- #
# reading Pysa output (defensive across schema versions)
# --------------------------------------------------------------------------- #
def _load_json(path: str) -> Any:
    p = Path(path)
    if p.is_dir():
        cand = p / "taint-output.json"
        if not cand.exists():
            # some versions shard output; take the first taint-output*.json
            shards = sorted(p.glob("taint-output*.json"))
            if not shards:
                raise SystemExit(f"no taint-output.json under {p}")
            cand = shards[0]
        p = cand
    text = p.read_text(encoding="utf-8")
    # pyre may emit JSON-lines; try array first, then line-by-line.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def _iter_issues(doc: Any) -> Iterable[Dict[str, Any]]:
    """Yield issue dicts regardless of the wrapper shape."""
    if isinstance(doc, dict):
        if "issues" in doc and isinstance(doc["issues"], list):
            yield from (i for i in doc["issues"] if isinstance(i, dict))
            return
        doc = [doc]
    if isinstance(doc, list):
        for item in doc:
            if not isinstance(item, dict):
                continue
            if item.get("kind") == "issue" or "code" in item:
                yield item


def _collect_feature_tokens(node: Any, out: Set[str]) -> None:
    """Recursively gather any of our known feature names appearing anywhere."""
    if isinstance(node, str):
        for f in KNOWN_FEATURES:
            if f in node:
                out.add(f)
    elif isinstance(node, dict):
        for v in node.values():
            _collect_feature_tokens(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_feature_tokens(v, out)


def _first(d: Dict[str, Any], *keys: str, default=None):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


# --------------------------------------------------------------------------- #
# structural implicit detection (does the flow traverse a modeled LLM node?)
#
# The `llm_node` breadcrumb is a precise but FRAGILE signal: Pysa's broadening
# (`tito-broadening`) can drop it over long post-LLM projection chains
# (response -> attr chain -> json.loads -> **splat -> sink), and an aliased LLM
# call may even be `obscure:unknown-callee` so the model never tags it. So we
# also classify a flow as implicit STRUCTURALLY: does any callable on the flow's
# trace invoke a function we modeled as an LLM node? Aliased calls
# (`completion = client.chat.completions.create`) are resolved with the same
# binding resolver the standalone engine uses (§6.4 part-A).
# --------------------------------------------------------------------------- #
def _llm_node_patterns(models_paths: List[str]) -> List[tuple]:
    """Parse .pysa models for functions modeled with the `llm_node` feature.

    Returns (final_attr, receiver_hint) pairs, e.g. ('create', 'completions'),
    derived from a qualified name like ``openai._Completions.create``.
    """
    pats: List[tuple] = []
    line_re = re.compile(r"def\s+([A-Za-z_][\w\.]*)\s*\(")
    for mp in models_paths:
        for pf in Path(mp).glob("*.pysa"):
            for line in pf.read_text(encoding="utf-8").splitlines():
                if "llm_node" not in line:
                    continue
                m = line_re.search(line)
                if not m:
                    continue
                segs = m.group(1).split(".")
                final = segs[-1]
                hint = re.sub(r"[^a-z]", "", segs[-2].lower()) if len(segs) >= 2 else ""
                pats.append((final, hint))
    return pats


def _name_is_llm_node(dotted: str, pats: List[tuple]) -> bool:
    d = dotted.lower()
    last = d.rsplit(".", 1)[-1]
    for final, hint in pats:
        if last == final.lower() and (not hint or hint in d):
            return True
    return False


_SOURCE_CACHE: Dict[str, Optional[ast.AST]] = {}


def _repo_root(results_path: str) -> Optional[str]:
    """Pyre records the analyzed repo in call-graph.json's first line."""
    d = Path(results_path)
    d = d if d.is_dir() else d.parent
    cg = d / "call-graph.json"
    if not cg.exists():
        return None
    try:
        first = cg.read_text(encoding="utf-8").splitlines()[0]
        return json.loads(first).get("config", {}).get("repo")
    except Exception:
        return None


def _module_ast(repo_root: str, rel_path: str) -> Optional[ast.AST]:
    key = os.path.join(repo_root or "", rel_path or "")
    if key in _SOURCE_CACHE:
        return _SOURCE_CACHE[key]
    tree = None
    # the analyzed file may sit under a source dir (e.g. src/); search for it.
    cands = [Path(repo_root or "") / rel_path]
    if repo_root and rel_path:
        cands += list(Path(repo_root).rglob(os.path.basename(rel_path)))
    for c in cands:
        try:
            tree = ast.parse(Path(c).read_text(encoding="utf-8"))
            break
        except Exception:
            continue
    _SOURCE_CACHE[key] = tree
    return tree


def _callable_short_names(issue_data: Dict[str, Any]) -> Set[str]:
    """Function names whose bodies the flow passes through: the issue callable
    plus every `resolves_to` callee named in the forward/backward traces."""
    names: Set[str] = set()
    cal = issue_data.get("callable")
    if isinstance(cal, str):
        names.add(cal.split(".")[-1])

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            call = node.get("call")
            if isinstance(call, dict):
                for tgt in call.get("resolves_to", []) or []:
                    if isinstance(tgt, str):
                        names.add(tgt.split(".")[-1])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(issue_data.get("traces", []))
    return names


def _dotted_of(func: ast.AST) -> str:
    """Best-effort dotted source of a call target (e.g. self._client.post)."""
    parts = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _fn_calls_llm_node(fn: ast.AST, aliases, pats: List[tuple]) -> bool:
    for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
        # (a) alias-resolved candidates (imports, `x = dotted.callable`)
        for cand in aliases.resolve_callee(call.func):
            if _name_is_llm_node(cand, pats):
                return True
        # (b) raw dotted name (instance-attr calls like self._client.post that
        #     the alias resolver does not rewrite)
        if _name_is_llm_node(_dotted_of(call.func), pats):
            return True
    return False


def _flow_traverses_llm_node(issue_data: Dict[str, Any], repo_root: Optional[str],
                             pats: List[tuple]) -> bool:
    """True if any callable in the flow's bounded call-closure invokes a modeled
    LLM node. The closure starts from the issue's callables (issue callable +
    trace `resolves_to`) and expands one hop at a time over same-file callees by
    name, so a provider abstraction two hops away (agent -> provider.complete ->
    httpx.post) is still seen — while staying scoped to the flow (an unrelated
    LLM call elsewhere in the module is not reached)."""
    if not pats or not repo_root:
        return False
    rel = _first(issue_data, "filename", "path", "file", default="")
    tree = _module_ast(repo_root, rel)
    if tree is None:
        return False
    aliases = AliasResolver.from_module(tree)
    by_name: Dict[str, List[ast.AST]] = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            by_name.setdefault(n.name, []).append(n)

    frontier = set(_callable_short_names(issue_data))
    seen: Set[str] = set()
    for _depth in range(5):                      # bounded transitive closure
        nxt: Set[str] = set()
        for name in frontier - seen:
            seen.add(name)
            for fn in by_name.get(name, []):
                if _fn_calls_llm_node(fn, aliases, pats):
                    return True
                # expand to this function's same-file callees (by final name)
                for c in (x for x in ast.walk(fn) if isinstance(x, ast.Call)):
                    fin = _dotted_of(c.func).split(".")[-1]
                    if fin in by_name:
                        nxt.add(fin)
        frontier = nxt
        if not frontier:
            break
    return False



def _sink_from_traces(data: Dict[str, Any]) -> Optional[str]:
    """Pick the most specific sink name from the backward trace leaves
    (e.g. ``subprocess.run`` rather than the enclosing define)."""
    names: List[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            leaves = node.get("leaves")
            if isinstance(leaves, list):
                for lf in leaves:
                    if isinstance(lf, dict) and isinstance(lf.get("name"), str):
                        names.append(lf["name"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    for tr in data.get("traces", []) or []:
        if isinstance(tr, dict) and tr.get("name") == "backward":
            walk(tr)
    return names[-1] if names else None


def _to_finding(issue: Dict[str, Any], repo_root: Optional[str] = None,
                llm_pats: Optional[List[tuple]] = None) -> Optional[Finding]:
    # Pyre's taint-output.json is JSON-lines; each issue is wrapped as
    # {"kind": "issue", "data": {...}}. Unwrap to reach code/line/features.
    data = issue.get("data") if isinstance(issue.get("data"), dict) else issue

    try:
        code = int(_first(data, "code", default=-1))
    except (TypeError, ValueError):
        code = -1
    if code not in CODE_TO_CATEGORY:
        return None
    category, severity = CODE_TO_CATEGORY[code]

    feats: Set[str] = set()
    _collect_feature_tokens(data, feats)
    # implicit = the flow goes through an LLM node. Primary signal: the
    # `llm_node` breadcrumb. Fallback (robust to broadening / obscure aliased
    # calls): the flow's trace structurally traverses a modeled LLM-node call.
    implicit = "llm_node" in feats or _flow_traverses_llm_node(
        data, repo_root, llm_pats or [])
    kind = "implicit" if implicit else "explicit"

    path = _first(data, "path", "filename", "file", default="")
    line = _first(data, "line", default=None)
    loc = data.get("location") or {}
    if isinstance(loc, dict):
        line = line or loc.get("line")
        path = path or loc.get("path") or loc.get("filename") or ""
    sink_site = f"{line}" if line is not None else "?"

    sink_name = (_sink_from_traces(data)
                 or _first(data, "callable", default=None)
                 or f"<{category} sink>")
    message = _first(data, "message", "description", default="") or ""

    # capacity / role come from the source-side features Pysa attached.
    if "cap_bool" in feats:
        out_type = "bool"
    elif "cap_enum" in feats:
        out_type = "enum"
    else:
        out_type = "string"
    role = "readonly" if "role_readonly" in feats else ("exec" if "role_exec" in feats else None)

    mark = SourceMark(tool="ToolOutput", framework="pysa",
                      site=f"{path}:{sink_site}", out_type=out_type, role=role)

    return Finding(
        kind=kind,
        sink_name=str(sink_name),
        sink_category=category,
        severity=severity,
        sink_site=sink_site,
        arg_expr="",
        param_type="string",
        source_marks=(mark,),
        exit_sites=("<llm-node>",) if kind == "implicit" else (),
        file=str(path),
        reachable=True,            # Pysa's own analysis handles reachability (§4.5(1))
        triage_rationale=message or None,
    )


# --------------------------------------------------------------------------- #
def findings_from_results(results: str, do_prune: bool = True,
                          triage: str = "mock", triage_model: Optional[str] = None,
                          implicit_only: bool = False) -> List[Finding]:
    """Public helper: Pysa results dir/file -> ctaudit Findings (the data-flow leg).

    Used by the standalone CLI (main) and by the hybrid driver, so both legs
    produce homogeneous ``Finding`` objects that can be merged.
    """
    doc = _load_json(results)
    issues = list(_iter_issues(doc))
    repo_root = _repo_root(results)
    models_paths: List[str] = []
    if repo_root:
        cfg = Path(repo_root) / ".pyre_configuration"
        if cfg.exists():
            try:
                tmp = json.loads(cfg.read_text()).get("taint_models_path", [])
                models_paths = [str(Path(repo_root) / m)
                                for m in (tmp if isinstance(tmp, list) else [tmp])]
            except Exception:
                pass
    llm_pats = _llm_node_patterns(models_paths)

    out: List[Finding] = []
    for issue in issues:
        f = _to_finding(issue, repo_root=repo_root, llm_pats=llm_pats)
        if f is None:
            continue
        if implicit_only and f.kind != "implicit":
            continue
        out.append(f)
    if do_prune:
        prune(out, PruneConfig())
    get_triager(triage, triage_model).triage(out, source=None)
    return out


# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="postprocess",
                                 description="Pysa -> ctaudit cross-tool findings")
    ap.add_argument("results", help="taint-output.json file, or the --save-results-to dir")
    ap.add_argument("--triage", choices=("mock", "anthropic"), default="mock")
    ap.add_argument("--triage-model", default=None)
    ap.add_argument("--no-prune", action="store_true")
    ap.add_argument("--show-pruned", action="store_true")
    ap.add_argument("--implicit-only", action="store_true",
                    help="drop explicit (verbatim) flows, keep only CWE-1426 implicit ones")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    doc = _load_json(args.results)
    issues = list(_iter_issues(doc))
    # taint-models path(s) from .pyre_configuration, for structural LLM-node detection
    repo_root = _repo_root(args.results)
    models_paths: List[str] = []
    if repo_root:
        cfg = Path(repo_root) / ".pyre_configuration"
        if cfg.exists():
            try:
                tmp = json.loads(cfg.read_text()).get("taint_models_path", [])
                models_paths = [str(Path(repo_root) / m) for m in (tmp if isinstance(tmp, list) else [tmp])]
            except Exception:
                pass
    llm_pats = _llm_node_patterns(models_paths)

    findings: List[Finding] = []
    for issue in issues:
        f = _to_finding(issue, repo_root=repo_root, llm_pats=llm_pats)
        if f is None:
            continue
        if args.implicit_only and f.kind != "implicit":
            continue
        findings.append(f)

    if not findings and not issues:
        top = list(doc.keys()) if isinstance(doc, dict) else f"list[{len(doc)}]"
        print(f"No Pysa issues found. Top-level JSON shape: {top}", file=sys.stderr)
        print("Adjust _iter_issues() to your pyre-check output schema.", file=sys.stderr)
        return 2

    if not findings:
        # diagnostics to pinpoint why nothing matched (codes / feature presence).
        def _d(i):
            return i.get("data") if isinstance(i.get("data"), dict) else i
        codes = sorted({_d(issue).get("code") for issue in issues if "code" in _d(issue)})
        feats: Set[str] = set()
        for issue in issues:
            _collect_feature_tokens(issue, feats)
        print(f"[diag] parsed {len(issues)} Pysa issue(s); codes seen: {codes or 'none'}; "
              f"features seen: {sorted(feats) or 'none'}", file=sys.stderr)
        if codes and not any(c in CODE_TO_CATEGORY for c in codes):
            print("[diag] none of those codes are ours (9001–9005): check taint.config rules "
                  "were loaded.", file=sys.stderr)
        elif "llm_node" not in feats:
            print("[diag] our code(s) present but no 'llm_node' feature: the flow is being "
                  "found as EXPLICIT. Re-run without --implicit-only, or ensure the LLM call is "
                  "modeled TaintInTaintOut[Via[llm_node]] and its body does not itself propagate "
                  "the prompt.", file=sys.stderr)

    if not args.no_prune:
        prune(findings, PruneConfig())
    triager = get_triager(args.triage, args.triage_model)
    triager.triage(findings, source=None)

    if args.json:
        print(json.dumps([{
            "kind": f.kind, "sink": f.sink_name, "category": f.sink_category,
            "severity": f.severity, "file": f.file, "site": f.sink_site,
            "pruned": f.pruned, "prune_reason": f.prune_reason,
            "triage": f.triage_verdict, "confidence": f.triage_confidence,
        } for f in findings], indent=2))
    else:
        print(render_findings(findings, show_pruned=args.show_pruned))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
