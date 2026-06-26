"""`ctaudit-annotate` — build label sheets and compute inter-annotator agreement.

Workflow for the external-validity (independent-annotation) study:

  1. ctaudit-annotate emit  --repo codecli --sample 40 --seed 0 --out codecli.blank.csv
     -> hand codecli.blank.csv to a 2nd annotator (blind: no gold, no model output).
  2. ctaudit-annotate gold  --repo codecli --sample 40 --seed 0 --out codecli.gold.csv
     -> annotator #1, auto-derived from benchmark.labels.GOLD (same sample/seed = aligned).
  3. (annotator #2 fills codecli.blank.csv -> codecli.annot2.csv)
  4. ctaudit-annotate kappa --a codecli.gold.csv --b codecli.annot2.csv
     -> Cohen's kappa per dimension (tool-ness, role, sink-category, guard).

  Optional: ctaudit-annotate model --repo codecli --classifier heuristic ... for
  annotator-vs-tool agreement, and  coverage --repo codecli  to confirm every gold tool
  maps to a candidate (so the GOLD sheet is faithful).
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional, Tuple

from .labels import CORPUS_BASE, GOLD
from . import annotation as A


def _resolve_repo(arg: str) -> Tuple[str, Optional[str], Optional[str]]:
    """GOLD key -> (repo_path, repo-relative src_rel, repo_key); raw path -> (path, None, None)."""
    if arg in GOLD:
        spec = GOLD[arg]
        repo = str(Path(CORPUS_BASE) / spec["rel"])
        src = spec.get("src_rel", spec["rel"])
        if src == spec["rel"]:
            src_rel = None
        elif src.startswith(spec["rel"] + "/"):
            src_rel = src[len(spec["rel"]) + 1:]
        else:
            src_rel = src
        return repo, src_rel, arg
    return arg, None, None


def _add_pool_opts(p):
    p.add_argument("--repo", required=True, help="GOLD key (e.g. codecli) or a repo path")
    p.add_argument("--src-rel", default=None, help="source subdir relative to repo (raw paths)")
    p.add_argument("--sample", type=int, default=None, help="label only N candidates (gold tools always kept)")
    p.add_argument("--seed", type=int, default=0, help="sampling seed (use the SAME across emit/gold/model)")
    p.add_argument("--out", required=True, help="output CSV path")


def _src_rel(args, derived):
    return args.src_rel if args.src_rel is not None else derived


def _fmt(k):
    return f"kappa={k['kappa']:.3f}  po={k['po']:.3f}  n={k['n']}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ctaudit-annotate",
                                 description="label sheets + inter-annotator Cohen's kappa")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("emit", help="blank sheet for an independent 2nd annotator")
    _add_pool_opts(pe)

    pg = sub.add_parser("gold", help="annotator #1 sheet auto-derived from GOLD")
    _add_pool_opts(pg)

    pm = sub.add_parser("model", help="sheet derived from a classifier (annotator-vs-tool)")
    _add_pool_opts(pm)
    pm.add_argument("--classifier", default="heuristic",
                    choices=("heuristic", "anthropic", "deepseek", "openai"))

    pk = sub.add_parser("kappa", help="agreement report between two filled sheets")
    pk.add_argument("--a", required=True)
    pk.add_argument("--b", required=True)

    pc = sub.add_parser("coverage", help="which gold tools map to a candidate")
    pc.add_argument("--repo", required=True)

    args = ap.parse_args(argv)

    if args.cmd == "coverage":
        repo, src_rel, key = _resolve_repo(args.repo)
        if key is None:
            print("coverage needs a GOLD key (e.g. codecli)"); return 2
        cov = A.coverage_check(repo, src_rel, key)
        print(f"{key}: matched {len(cov['matched'])}/{len(cov['matched']) + len(cov['missing'])} gold tools")
        if cov["matched"]:
            print("  matched:", ", ".join(cov["matched"]))
        if cov["missing"]:
            print("  MISSING (GOLD sheet will mislabel these):", ", ".join(cov["missing"]))
        return 0

    if args.cmd == "kappa":
        rep = A.agreement_report(A.read_csv(args.a), A.read_csv(args.b))
        print(f"matched={rep['n_matched']}  only_a={rep['n_only_a']}  only_b={rep['n_only_b']}\n")
        print(f"is_tool        : {_fmt(rep['is_tool'])}")
        for dim in ("role", "sink_category", "guarded"):
            print(f"{dim:14s} : {_fmt(rep[dim])}   | tools-only: {_fmt(rep[dim + '_tools_only'])}")
        return 0

    # emit / gold / model -> write a sheet
    repo, derived_src, key = _resolve_repo(args.repo)
    src_rel = _src_rel(args, derived_src)
    model = None
    if args.cmd == "model":
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from ctaudit.toolmodel import get_classifier
        src_root = str(Path(repo) / src_rel) if src_rel else repo
        model = get_classifier(args.classifier).classify(repo, src_root=src_root)
    if args.cmd == "gold" and key is None:
        print("gold needs a GOLD key (e.g. codecli)"); return 2

    rows = A.build_sheet(repo, src_rel, args.cmd, repo_key=key, model=model,
                         sample=args.sample, seed=args.seed)
    A.write_csv(rows, args.out)
    n_pos = sum(1 for r in rows if (r.get("is_tool") or "").strip().upper() == "Y")
    extra = f" ({n_pos} tool-positive)" if args.cmd in ("gold", "model") else ""
    print(f"wrote {len(rows)} candidate rows{extra} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
