"""Comparison runner against TaintP2X on the multi-tool-agent CVE subset.

For each in-scope CVE whose repository is checked out locally, this:
  1. builds the tool model (heuristic by default; --classifier deepseek to use the LLM),
  2. runs ctaudit's flow pipeline (dataflow leg + §4.5 pruning + dispatch resolution),
  3. checks whether a reported flow matches the CVE's sink category -> DETECTED, and
  4. prints a comparison table (ctaudit vs TaintP2X) and two recall figures:
       - recall on the in-scope subset that is present locally, and
       - recall on the {in-scope AND TaintP2X-missed} cases (the complementary-value claim).

This measures *flow detection on the regime ctaudit targets*; it is not a claim over all 35
TaintP2X vulnerabilities. Single-hop cases are out of scope and are not run.

USAGE (on a machine with the repos checked out, see scripts/fetch_cve_corpus.sh):
    python -m benchmark.cve_bench --corpus ./cve_corpus
    python -m benchmark.cve_bench --corpus ./cve_corpus --classifier deepseek
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import List, Optional

from ctaudit import analyze_path
from ctaudit.analysis import resolve_dispatch
from ctaudit.toolmodel.classify import get_classifier
from ctaudit.toolmodel.schema import RepoToolModel

from benchmark.cve_cases import ALL_CASES, IN_SCOPE, CVECase
from benchmark.flow_bench import Flow, _norm_cat


def flows_and_walls(repo: str, src_root: Optional[str], classifier: str,
                    model: Optional[RepoToolModel] = None):
    """Return (concrete flows, #unresolved dispatch walls) for a repo path."""
    target = src_root or repo
    findings = [f for f in analyze_path(target, do_triage=False).findings
                if not getattr(f, "pruned", False)]
    mdl = model or get_classifier(classifier).classify(repo, src_root)
    flows: List[Flow] = []
    walls = 0
    for f in resolve_dispatch(findings, mdl, repo=target):
        if f.kind == "dispatch":
            walls += 1                      # control-tainted dispatch we could not resolve
            continue
        flows.append(Flow(f.kind, f.sink_name, _norm_cat(f.sink_category), f.guard is not None))
    return flows, walls


def run_case(case: CVECase, repo: str, src_root: Optional[str] = None,
             classifier: str = "heuristic", model: Optional[RepoToolModel] = None) -> dict:
    flows, walls = flows_and_walls(repo, src_root, classifier, model)
    hit = [f for f in flows if f.category == case.sink_category]
    if hit:
        verdict = "DETECTED"
    elif walls and case.scope == "dynamic_dispatch":
        verdict = "DISPATCH?"               # unresolved control-tainted wall (weak positive)
    else:
        verdict = "missed"
    return {"verdict": verdict, "n_flows": len(flows), "walls": walls,
            "hit_categories": sorted({f.category for f in hit}),
            "guarded": any(f.guarded for f in hit)}


def evaluate(corpus: str, classifier: str = "heuristic", cases=None) -> dict:
    cases = cases or IN_SCOPE
    rows = []
    present = detected = 0
    missed_present = missed_detected = 0     # TaintP2X-missed AND in-scope
    for case in cases:
        repo_root = Path(corpus) / case.repo.split("/")[-1]
        analyse = repo_root / case.src_rel if case.src_rel else repo_root
        if not analyse.exists():
            rows.append({"case": case, "status": "absent", "res": None})
            continue
        present += 1
        res = run_case(case, str(repo_root),
                       str(analyse) if case.src_rel else None, classifier)
        rows.append({"case": case, "status": "ran", "res": res})
        if res["verdict"] == "DETECTED":
            detected += 1
        if case.taintp2x == "N":
            missed_present += 1
            if res["verdict"] == "DETECTED":
                missed_detected += 1
    return {"rows": rows, "present": present, "detected": detected,
            "missed_present": missed_present, "missed_detected": missed_detected}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Compare ctaudit to TaintP2X on the agent CVE subset.")
    ap.add_argument("--corpus", default="./cve_corpus",
                    help="directory containing checked-out repos (see fetch_cve_corpus.sh)")
    ap.add_argument("--classifier", default="heuristic",
                    choices=["heuristic", "deepseek", "openai", "anthropic"])
    args = ap.parse_args(argv)

    r = evaluate(args.corpus, args.classifier)
    print(f"CVE comparison vs TaintP2X — in-scope (multi-tool agent / dynamic dispatch)\n"
          f"corpus={args.corpus}  classifier={args.classifier}\n")
    print(f"{'CVE':22} {'repo':28} {'cat':14} {'scope':16} {'ctaudit':10} {'TaintP2X'}")
    for row in r["rows"]:
        c = row["case"]
        repo = c.repo.split('/')[-1]
        if row["status"] == "absent":
            print(f"{c.cve:22} {repo:28} {c.sink_category:14} {c.scope:16} {'(absent)':10} {c.taintp2x}")
            continue
        res = row["res"]
        tag = res["verdict"]
        if tag == "DETECTED" and res["guarded"]:
            tag = "DETECT(G)"
        print(f"{c.cve:22} {repo:28} {c.sink_category:14} {c.scope:16} {tag:10} {c.taintp2x}"
              f"    [flows={res['n_flows']} walls={res['walls']}]")
    rec = r["detected"] / r["present"] if r["present"] else 0.0
    print(f"\nin-scope present : {r['present']}    ctaudit detected : {r['detected']}"
          f"    recall = {rec:.2f}")
    if r["missed_present"]:
        print(f"of which TaintP2X MISSED (N): {r['missed_present']} present, "
              f"ctaudit detected {r['missed_detected']}  <- complementary-value claim")
    print("\nNote: DETECT(G)=detected but guarded; DISPATCH?=unresolved control-tainted dispatch "
          "wall (weak positive, inspect). Single-hop CVEs are out of scope and not run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
