#!/usr/bin/env python3
"""Run all four AgentDojo suite runtimes individually and emit a combined,
per-suite + aggregate view of dispatch resolution scored against AgentDojo's
own injection_vectors.yaml (external ground truth; no manual labels).

Each suite is analysed ALONE (a directory analysis would collapse the four
identical FunctionsRuntime registries into one and destroy the suite
boundaries), then per-stage HTML reports are written per suite and the metrics
are summed for an aggregate line.

Usage:
    python agentdojo_all_suites.py [--triage mock|deepseek|anthropic]
                                   [--out-dir DIR] [--inline-mermaid JS]
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import hybrid  # noqa: E402
from ctaudit.render_html import write_report  # noqa: E402

SUITES = ("banking", "workspace", "travel", "slack")
STAGES = (
    ("stage1_classical", "Stage 1 — CLASSICAL (walls unresolved)"),
    ("stage2_resolved", "Stage 2 — resolution only"),
    ("stage3_pruned", "Stage 3 — + pruning §4.5"),
    ("stage4_final", "Stage 4 — + LLM triage §4.6"),
)


def _stage_findings(target, triage, stage, classifier="heuristic", expand=True):
    """Build the finding set for one stage of one suite."""
    if stage == "stage1_classical":
        return hybrid._classical_view(target, triage, True)
    if stage == "stage2_resolved":
        return hybrid.run(target, None, triage, classifier=classifier, resolve=True,
                          agentdojo=True, do_prune=False, do_triage=False,
                          expand_sources=expand)
    if stage == "stage3_pruned":
        return hybrid.run(target, None, triage, classifier=classifier, resolve=True,
                          agentdojo=True, do_prune=True, do_triage=False,
                          expand_sources=expand)
    # stage4_final
    fs = hybrid.run(target, None, triage, classifier=classifier, resolve=True,
                    agentdojo=True, do_prune=True, do_triage=True,
                    expand_sources=expand)
    for f in fs:
        if not f.pruned and f.triage_verdict == "false-positive":
            f.pruned = True
            f.prune_reason = "LLM triage: false-positive"
    return fs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--triage", default="mock",
                    choices=("mock", "anthropic", "deepseek", "openai", "openai-compat"),
                    help="triage backend (§4.6 precision filter)")
    ap.add_argument("--classifier", default="heuristic",
                    choices=("heuristic", "anthropic", "deepseek", "openai"),
                    help="dispatch-resolution classifier (fusion#4); heuristic is "
                         "offline and resolves the AgentDojo run_function wall fine, "
                         "but deepseek/anthropic can be used for parity with the triage LLM")
    ap.add_argument("--out-dir", default="agentdojo_suite_reports")
    ap.add_argument("--fixture-kind", choices=("full", "runtime"), default="full",
                    help="'full' = agentdojo_<suite>_full.py (all tools; over-flags "
                         "appear so pruning/triage have something to filter); "
                         "'runtime' = the reduced agentdojo_<suite>_runtime.py demo")
    ap.add_argument("--inline-mermaid", default=None)
    args = ap.parse_args(argv)

    expand = (args.fixture_kind == "full")
    os.makedirs(args.out_dir, exist_ok=True)

    # totals[stage] = {tp,fp,fn,tn}; combined[stage] = merged findings across suites
    totals = {sk: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for sk, _ in STAGES}
    combined = {sk: [] for sk, _ in STAGES}
    per_suite_lines = []

    for suite in SUITES:
        target = str(ROOT / "fixtures" / f"agentdojo_{suite}_{args.fixture_kind}.py")
        if not os.path.exists(target):
            print(f"  ! missing fixture for {suite}: {target}")
            continue
        suite_metrics = {}
        for stage_key, stage_title in STAGES:
            fs = _stage_findings(target, args.triage, stage_key, args.classifier, expand)
            combined[stage_key].extend(fs)
            m = hybrid._vector_metrics_agentdojo(fs, suite) or \
                {"tp": 0, "fp": 0, "fn": 0, "precision": 1.0, "recall": 0.0, "f1": 0.0,
                 "note": "no vectors"}
            suite_metrics[stage_key] = m
            for k in ("tp", "fp", "fn", "tn"):
                totals[stage_key][k] += m.get(k, 0)
            path = os.path.join(args.out_dir, f"{suite}_{stage_key}.html")
            write_report(fs, path,
                         title=f"AgentDojo {suite} — {stage_title}",
                         subtitle=f"agentdojo_{suite}_{args.fixture_kind}.py · scored vs "
                                  f"injection_vectors.yaml ({suite})",
                         include_pruned=True, metrics=m,
                         inline_mermaid=args.inline_mermaid)
        # show the full per-stage precision/recall progression for this suite
        prog = "  ".join(
            f"{sk.split('_')[0]}:P{suite_metrics[sk]['precision']:.0%}/"
            f"R{suite_metrics[sk]['recall']:.0%}"
            for sk, _ in STAGES)
        per_suite_lines.append(f"  {suite:10} {prog}")

    # INTEGRATED reports: one per stage merging all four suites, scored against
    # the union of every suite's injection vectors. This is the combined view.
    all_suites = list(SUITES)
    for stage_key, stage_title in STAGES:
        fs = combined[stage_key]
        if not fs:
            continue
        m = hybrid._vector_metrics_agentdojo(fs, all_suites) or \
            {"tp": 0, "fp": 0, "fn": 0, "precision": 1.0, "recall": 0.0, "f1": 0.0}
        path = os.path.join(args.out_dir, f"ALL_{stage_key}.html")
        write_report(fs, path,
                     title=f"AgentDojo ALL SUITES — {stage_title}",
                     subtitle=f"banking+workspace+travel+slack combined · scored vs "
                              f"injection_vectors.yaml (all suites)",
                     include_pruned=True, metrics=m,
                     inline_mermaid=args.inline_mermaid)

    def _pr(d):
        tp, fp, fn = d["tp"], d["fp"], d["fn"]
        p = tp / (tp + fp) if (tp + fp) else 1.0
        r = tp / (tp + fn) if (tp + fn) else (1.0 if tp else 0.0)
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        return p, r, f1

    print(f"\nAgentDojo dispatch-resolution across all suites "
          f"(triage={args.triage}, fixtures={args.fixture_kind}), "
          f"reports in {args.out_dir}/:\n")
    print("per suite (P/R per stage vs injection_vectors):")
    print("\n".join(per_suite_lines))
    print("\naggregate (all 4 suites summed; also written as ALL_stage*.html):")
    for stage_key, stage_title in STAGES:
        p, r, f1 = _pr(totals[stage_key])
        d = totals[stage_key]
        total = d['tp'] + d['fp'] + d['fn'] + d['tn']
        print(f"  {stage_title:34} P={p:.0%} R={r:.0%} F1={f1:.2f}  "
              f"(TP={d['tp']} FP={d['fp']} FN={d['fn']} TN={d['tn']} | Σ={total})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
