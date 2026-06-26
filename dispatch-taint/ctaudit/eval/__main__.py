"""CLI for the Stage-4 evaluation harness.

    python -m ctaudit.eval [--fixtures DIR] [--triage mock|anthropic] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys

from .harness import DEFAULT_FIXTURES, ablation, evaluate, format_report, framework_cost


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # --real-corpus is a mode switch: everything else is parsed by real_corpus.report
    if "--real-corpus" in argv:
        argv = [a for a in argv if a != "--real-corpus"]
        from .real_corpus import report
        return report(argv)

    ap = argparse.ArgumentParser(prog="ctaudit-eval",
                                 description="Stage-4 evaluation (§5, RQ1–RQ4)")
    ap.add_argument("--fixtures", default=str(DEFAULT_FIXTURES),
                    help="directory of labeled fixtures (default: bundled fixtures/)")
    ap.add_argument("--triage",
                    choices=("mock", "anthropic", "deepseek", "openai", "openai-compat"),
                    default="mock", help="triage backend for the triaged-stage metrics")
    ap.add_argument("--real-corpus", action="store_true",
                    help="real-repository mode (DVLA + AgentDojo×4); all other "
                         "options after it are passed to the real-corpus harness — "
                         "see docs/stage4_evaluation.md §8")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args(argv)

    overall, per_case = evaluate(args.fixtures, triage_backend=args.triage)
    abl = ablation(args.fixtures)
    costs = framework_cost(per_case)

    if args.json:
        out = {
            "stages": {
                name: {"tp": c.tp, "fp": c.fp, "fn": c.fn,
                       "precision": c.precision, "recall": c.recall, "f1": c.f1}
                for name, c in (("raw", overall.raw), ("pruned", overall.pruned),
                                ("triaged", overall.triaged))
            },
            "ablation": [
                {"prune": r.prune, "fp_removed": r.fp_removed, "tp_removed": r.tp_removed}
                for r in abl
            ],
            "framework_cost": [
                {"framework": fc.framework, "specs": fc.specs, "tools": fc.tools,
                 "entries": fc.entries, "bridges": fc.bridges, "exits": fc.exits,
                 "cases": fc.cases, "recall": fc.recall}
                for fc in costs
            ],
        }
        print(json.dumps(out, indent=2))
    else:
        print(format_report(overall, per_case, abl, costs, args.triage))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
