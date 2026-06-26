"""Command-line interface: ``ctaudit <path> [options]``.

Walks a file or directory of Python sources, runs the two-layer taint engine,
prunes (§4.5), triages (§4.6), and prints a report.  Runnable as both
``ctaudit ...`` (console script) and ``python -m ctaudit.cli ...``.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from . import analyze_path
from .report import Finding


def _findings_to_dicts(findings: List[Finding], show_pruned: bool) -> list:
    out = []
    for f in findings:
        if f.pruned and not show_pruned:
            continue
        out.append({
            "kind": f.kind,
            "sink": f.sink_name,
            "category": f.sink_category,
            "severity": f.severity,
            "location": f"{f.file}:{f.sink_site}",
            "tainted_argument": f.arg_expr,
            "param_type": f.param_type,
            "guard": f.guard,
            "source_tools": list(f.source_tools),
            "frameworks": list(f.frameworks),
            "llm_nodes": list(f.exit_sites),
            "trace": f.trace(),
            "pruned": f.pruned,
            "prune_reason": f.prune_reason,
            "triage_verdict": f.triage_verdict,
            "triage_confidence": f.triage_confidence,
            "triage_rationale": f.triage_rationale,
        })
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ctaudit",
        description="Pre-deployment static audit for cross-tool implicit "
                    "(control-dependency) taint flows in LLM agents (CWE-1426).",
    )
    p.add_argument("path", help="Python file or directory to audit")
    p.add_argument("--no-triage", action="store_true",
                   help="skip the LLM-triage stage (§4.6)")
    p.add_argument("--triage", choices=["mock", "anthropic", "deepseek",
                                        "openai", "openai-compat"], default="mock",
                   help="triage backend (default: mock, offline & deterministic). "
                        "deepseek/openai/anthropic call the real LLM; set the matching "
                        "API-key env var (DEEPSEEK_API_KEY / OPENAI_API_KEY / "
                        "ANTHROPIC_API_KEY).")
    p.add_argument("--triage-model", default=None,
                   help="model name for --triage anthropic")
    p.add_argument("--no-prune", action="store_true",
                   help="skip candidate pruning (§4.5)")
    p.add_argument("--show-pruned", action="store_true",
                   help="include pruned candidates in the report")
    p.add_argument("--json", action="store_true",
                   help="emit findings as JSON")
    p.add_argument("--html", metavar="FILE", default=None,
                   help="also write a graphical HTML report (Mermaid path diagrams)")
    p.add_argument("--compare-pruning", action="store_true",
                   help="with --html, ALSO write a second report of the complete raw "
                        "candidate list (pruning AND triage disabled) to FILE with a "
                        "'_raw' suffix, for before/after comparison (§4.5 ablation)")
    p.add_argument("--inline-mermaid", metavar="JS", default=None,
                   help="path to mermaid.min.js to embed for a fully offline HTML report")
    p.add_argument("--fail-on-finding", action="store_true",
                   help="exit non-zero if any non-pruned finding remains (for CI)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    result = analyze_path(
        args.path,
        do_prune=not args.no_prune,
        do_triage=not args.no_triage,
        triage_backend=args.triage,
        triage_model=args.triage_model,
    )

    if args.json:
        print(json.dumps({
            "files_scanned": result.files_scanned,
            "raw_findings": len(result.findings),
            "kept_findings": len(result.kept),
            "errors": result.errors,
            "findings": _findings_to_dicts(result.findings, args.show_pruned),
        }, indent=2, ensure_ascii=False))
    else:
        print(result.render(show_pruned=args.show_pruned))
        print(f"\nscanned {result.files_scanned} file(s)")
        if result.errors:
            print(f"{len(result.errors)} file(s) skipped:")
            for e in result.errors:
                print(f"  ! {e}")

    if args.fail_on_finding and result.kept:
        return 1
    if args.html:
        import os
        from .render_html import write_report

        n_kept = len(result.kept)
        write_report(
            result.findings, args.html,
            title="Cross-Tool Audit Report",
            subtitle=f"{args.path}  ·  pruned + triaged  ·  "
                     f"{n_kept} kept of {len(result.findings)} raw "
                     f"·  {result.files_scanned} file(s)",
            include_pruned=args.show_pruned,
            inline_mermaid=args.inline_mermaid,
        )
        print(f"\nHTML report written to {args.html}")

        if args.compare_pruning:
            # complete RAW candidate list: pruning AND triage disabled (§4.5 ablation).
            raw = analyze_path(
                args.path, do_prune=False, do_triage=False,
            )
            n_raw = len(raw.findings)
            # display-only annotation pass: mark which candidates §4.5 pruning WOULD
            # remove (and why) so the raw report dims them with a reason, making the
            # before/after effect visible without changing the analysis.
            from .analysis.pruning import prune as _prune
            would_remove = 0
            try:
                _prune(raw.findings)
                would_remove = sum(1 for f in raw.findings if f.pruned)
            except Exception:
                pass
            import os
            base, ext = os.path.splitext(args.html)
            raw_path = f"{base}_raw{ext or '.html'}"
            removed = n_raw - n_kept
            pct = f"{removed / n_raw:.0%}" if n_raw else "0%"
            write_report(
                raw.findings, raw_path,
                title="Cross-Tool Audit Report — RAW (no pruning, no triage)",
                subtitle=f"{args.path}  ·  unfiltered candidates (dimmed = would be "
                         f"pruned)  ·  {n_raw} raw  →  {n_kept} after filtering "
                         f"(−{removed}, {pct} reduced)",
                include_pruned=True,
                inline_mermaid=args.inline_mermaid,
            )
            print(f"RAW comparison report written to {raw_path}")
            print(f"  pruning+triage reduced {n_raw} candidates to {n_kept} "
                  f"(−{removed}, {pct})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
