"""Stage-4 evaluation harness (§5, RQ1–RQ4).

Computes, against a labeled benchmark:

* **detection metrics** (precision / recall / F1) at three pipeline stages —
  *raw* (every candidate), *pruned* (after §4.5), *triaged* (kept ∧ triage says
  true-positive) — answering RQ1 (does it find the flows?) and showing what
  pruning + triage do to precision (RQ2/RQ3);
* **per-prune ablation** — turning each §4.5 prune off and measuring how many
  false positives it removes and, crucially, whether it ever removes a *true*
  positive (a soundness violation);
* **framework cost (RQ4)** — how many wiring specs each framework contributes and
  the recall on that framework's cases, as a portability proxy.

Run it with :mod:`ctaudit.eval.__main__` (``python -m ctaudit.eval``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .. import analyze_path, default_registry
from ..analysis.pruning import PruneConfig
from ..models.base import ModelRegistry
from ..report import Finding
from .labels import BENCHMARK, ExpectedFinding, LabeledCase

# fixtures live at the repo root in a source checkout: ctaudit/eval/harness.py
DEFAULT_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"

_PRUNES = ("selective_hiding", "reachability", "schema", "role")


# --------------------------------------------------------------------------- #
# metrics
# --------------------------------------------------------------------------- #
@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def add(self, other: "Counts") -> "Counts":
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn
        return self


def _matches(pred: Finding, exp: ExpectedFinding) -> bool:
    if pred.sink_name != exp.sink or pred.kind != exp.kind:
        return False
    if exp.line is not None:
        head = pred.sink_site.split(":")[0]
        return head.isdigit() and int(head) == exp.line
    return True


def _confusion(predictions: List[Finding], expected: Tuple[ExpectedFinding, ...]) -> Counts:
    """Match predictions against the expected *positives* (findings that should be
    reported).  An expected ``should_be_pruned`` finding is not a positive, so a
    prediction matching it still counts as a false positive."""
    positives = [e for e in expected if not e.should_be_pruned]
    matched: set = set()
    tp = fp = 0
    for pred in predictions:
        hit = None
        for i, e in enumerate(positives):
            if i in matched:
                continue
            if _matches(pred, e):
                hit = i
                break
        if hit is None:
            fp += 1
        else:
            matched.add(hit)
            tp += 1
    fn = len(positives) - len(matched)
    return Counts(tp, fp, fn)


# --------------------------------------------------------------------------- #
# pipeline stages
# --------------------------------------------------------------------------- #
def _analyze(path: str, *, do_prune: bool, do_triage: bool,
             prune_config: Optional[PruneConfig] = None,
             triage_backend: str = "mock",
             registry: Optional[ModelRegistry] = None) -> List[Finding]:
    res = analyze_path(path, registry=registry, do_prune=do_prune,
                       prune_config=prune_config, do_triage=do_triage,
                       triage_backend=triage_backend)
    return list(res.findings)


def _kept(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if not f.pruned]


def _key(f: Finding) -> Tuple[str, str, str]:
    return (f.file, f.sink_site, f.kind)


@dataclass
class StageMetrics:
    raw: Counts = field(default_factory=Counts)
    pruned: Counts = field(default_factory=Counts)
    triaged: Counts = field(default_factory=Counts)


@dataclass
class CaseResult:
    case: LabeledCase
    raw: Counts
    pruned: Counts
    triaged: Counts


def evaluate(fixtures_dir: os.PathLike | str = DEFAULT_FIXTURES,
             benchmark: Tuple[LabeledCase, ...] = BENCHMARK,
             triage_backend: str = "mock") -> Tuple[StageMetrics, List[CaseResult]]:
    fixtures = Path(fixtures_dir)
    overall = StageMetrics()
    per_case: List[CaseResult] = []
    for case in benchmark:
        path = str(fixtures / case.filename)
        raw = _analyze(path, do_prune=False, do_triage=False)
        pruned_all = _analyze(path, do_prune=True, do_triage=False)
        triaged_all = _analyze(path, do_prune=True, do_triage=True,
                               triage_backend=triage_backend)

        c_raw = _confusion(raw, case.expected)
        c_pruned = _confusion(_kept(pruned_all), case.expected)
        kept_true = [f for f in _kept(triaged_all) if f.triage_verdict == "true-positive"]
        c_triaged = _confusion(kept_true, case.expected)

        overall.raw.add(c_raw)
        overall.pruned.add(c_pruned)
        overall.triaged.add(c_triaged)
        per_case.append(CaseResult(case, c_raw, c_pruned, c_triaged))
    return overall, per_case


# --------------------------------------------------------------------------- #
# per-prune ablation
# --------------------------------------------------------------------------- #
@dataclass
class AblationRow:
    prune: str
    fp_removed: int = 0   # candidates this prune correctly removes (not ground-truth positives)
    tp_removed: int = 0   # ground-truth positives this prune wrongly removes (UNSOUND if > 0)


def ablation(fixtures_dir: os.PathLike | str = DEFAULT_FIXTURES,
             benchmark: Tuple[LabeledCase, ...] = BENCHMARK) -> List[AblationRow]:
    fixtures = Path(fixtures_dir)
    rows = {p: AblationRow(p) for p in _PRUNES}
    for case in benchmark:
        path = str(fixtures / case.filename)
        positives = tuple(e for e in case.expected if not e.should_be_pruned)
        base_kept = {_key(f): f for f in _kept(_analyze(path, do_prune=True, do_triage=False))}
        for p in _PRUNES:
            cfg = PruneConfig(**{p: False})
            off_kept = _kept(_analyze(path, do_prune=True, do_triage=False, prune_config=cfg))
            for f in off_kept:
                if _key(f) in base_kept:
                    continue  # not removed by enabling this prune
                # f is present with the prune OFF but gone with it ON -> removed by it.
                if any(_matches(f, e) for e in positives):
                    rows[p].tp_removed += 1
                else:
                    rows[p].fp_removed += 1
    return [rows[p] for p in _PRUNES]


# --------------------------------------------------------------------------- #
# RQ4 — framework cost / portability
# --------------------------------------------------------------------------- #
@dataclass
class FrameworkCost:
    framework: str
    tools: int = 0
    entries: int = 0
    bridges: int = 0
    exits: int = 0
    cases: int = 0
    recall: float = 1.0

    @property
    def specs(self) -> int:
        return self.tools + self.entries + self.bridges + self.exits


def framework_cost(per_case: List[CaseResult],
                   registry: Optional[ModelRegistry] = None) -> List[FrameworkCost]:
    reg = registry or default_registry()
    fw: Dict[str, FrameworkCost] = {}

    def slot(name: str) -> FrameworkCost:
        return fw.setdefault(name, FrameworkCost(name))

    for t in reg.tools:
        slot(t.framework).tools += 1
    for e in reg.entries:
        slot(e.framework).entries += 1
    for b in reg.bridges:
        slot(b.framework).bridges += 1
    for x in reg.exits:
        slot(x.framework).exits += 1

    # attach recall per framework from the per-case pruned-stage counts.
    by_fw: Dict[str, Counts] = {}
    case_counts: Dict[str, int] = {}
    for cr in per_case:
        c = by_fw.setdefault(cr.case.framework, Counts())
        c.add(Counts(cr.pruned.tp, 0, cr.pruned.fn))
        case_counts[cr.case.framework] = case_counts.get(cr.case.framework, 0) + 1
    for name, c in by_fw.items():
        slot(name).recall = c.recall
    for name, n in case_counts.items():
        slot(name).cases = n
    # ensure frameworks that have cases but were not counted above still appear
    for cr in per_case:
        slot(cr.case.framework)

    return [fw[k] for k in sorted(fw)]


# --------------------------------------------------------------------------- #
# report rendering
# --------------------------------------------------------------------------- #
def _pct(x: float) -> str:
    return f"{100 * x:5.1f}%"


def format_report(overall: StageMetrics, per_case: List[CaseResult],
                  abl: List[AblationRow], costs: List[FrameworkCost],
                  triage_backend: str) -> str:
    L: List[str] = []
    L.append("=" * 74)
    L.append("ctaudit — Stage 4 evaluation (§5, RQ1–RQ4)")
    L.append("=" * 74)
    L.append("NOTE: the bundled benchmark is self-authored; perfect scores here are")
    L.append("      expected and circular. Swap BENCHMARK / --fixtures for a real,")
    L.append("      independently-labeled corpus to get meaningful numbers.")
    L.append(f"      triage backend: {triage_backend}")
    L.append("")

    L.append("RQ1/RQ2/RQ3 — detection metrics by pipeline stage")
    L.append("-" * 74)
    L.append(f"  {'stage':<10} {'TP':>4} {'FP':>4} {'FN':>4}   {'precision':>9} {'recall':>9} {'F1':>9}")
    for name, c in (("raw", overall.raw), ("pruned", overall.pruned), ("triaged", overall.triaged)):
        L.append(f"  {name:<10} {c.tp:>4} {c.fp:>4} {c.fn:>4}   "
                 f"{_pct(c.precision):>9} {_pct(c.recall):>9} {_pct(c.f1):>9}")
    L.append("  (raw = every candidate; pruned = after §4.5; triaged = kept ∧ true-positive)")
    L.append("")

    L.append("per-case (pruned stage)")
    L.append("-" * 74)
    for cr in per_case:
        c = cr.pruned
        status = "ok" if (c.fp == 0 and c.fn == 0) else "MISS"
        L.append(f"  [{status:>4}] {cr.case.filename:<30} "
                 f"TP={c.tp} FP={c.fp} FN={c.fn}   ({cr.case.note})")
    L.append("")

    L.append("RQ2/RQ3 — per-prune ablation (contribution; soundness)")
    L.append("-" * 74)
    L.append(f"  {'prune':<18} {'FP removed':>11} {'TP removed':>11}   soundness")
    for r in abl:
        sound = "OK" if r.tp_removed == 0 else "UNSOUND (removed a true positive!)"
        L.append(f"  {r.prune:<18} {r.fp_removed:>11} {r.tp_removed:>11}   {sound}")
    L.append("  (role is policy-driven: 0 here because no RolePolicy is supplied;")
    L.append("   selective_hiding is 0 because the LLM-join already drops hidden marks.)")
    L.append("")

    L.append("RQ4 — framework cost / portability")
    L.append("-" * 74)
    L.append(f"  {'framework':<16} {'tools':>5} {'entry':>5} {'bridge':>6} {'exit':>5} {'specs':>6} {'cases':>5} {'recall':>8}")
    for fc in costs:
        L.append(f"  {fc.framework:<16} {fc.tools:>5} {fc.entries:>5} {fc.bridges:>6} "
                 f"{fc.exits:>5} {fc.specs:>6} {fc.cases:>5} {_pct(fc.recall):>8}")
    L.append("  (specs = wiring rows to add a framework; a portability proxy for RQ4.)")
    L.append("=" * 74)
    return "\n".join(L)


def run_report(fixtures_dir: os.PathLike | str = DEFAULT_FIXTURES,
               benchmark: Tuple[LabeledCase, ...] = BENCHMARK,
               triage_backend: str = "mock") -> str:
    overall, per_case = evaluate(fixtures_dir, benchmark, triage_backend)
    abl = ablation(fixtures_dir, benchmark)
    costs = framework_cost(per_case)
    return format_report(overall, per_case, abl, costs, triage_backend)
