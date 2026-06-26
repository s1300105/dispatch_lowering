"""Measure the tool classifier against the hand-labelled gold (proposal RQ4).

    python -m benchmark.run_benchmark [--classifier heuristic|anthropic]

Reports, per repo and in aggregate (all repos, and held-out only): tool-level
precision/recall (did we recover the right tool set?), plus role / sink-category /
guard-presence accuracy on the matched tools. Empty-gold repos (chat / verbatim-exec)
contribute to precision only — they check that the classifier does not invent tools.

The point is to quantify generalisation: the heuristic was tuned on shellgpt +
termwise, so held-out numbers are the honest measure.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))                       # repo root (ctaudit importable)

from ctaudit.toolmodel import get_classifier                # noqa: E402
from benchmark.labels import (                              # noqa: E402
    CORPUS_BASE, GOLD, SYNTHETIC_DICT_REGISTRY, SYNTHETIC_GOLD,
)


def _norm(name: str) -> str:
    return name.strip().lower()


def _eval_one(detected_tools, gold_tools):
    """Return (tp, fp, fn, role_ok, role_tot, cat_ok, cat_tot, guard_ok, guard_tot, detail)."""
    det = {_norm(t.name): t for t in detected_tools}
    gold = {_norm(k): v for k, v in gold_tools.items()}
    tp = sorted(set(det) & set(gold))
    fp = sorted(set(det) - set(gold))
    fn = sorted(set(gold) - set(det))

    role_ok = role_tot = cat_ok = cat_tot = guard_ok = guard_tot = 0
    detail = []
    for name in tp:
        d, g = det[name], gold[name]
        d_roles = set(d.roles)
        g_roles = set(g["roles"])
        role_tot += 1
        rok = d_roles == g_roles
        role_ok += int(rok)
        cflag = gflag = None
        if "sink" in g_roles:
            cat_tot += 1
            d_cat = d.sink.category if d.sink else None
            cflag = (d_cat == g["category"])
            cat_ok += int(bool(cflag))
            guard_tot += 1
            d_guard = (d.sink.guard if d.sink else None)
            gflag = (bool(d_guard) == bool(g["guard"]))   # presence agreement
            guard_ok += int(gflag)
        detail.append((name, sorted(d_roles), sorted(g_roles), rok, cflag, gflag))
    return tp, fp, fn, role_ok, role_tot, cat_ok, cat_tot, guard_ok, guard_tot, detail


def _make_synthetic() -> str:
    # fixed basename so the replay transport can key on REPO: synthetic-dict
    d = Path(tempfile.mkdtemp(prefix="ctaudit_bench_")) / "synthetic-dict"
    d.mkdir(parents=True, exist_ok=True)
    for rel, body in SYNTHETIC_DICT_REGISTRY.items():
        (d / rel).write_text(body)
    return str(d)


def _pr(a):
    p = a["tp"] / (a["tp"] + a["fp"]) if (a["tp"] + a["fp"]) else float("nan")
    r = a["tp"] / (a["tp"] + a["fn"]) if (a["tp"] + a["fn"]) else float("nan")
    return p, r


def _one_pass(clf, items):
    """Run the classifier once over all items; return (rows, aggregate)."""
    rows = []   # (key, spec, gold_n, det_n, tp, fp, fn, ro, rt, co, ct, go, gt)
    agg = {s: dict(tp=0, fp=0, fn=0, ro=0, rt=0, co=0, ct=0, go=0, gt=0)
           for s in ("all", "held_out")}
    for key, path, src_root, spec in items:
        model = clf.classify(path, src_root=src_root)
        tp, fp, fn, ro, rt, co, ct, go, gt, _ = _eval_one(model.tools, spec["tools"])
        rows.append((key, spec, len(spec["tools"]), len(model.tools),
                     tp, fp, fn, ro, rt, co, ct, go, gt))
        for scope in (("all", "held_out") if not spec.get("tuning") else ("all",)):
            a = agg[scope]
            a["tp"] += len(tp); a["fp"] += len(fp); a["fn"] += len(fn)
            a["ro"] += ro; a["rt"] += rt; a["co"] += co; a["ct"] += ct
            a["go"] += go; a["gt"] += gt
    return rows, agg


def _fmt_dist(vals):
    import statistics
    vals = [v for v in vals if v == v]   # drop nan
    if not vals:
        return "n/a"
    if len(vals) == 1:
        return f"{vals[0]:.1f}%"
    return (f"{statistics.mean(vals):5.1f}% ± {statistics.pstdev(vals):4.1f} "
            f"[{min(vals):.0f}–{max(vals):.0f}]")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="benchmark.run_benchmark")
    ap.add_argument("--classifier", default="heuristic",
                    choices=["heuristic", "anthropic", "deepseek", "openai", "llm", "replay"])
    ap.add_argument("--fixtures", default=str(_HERE / "llm_fixtures"),
                    help="captured discovery JSONs for --classifier replay")
    ap.add_argument("--repeat", type=int, default=1,
                    help="run the classifier N times and report the distribution "
                         "(LLM output varies run-to-run even at temperature 0)")
    ap.add_argument("--no-ground", dest="ground", action="store_false",
                    help="disable the deterministic grounding post-filter (LLM backends)")
    ap.set_defaults(ground=True)
    args = ap.parse_args(argv)
    if args.classifier == "replay":
        clf = get_classifier("replay", fixtures=args.fixtures, ground=args.ground)
    else:
        clf = get_classifier(args.classifier, ground=args.ground)

    _KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY (+ pip install anthropic)",
                "llm": "ANTHROPIC_API_KEY (+ pip install anthropic)",
                "deepseek": "DEEPSEEK_API_KEY (+ pip install openai)",
                "openai": "OPENAI_API_KEY (+ pip install openai)"}
    if args.classifier in _KEY_ENV and getattr(clf, "_complete", None) is None:
        print("!! WARNING: --classifier", args.classifier,
              "requested but NO live LLM transport was created.")
        print(f"!! Set/install: {_KEY_ENV[args.classifier]}.")
        print("!! This run FALLS BACK TO THE HEURISTIC — the numbers below are NOT the LLM result.\n")

    items = []  # (key, path, src_root, spec)
    skipped = []
    for key, spec in GOLD.items():
        path = Path(CORPUS_BASE) / spec["rel"]
        if path.exists():
            items.append((key, str(path), str(Path(CORPUS_BASE) / spec["src_rel"]), spec))
        else:
            skipped.append(key)
    syn = _make_synthetic()
    items.append(("synthetic-dict", syn, syn, SYNTHETIC_GOLD))

    print(f"classifier = {args.classifier}   corpus base = {CORPUS_BASE}"
          + (f"   repeat = {args.repeat}" if args.repeat > 1 else ""))
    if skipped:
        print(f"skipped (path not found; set CTAUDIT_CORPUS_BASE): {', '.join(skipped)}")
    print()

    # -------- single run: the familiar table --------
    if args.repeat <= 1:
        rows, agg = _one_pass(clf, items)
        hdr = (f"{'repo':<16}{'idiom':<34}{'tune':<5}{'gold':>5}{'det':>5}"
               f"{'TP':>4}{'FP':>4}{'FN':>4}  recall")
        print(hdr); print("-" * len(hdr))
        missed, overincl = [], []
        for (key, spec, gold_n, det_n, tp, fp, fn, *_r) in rows:
            rec_s = f"{len(tp)/gold_n*100:5.0f}%" if gold_n else "   n/a"
            tune = "Y" if spec.get("tuning") else "-"
            print(f"{key:<16}{spec['idiom']:<34}{tune:<5}{gold_n:>5}{det_n:>5}"
                  f"{len(tp):>4}{len(fp):>4}{len(fn):>4}  {rec_s}")
            if fn:
                missed.append((key, fn))
            if fp:
                overincl.append((key, fp))
        print("\n=== aggregate (tool-level) ===")
        for scope in ("all", "held_out"):
            a = agg[scope]; p, r = _pr(a)
            role = f"{a['ro']}/{a['rt']}" if a["rt"] else "-"
            cat = f"{a['co']}/{a['ct']}" if a["ct"] else "-"
            guard = f"{a['go']}/{a['gt']}" if a["gt"] else "-"
            print(f"  {scope:<9} precision={p*100:5.1f}%  recall={r*100:5.1f}%  "
                  f"(TP={a['tp']} FP={a['fp']} FN={a['fn']})  "
                  f"role {role}, sink-cat {cat}, guard-presence {guard}")
        if missed:
            print("\n=== recall holes (gold tools the classifier missed) ===")
            for repo, fn in missed:
                print(f"  {repo}: {', '.join(fn)}")
        if overincl:
            print("\n=== over-enumeration (detected, NOT in gold = precision cost) ===")
            for repo, fp in overincl:
                print(f"  {repo}: {', '.join(fp)}")
        return 0

    # -------- N runs: distribution + stability (LLM non-determinism) --------
    from collections import Counter, defaultdict
    runs = [_one_pass(clf, items) for _ in range(args.repeat)]
    repo_recall = defaultdict(list)
    repo_fp_runs = Counter()
    fn_freq = defaultdict(Counter)
    fp_freq = defaultdict(Counter)
    for rows, _agg in runs:
        for (key, spec, gold_n, det_n, tp, fp, fn, *_r) in rows:
            if gold_n:
                repo_recall[key].append(len(tp) / gold_n * 100)
            if fp:
                repo_fp_runs[key] += 1
            for t in fn:
                fn_freq[key][t] += 1
            for t in fp:
                fp_freq[key][t] += 1

    N = args.repeat
    hdr = f"{'repo':<16}{'idiom':<34}  recall over N runs{'':<6}FP-runs"
    print(hdr); print("-" * len(hdr))
    for key, _path, _src, spec in items:
        rec = _fmt_dist(repo_recall.get(key, [])) if spec["tools"] else "n/a (empty gold)"
        print(f"{key:<16}{spec['idiom']:<34}  {rec:<24}{repo_fp_runs.get(key, 0)}/{N}")

    print(f"\n=== aggregate over {N} runs (mean ± popstdev [min–max]) ===")
    for scope in ("all", "held_out"):
        precs = [_pr(agg[scope])[0] * 100 for _r, agg in runs]
        recs = [_pr(agg[scope])[1] * 100 for _r, agg in runs]
        print(f"  {scope:<9} precision={_fmt_dist(precs):<26} recall={_fmt_dist(recs)}")
        roles = [100 * agg[scope]["ro"] / agg[scope]["rt"] for _r, agg in runs if agg[scope]["rt"]]
        cats = [100 * agg[scope]["co"] / agg[scope]["ct"] for _r, agg in runs if agg[scope]["ct"]]
        guards = [100 * agg[scope]["go"] / agg[scope]["gt"] for _r, agg in runs if agg[scope]["gt"]]
        print(f"  {'':<9} role={_fmt_dist(roles)}   sink-cat={_fmt_dist(cats)}   "
              f"guard-presence={_fmt_dist(guards)}")

    sometimes_missed = {(r, t): c for r, cnt in fn_freq.items() for t, c in cnt.items()}
    sometimes_over = {(r, t): c for r, cnt in fp_freq.items() for t, c in cnt.items()}
    if sometimes_missed:
        print("\n=== recall instability (gold tools missed in SOME runs) ===")
        for (r, t), c in sorted(sometimes_missed.items(), key=lambda kv: -kv[1]):
            print(f"  {r}:{t}  missed in {c}/{N} runs")
    if sometimes_over:
        print("\n=== precision instability (spurious tools in SOME runs) ===")
        for (r, t), c in sorted(sometimes_over.items(), key=lambda kv: -kv[1]):
            print(f"  {r}:{t}  over-included in {c}/{N} runs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
