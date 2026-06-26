#!/usr/bin/env python3
"""ctaudit hybrid driver — one report from two complementary legs.

A real agent repo needs BOTH static legs at once (proposal §6.1 (a)+(b)):

  * Pysa data-flow leg (`pysa/postprocess.py`): sound inter-procedural +
    recursion value flow (source -> history -> LLM node -> response -> args).
    BLIND SPOT: it cannot resolve a model-chosen *dynamic registry dispatch*
    (`get_function(name)(...)` to a dict-lookup or @classmethod tool), so it
    cannot reach a sink that sits behind such a dispatch.

  * Standalone enumeration leg (`ctaudit`, §4.2 join@LLM + §4.5 + part-B dynamic
    dispatch recognition): flags the model-controlled routing at the dispatch
    site. BLIND SPOT: it is intra-procedural (no cross-method / recursion).

Neither leg alone covers a framework-factored repo; together they do. Both legs
emit homogeneous ``ctaudit.report.Finding`` objects, so this driver just runs
both, tags provenance, de-duplicates, and renders one report.

Usage:
    python hybrid.py <target_dir> [--pysa-results <dir>] [--triage mock]
                     [--classifier heuristic|deepseek|anthropic] [--no-resolve]

With ``--classifier``, fusion #4 resolves each dynamic-dispatch wall in the enumeration
leg to concrete, registry-narrowed sink tools from the shared #5 tool model (recall-first:
an unmatched wall is kept). ``--classifier deepseek`` discovers sinks an idiom-specific
heuristic misses (e.g. a ``@classmethod`` tool behind a registry).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "pysa"))

# AgentDojo external ground truth (injection_vectors) lives here
ROOT_CORPUS = Path(__file__).resolve().parent / "corpus" / "agentdojo"

from ctaudit import analyze_path                       # noqa: E402
from ctaudit.report import Finding                     # noqa: E402
from ctaudit.labels import SourceMark                   # noqa: E402
from ctaudit.analysis import resolve_dispatch          # noqa: E402  (fusion #4)
from ctaudit.toolmodel import get_classifier           # noqa: E402  (shared #5 model)
from ctaudit.triage import get_triager                 # noqa: E402
import postprocess                                      # noqa: E402  (pysa/postprocess.py)


import copy as _copy                                     # noqa: E402


def _key(f: Finding) -> Tuple[str, str, str, str]:
    # include the (first) source tool so source-expanded AgentDojo findings —
    # same sink, different candidate source — are not collapsed by dedup.
    src = f.source_tools[0] if f.source_tools else ""
    return (os.path.basename(f.file or ""), str(f.sink_site), f.sink_category, src)


def _gt_metrics(findings: List[Finding]) -> Optional[dict]:
    """Score `findings` (the KEPT, non-pruned ones) against the bundled
    ground-truth BENCHMARK, returning a dict for render_html's metrics banner.

    Matching reuses the eval harness's own rule (basename + sink + kind). Only
    fixtures that appear in the benchmark contribute to the counts; if none of
    the analysed files are labelled, returns None (no banner)."""
    try:
        from ctaudit.eval.labels import BENCHMARK, ExpectedFinding
        from ctaudit.eval.harness import _confusion
    except Exception:
        return None

    kept = [f for f in findings if not f.pruned]
    # group predictions by fixture basename
    by_file: Dict[str, List[Finding]] = {}
    for f in kept:
        by_file.setdefault(os.path.basename(f.file or ""), []).append(f)

    tp = fp = fn = 0
    labelled = 0
    for case in BENCHMARK:
        if case.filename not in by_file and not case.expected:
            continue
        preds = by_file.get(case.filename, [])
        # only count files we actually analysed (present in by_file) OR that have
        # expected positives (so a missed file shows as FN)
        if case.filename not in by_file and not any(
                not e.should_be_pruned for e in case.expected):
            continue
        labelled += 1
        c = _confusion(preds, case.expected)
        tp += c.tp; fp += c.fp; fn += c.fn

    if labelled == 0:
        return None
    p = tp / (tp + fp) if (tp + fp) else 1.0
    r = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1,
            "note": f"scored against {labelled} labelled fixture(s) in the bundled "
                    f"benchmark; counts cover only labelled files"}


def _stage_counts(findings: List[Finding]) -> dict:
    """Ground-truth-independent tallies for a stage: how many candidates are
    kept vs removed (and why), across ALL analysed files (not just labelled
    ones). Complements _gt_metrics, which only covers benchmark fixtures."""
    total = len(findings)
    kept = sum(1 for f in findings if not f.pruned)
    pruned = sum(1 for f in findings if f.pruned and "LLM triage" not in (f.prune_reason or ""))
    triaged_out = sum(1 for f in findings if f.pruned and "LLM triage" in (f.prune_reason or ""))
    walls = sum(1 for f in findings if f.kind == "dispatch" and not f.via_dispatch)
    return {"total": total, "kept": kept, "pruned": pruned,
            "triaged_out": triaged_out, "walls": walls}


def _vector_metrics_agentdojo(findings: List[Finding], suites) -> Optional[dict]:
    """Score AgentDojo findings against AgentDojo's OWN injection_vectors.yaml
    (external ground truth; no manual labels).

    `suites` is a suite name or an iterable of suite names; the union of their
    injection vectors is used (so a directory of several suite runtimes can be
    scored together).

    A resolved dispatch finding carries the wall's candidate set in
    ``framework_candidates``; a finding is judged a TRUE POSITIVE when a real
    injection vector is reachable as the source (the source tool itself, or — for
    a resolved registry wall whose source is the abstract ``<agentdojo-tools>``
    placeholder — a vector appears in the candidate set). An UNRESOLVED dispatch
    wall counts as a false negative (the dangerous sink is not yet surfaced)."""
    if isinstance(suites, str):
        suites = (suites,)
    try:
        import sys as _sys
        corpus = ROOT_CORPUS
        if str(corpus) not in _sys.path:
            _sys.path.insert(0, str(corpus))
        from injection_ground_truth import INJECTION_VECTORS  # type: ignore
    except Exception:
        return None
    vecs = set()
    used = []
    for s in suites:
        v = INJECTION_VECTORS.get(s)
        if v:
            vecs |= v
            used.append(s)
    if not vecs:
        return None

    # suite source/sink registries — used to expand an UNRESOLVED wall into the
    # same source×sink candidate space the resolved stages enumerate, so stage 1
    # shares the fixed denominator instead of counting as a single wall.
    import importlib.util as _ilu
    suite_meta = {}
    for s in used:
        try:
            spec = _ilu.spec_from_file_location(f"_ad_meta_{s}",
                                                str(ROOT_CORPUS / f"analyze_{s}.py"))
            mod = _ilu.module_from_spec(spec)
            spec.loader.exec_module(mod)
            suite_meta[s] = (set(mod.SOURCES), set(mod.SINKS))
        except Exception:
            pass

    def _suite_of(f: Finding) -> Optional[str]:
        fn = os.path.basename(f.file or "")
        return next((s for s in used if s in fn), None)

    try:
        from ctaudit.models.agentdojo import AGENTDOJO_DOMAIN_SINKS
        _DANGER_SINKS = set(AGENTDOJO_DOMAIN_SINKS)
    except Exception:
        _DANGER_SINKS = set()

    def _is_wall(f: Finding) -> bool:
        return f.kind == "dispatch" and not getattr(f, "via_dispatch", None)

    def _vector_backed(f: Finding) -> bool:
        srcs = set(f.source_tools)
        # a concrete (expanded) source: judge by whether THAT source is a vector;
        # do not fall back to the candidate set (which would pass everything).
        is_concrete = bool(srcs) and not any(s.startswith("<") for s in srcs)
        if is_concrete:
            return bool(srcs & vecs)
        if srcs & vecs:
            return True
        cands = set(getattr(f, "framework_candidates", ()) or ())
        return bool(cands & vecs)

    # FIXED-DENOMINATOR confusion matrix: every candidate is classified into
    # exactly one quadrant so TP+FP+FN+TN is CONSTANT across stages. Pruning
    # does not remove a candidate from the matrix — it MOVES it from a "kept"
    # quadrant (TP/FP) to a "suppressed" one (FN/TN). The two axes are:
    #   vector-backed?  (is this a real injection vector → should be reported)
    #   reported?       (kept = not pruned, and not still an unresolved wall)
    # quadrants:  vector & reported = TP   | non-vector & reported = FP
    #             vector & suppressed = FN | non-vector & suppressed = TN
    # An unresolved dispatch wall is "not reported" (classical is stuck): if its
    # candidate set contains a vector it is a suppressed positive → FN.
    tp = fp = fn = tn = 0
    any_concrete = False
    saw_wall_expanded = False
    for f in findings:
        wall = _is_wall(f)
        if wall:
            # classical can't resolve this wall — it reports none of the
            # source×sink candidates it hides. Expand it the same way the
            # resolved stages do, so stage 1 shares the fixed denominator:
            # each (source, dangerous-sink) pair the wall would yield is a
            # MISSED candidate. Vector sources → FN (a real vuln gone unseen);
            # non-vector sources → TN (correctly not reported).
            suite = _suite_of(f)
            meta = suite_meta.get(suite)
            cands = set(getattr(f, "framework_candidates", ()) or ())
            if meta:
                srcs_all, sinks_all = meta
                cand_sources = cands & srcs_all
                # only the DANGER sinks are resolved targets (the resolved stages
                # enumerate source × danger-sink), so restrict the wall expansion
                # to those — otherwise stage 1's denominator would include benign
                # sinks the resolved stages never produce.
                cand_sinks = (cands & sinks_all) & _DANGER_SINKS
                if cand_sources and cand_sinks:
                    n_sink = len(cand_sinks)
                    for src in cand_sources:
                        if src in vecs:
                            fn += n_sink
                        else:
                            tn += n_sink
                    any_concrete = True
                    saw_wall_expanded = True
                    continue
            # fallback (no metadata): a vector-bearing wall is one missed positive
            if cands & vecs:
                fn += 1
            continue
        if f.source_tools and not any(s.startswith("<") for s in f.source_tools):
            any_concrete = True
        vb = _vector_backed(f)
        reported = not f.pruned
        if reported:
            if vb:
                tp += 1
            else:
                fp += 1
        else:  # suppressed: pruned
            if vb:
                fn += 1
            else:
                tn += 1

    # TN is only meaningful once the candidate space is enumerated (source
    # expansion). Without it, the negative space is unbounded, so report the
    # 3-quadrant view (drop TN and the TN-bearing suppressed non-vectors).
    has_tn = any_concrete
    if not has_tn:
        tn = 0

    p = tp / (tp + fp) if (tp + fp) else 1.0
    r = tp / (tp + fn) if (tp + fn) else (1.0 if tp else 0.0)
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    out = {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1,
           "note": f"scored vs AgentDojo's own injection_vectors.yaml for "
                   f"suite(s) {', '.join(used)} (external ground truth; no manual "
                   f"labels). Fixed-denominator confusion matrix: pruning MOVES a "
                   f"candidate from a reported quadrant (TP/FP) to a suppressed "
                   f"one (FN/TN), so TP+FP+FN+TN is constant across stages. An "
                   f"unresolved dispatch wall is a suppressed positive (FN)."}
    if has_tn:
        out["tn"] = tn
    return out



def _classical_view(target: str, triage: str, agentdojo: bool) -> List[Finding]:
    """The view a CLASSICAL static taint analysis would have produced.

    Classical taint analysis (explicit/data-dependency only, no dispatch
    resolution) has two hard limits this project removes:

      * it CANNOT see implicit / control-dependency flows (the LLM-routing case,
        CWE-1426) — TITO only follows bytes, not the model's choice; and
      * it STOPS at a dynamic-dispatch wall — it cannot resolve which concrete
        tool ``registry[name](...)`` selects.

    We reproduce that view from our own raw output by: running with resolution
    OFF (so dispatch stays a wall), then marking every implicit finding as
    ``pruned`` with the reason that classical analysis is blind to it.  The
    existing renderer then dims those (classically-invisible) and draws the
    dispatch walls as walls — i.e. exactly where a classical tool gets stuck.
    """
    raw = run(target, None, triage, resolve=False, agentdojo=agentdojo,
              do_prune=False)
    view: List[Finding] = []
    for f in raw:
        g = _copy.copy(f)
        if g.kind == "implicit":
            g.pruned = True
            g.prune_reason = ("invisible to classical taint analysis — implicit / "
                              "control-dependency flow (LLM routing, CWE-1426); "
                              "TITO follows bytes, not the model's tool choice")
        # dispatch findings stay unresolved walls (resolve=False), which is
        # precisely where classical analysis halts.
        view.append(g)
    return view


def _expand_sources_generic(findings: List[Finding], model) -> List[Finding]:
    """Framework-independent source expansion. Expand each resolved dispatch
    finding (whose source is an abstract ``<...-tools>`` placeholder) into one
    finding PER candidate source tool the classifier recovered, carrying that
    source's role. The role is decided by the classifier from the tool BODY
    (``SourceSpec.attacker``: external reads — HTTP/file/stdin — are
    attacker-influenced; fixed/internal returns are trusted-readonly), NOT a
    per-tool declaration. This is the generic analogue of the AgentDojo-specific
    expansion: same mechanism, role grounded in code instead of suite metadata.
    """
    # map: tool name -> attacker? for every source the classifier found
    src_role = {t.name: bool(t.source and t.source.attacker)
                for t in model.tools if t.source}
    if not src_role:
        return findings
    out: List[Finding] = []
    for f in findings:
        cands = getattr(f, "framework_candidates", ()) or ()
        srcs = list(f.source_tools)
        is_placeholder = (getattr(f, "via_dispatch", None) and
                          (not srcs or srcs[0].startswith("<")))
        cand_sources = [c for c in cands if c in src_role]
        if not (is_placeholder and cand_sources):
            out.append(f)
            continue
        for s in cand_sources:
            g = _copy.copy(f)
            mark = SourceMark(
                tool=s, framework=getattr(f, "framework", "generic") or "generic",
                site="(registry)", hidden=False, out_type="string",
                role=("attacker-influenced" if src_role[s] else "trusted-readonly"),
            )
            g.source_marks = (mark,)
            out.append(g)
    return out


def _expand_agentdojo_sources(findings: List[Finding], target: str) -> List[Finding]:
    """Expand each resolved AgentDojo dispatch finding (whose source is the
    abstract ``<agentdojo-tools>`` placeholder) into one finding PER candidate
    source tool that is an actual source in the suite.

    This surfaces the source×sink candidate space the way the static
    ``--real-corpus`` harness does, so over-flags appear (a non-attacker source
    feeding a dangerous sink) and §4.5 role pruning / §4.6 triage have something
    to filter. The per-source SourceMark carries the suite's declared
    ``attacker``/``capacity`` so role pruning can drop trusted-read-only sources.
    """
    import importlib.util
    base = os.path.basename(target)
    suite = next((s for s in ("banking", "workspace", "travel", "slack")
                  if s in base), None)
    if not suite:
        return findings
    try:
        spec = importlib.util.spec_from_file_location(
            f"_ad_src_{suite}", str(ROOT_CORPUS / f"analyze_{suite}.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        SOURCES = mod.SOURCES
    except Exception:
        return findings

    out: List[Finding] = []
    for f in findings:
        cands = getattr(f, "framework_candidates", ()) or ()
        # only expand resolved dispatch findings with the placeholder source
        srcs = list(f.source_tools)
        is_placeholder = (getattr(f, "via_dispatch", None) and
                          (not srcs or srcs[0].startswith("<")))
        cand_sources = [c for c in cands if c in SOURCES]
        if not (is_placeholder and cand_sources):
            out.append(f)
            continue
        for s in cand_sources:
            meta = SOURCES[s]
            g = _copy.copy(f)
            mark = SourceMark(
                tool=s, framework="agentdojo", site="(registry)",
                hidden=meta.get("hidden", False), out_type=meta.get("capacity"),
                role=("attacker-influenced" if meta.get("attacker")
                      else "trusted-readonly"),
            )
            g.source_marks = (mark,)
            out.append(g)
    return out


def run(target: str, pysa_results: str | None, triage: str,
        classifier: str = "heuristic", resolve: bool = True, model=None,
        framework_registry_trust: bool = False, agentdojo: bool = False,
        do_prune: bool = True, do_triage: bool = True,
        expand_sources: bool = False) -> List[Finding]:
    merged: Dict[Tuple, Finding] = {}
    prov: Dict[Tuple, set] = {}

    # AgentDojo applicability mode (opt-in): add the declarative AgentDojo runtime
    # spec (run_function wall + domain sinks) so the analyzer detects the wall and
    # the classifier grounds the domain tools as sinks/sources.
    reg = None
    if agentdojo:
        from ctaudit.models import default_registry
        from ctaudit.models.agentdojo import agentdojo_registry
        reg = default_registry()
        reg.extend(agentdojo_registry())

    # leg 1 — standalone enumeration / dynamic-dispatch (intra-proc).
    # do_prune=False keeps the COMPLETE raw candidate set (pruning §4.5 disabled),
    # so a comparison report can show what pruning would later remove — crucial
    # for the ablation, since the strong prune rules only bite AFTER fusion#4 has
    # resolved each dispatch wall to a concrete sink.  do_triage=False leaves the
    # candidates UNJUDGED (no triage_verdict), so a "resolution only" stage shows
    # the raw recovered set before any LLM precision filtering.
    res = analyze_path(target, registry=reg, do_prune=do_prune,
                       do_triage=do_triage, triage_backend=triage)
    leg1 = res.findings if not do_prune else [f for f in res.findings if not f.pruned]

    # fusion #4 — resolve each dynamic-dispatch wall to concrete (registry-narrowed)
    # sinks using the shared #5 tool model. Recall-first: if the model has no matching
    # sink the wall is kept as-is. The model is built from `target` (heuristic by
    # default = offline, no key) unless one is injected; pass --classifier deepseek to
    # discover sinks an idiom-specific heuristic misses (e.g. a @classmethod tool).
    # framework_registry_trust (項目1) controls whether a framework-managed dispatch's
    # registered tool set narrows the targets (True) or is candidate-only (False, default).
    if resolve:
        mdl = model if model is not None else get_classifier(classifier, agentdojo=agentdojo).classify(target)
        # Real AgentDojo splits the wall (tool_execution.py) from the TOOLS
        # registration (each suite's task_suite.py), so a wall finding carries an
        # EMPTY framework_candidates. Backfill it from the tools the classifier
        # recovered across the repo so cross-file registration can resolve.
        # GATED on agentdojo: generic dispatches (TOOL_MAP literals, etc.) already
        # narrow via _index_registries, and backfilling framework_candidates there
        # would route them through the candidate-only (non-narrowing) branch and
        # disable that narrowing.
        if agentdojo:
            all_tool_names = tuple(t.name for t in mdl.tools)
            if all_tool_names:
                for f in leg1:
                    if f.kind == "dispatch" and not (getattr(f, "framework_candidates", ()) or ()):
                        f.framework_candidates = all_tool_names
        leg1 = resolve_dispatch(leg1, mdl, repo=target,
                                framework_registry_trust=framework_registry_trust)
        if expand_sources:
            # source expansion: AgentDojo uses suite metadata for roles; the
            # generic path derives roles from the tool body (classifier).
            leg1 = (_expand_agentdojo_sources(leg1, target) if agentdojo
                    else _expand_sources_generic(leg1, mdl))
        if do_triage:
            fresh = [f for f in leg1
                     if getattr(f, "via_dispatch", None) and f.triage_verdict is None]
            if fresh:                              # the resolved findings are new -> triage them
                get_triager(triage).triage(fresh)

    for f in leg1:
        k = _key(f)
        merged.setdefault(k, f)
        tags = prov.setdefault(k, set())
        tags.add("ctaudit-enumerate")
        if getattr(f, "via_dispatch", None):
            tags.add("fusion#4-resolved")

    # leg 2 — Pysa data-flow (inter-proc + recursion), if results provided
    if pysa_results:
        for f in postprocess.findings_from_results(pysa_results, triage=triage):
            if f.pruned and do_prune:
                continue
            k = _key(f)
            if k not in merged:
                merged[k] = f          # Pysa-only finding (covers the dispatch/inter-proc gap)
            prov.setdefault(k, set()).add("pysa-dataflow")

    out = list(merged.values())

    # §4.5(3) role pruning for source-expanded AgentDojo findings: a
    # trusted-readonly source (AgentDojo's own attacker=False tools) cannot
    # dangerously drive any sink, so prune those over-flags statically (no LLM).
    # This is where pruning recovers precision before triage runs.
    # §4.5(3) role pruning for source-expanded findings: a trusted-readonly
    # source (attacker=False — a source the attacker cannot seed) cannot
    # dangerously drive any sink, so prune those over-flags statically (no LLM).
    # Roles come from suite metadata (AgentDojo) or the tool body (generic);
    # either way the pruner only sees the role label, not the ground truth.
    if expand_sources and do_prune:
        from ctaudit.analysis.pruning import prune as _prune, RolePolicy
        cats = {f.sink_category for f in out if f.sink_category}
        policy = RolePolicy(forbidden={c: frozenset({"trusted-readonly"})
                                       for c in cats})
        try:
            _prune(out, role_policy=policy)
        except Exception:
            pass

    # When pruning is disabled (raw/comparison mode), run §4.5 pruning as a
    # DISPLAY-ONLY annotation pass over the resolved candidates so a comparison
    # report can dim the ones pruning would remove (with reasons), without
    # dropping them. This is where the strong rules finally apply, because the
    # dispatch walls are now resolved to concrete sinks. NOTE: the role policy is
    # intentionally NOT applied here — "resolution only" (stage 2) must show the
    # full over-flagged candidate set; role pruning is a stage-3 effect.
    if not do_prune:
        from ctaudit.analysis.pruning import prune as _prune
        try:
            _prune(out)
        except Exception:
            pass

    for k, f in merged.items():
        setattr(f, "_provenance", sorted(prov.get(k, set())))
    return out


def render(findings: List[Finding]) -> str:
    if not findings:
        return "hybrid audit — 0 finding(s)"
    lines = [f"hybrid audit — {len(findings)} finding(s)\n"]
    for i, f in enumerate(findings, 1):
        prov = ", ".join(getattr(f, "_provenance", []) or ["?"])
        if getattr(f, "via_dispatch", None):
            tag = "LLM dispatch \u2192 resolved sink (CWE-1426)"
        elif f.kind == "implicit":
            tag = "CROSS-TOOL IMPLICIT FLOW (CWE-1426)"
        elif f.kind == "dispatch":
            tag = "LLM-controlled tool dispatch \u2014 unresolved (CWE-1426)"
        else:
            tag = "data-layer flow (verbatim)"
        guard = f"guard: {f.guard}()" if getattr(f, "guard", None) else "guard: NONE"
        lines.append(
            f"[{i}] {tag}  ({f.severity})  [{prov}]  [{guard}]\n"
            f"    sink : {f.sink_name}  ({f.sink_category})  @ {f.file}:{f.sink_site}\n"
            f"    via  : {f.trace()}\n"
            f"    triage: {f.triage_verdict} {f.triage_confidence}"
        )
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ctaudit-hybrid",
                                 description="merge Pysa data-flow + standalone dispatch legs")
    ap.add_argument("target", help="Python file or dir (standalone leg)")
    ap.add_argument("--pysa-results", default=None,
                    help="dir from `pyre analyze --save-results-to` (data-flow leg)")
    ap.add_argument("--classifier", choices=("heuristic", "anthropic", "deepseek", "openai"),
                    default="heuristic",
                    help="shared tool-model classifier for fusion #4 dispatch resolution "
                         "(default: heuristic = offline; deepseek/anthropic discover sinks "
                         "an idiom-specific heuristic misses)")
    ap.add_argument("--no-resolve", dest="resolve", action="store_false",
                    help="disable fusion #4 (leave dynamic-dispatch walls unresolved)")
    ap.add_argument("--framework-registry-trust", action="store_true",
                    help="trust a framework-managed dispatch's registered tool set "
                         "(create_react_agent(tools=[...])) as complete membership and "
                         "narrow targets to it; default is conservative (candidate-only, "
                         "recall-first)")
    ap.add_argument("--agentdojo", action="store_true",
                    help="AgentDojo applicability mode: add the declarative AgentDojo "
                         "runtime spec (run_function dict-registry wall + domain-semantic "
                         "sinks like send_money) so its plain-function tools are grounded")
    ap.add_argument("--triage", choices=("mock", "anthropic", "deepseek",
                                         "openai", "openai-compat"), default="mock",
                    help="triage backend (default: mock = offline). deepseek/openai/"
                         "anthropic call the real LLM; set the matching API-key env var "
                         "(DEEPSEEK_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY).")
    ap.add_argument("--html", metavar="FILE", default=None,
                    help="also write a graphical HTML report (Mermaid path diagrams)")
    ap.add_argument("--compare-pruning", action="store_true",
                    help="with --html, ALSO write a second report of the resolved-but-"
                         "UNPRUNED candidate set (pruning §4.5 disabled) to FILE with a "
                         "'_raw' suffix; candidates pruning would remove are dimmed with "
                         "reasons. This is the meaningful ablation, since the strong prune "
                         "rules only apply after fusion#4 resolves each dispatch wall.")
    ap.add_argument("--compare-stages", action="store_true",
                    help="with --html, write FOUR reports showing the progression "
                         "classical -> this work, each scored vs ground truth: "
                         "FILE_stage1_classical (walls unresolved, implicit invisible), "
                         "FILE_stage2_resolved (fusion#4 + implicit recovered, UNJUDGED: "
                         "no pruning, no triage), FILE_stage3_pruned (+ pruning §4.5), "
                         "FILE_stage4_final (+ LLM triage §4.6).")
    ap.add_argument("--expand-sources", action="store_true",
                    help="(AgentDojo) expand each resolved dispatch finding into one "
                         "per candidate source tool, surfacing the source×sink space so "
                         "over-flags appear and §4.5 role pruning / §4.6 triage have "
                         "something to filter. Use with --agentdojo --compare-stages on "
                         "a full-tool fixture (agentdojo_<suite>_full.py).")
    ap.add_argument("--inline-mermaid", metavar="JS", default=None,
                    help="path to mermaid.min.js to embed for a fully offline HTML report")
    args = ap.parse_args(argv)
    findings = run(args.target, args.pysa_results, args.triage,
                   classifier=args.classifier, resolve=args.resolve,
                   framework_registry_trust=args.framework_registry_trust,
                   agentdojo=args.agentdojo)
    print(render(findings))
    if args.html:
        from ctaudit.render_html import write_report
        mode = "AgentDojo applicability" if args.agentdojo else "real-repo hybrid"
        n_kept = sum(1 for f in findings if not f.pruned)
        write_report(
            findings, args.html,
            title="Cross-Tool Audit Report — hybrid",
            subtitle=f"{args.target}  ·  {mode}  ·  legs: pysa + enumerate(+fusion#4)",
            inline_mermaid=args.inline_mermaid,
        )
        print(f"\nHTML report written to {args.html}")

        if args.compare_pruning:
            import os
            raw = run(args.target, args.pysa_results, args.triage,
                      classifier=args.classifier, resolve=args.resolve,
                      framework_registry_trust=args.framework_registry_trust,
                      agentdojo=args.agentdojo, do_prune=False)
            n_raw = len(raw)
            n_pruned = sum(1 for f in raw if f.pruned)
            n_kept_raw = n_raw - n_pruned
            pct = f"{n_pruned / n_raw:.0%}" if n_raw else "0%"
            base, ext = os.path.splitext(args.html)
            raw_path = f"{base}_raw{ext or '.html'}"
            write_report(
                raw, raw_path,
                title="Cross-Tool Audit Report — hybrid RAW (resolved, no pruning)",
                subtitle=f"{args.target}  ·  {mode}  ·  resolved candidates, unfiltered "
                         f"(dimmed = would be pruned)  ·  {n_raw} raw → {n_kept_raw} kept "
                         f"(−{n_pruned}, {pct} reduced)",
                include_pruned=True,
                inline_mermaid=args.inline_mermaid,
            )
            print(f"RAW comparison report written to {raw_path}")
            print(f"  §4.5 pruning would reduce {n_raw} resolved candidates to "
                  f"{n_kept_raw} (−{n_pruned}, {pct})")

        if args.compare_stages:
            import os
            base, ext = os.path.splitext(args.html)
            ext = ext or ".html"
            t, tr, ad = args.target, args.triage, args.agentdojo

            def _metrics(fs):
                """GT metrics + a ground-truth-independent kept/removed breakdown.
                For --agentdojo targets, score against AgentDojo's injection_vectors
                (external GT) instead of the self-authored BENCHMARK."""
                c = _stage_counts(fs)
                breakdown = (f"all files: {c['kept']} kept / {c['pruned']} pruned / "
                             f"{c['triaged_out']} LLM-rejected / {c['walls']} unresolved "
                             f"wall(s) of {c['total']} candidate(s)")
                m = None
                if ad:
                    # detect which AgentDojo suite(s) the target covers, from the
                    # target name (file) or the names of files it contains (dir).
                    names = [os.path.basename(t)]
                    if os.path.isdir(t):
                        try:
                            names = os.listdir(t)
                        except OSError:
                            pass
                    suites = [s for s in ("banking", "workspace", "travel", "slack")
                              if any(s in n for n in names)]
                    if suites:
                        m = _vector_metrics_agentdojo(fs, suites)
                if m is None:
                    m = _gt_metrics(fs)
                if m:
                    m["note"] = m.get("note", "") + " · " + breakdown
                    return m
                # no labelled fixtures: still show the breakdown as a note-only banner
                return {"tp": 0, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0,
                        "f1": 0.0, "note": "(no labelled fixtures in this target) · "
                                           + breakdown}

            # stage 1 — classical static analysis: walls unresolved, implicit flows invisible
            s1 = _classical_view(t, tr, ad)
            s1_visible = sum(1 for f in s1 if not f.pruned)
            s1_walls = sum(1 for f in s1 if f.kind == "dispatch" and not f.via_dispatch)
            s1_blind = sum(1 for f in s1 if f.pruned)
            p1 = f"{base}_stage1_classical{ext}"
            write_report(
                s1, p1,
                title="Stage 1 — CLASSICAL static taint analysis",
                subtitle=f"{t}  ·  data-dependency only  ·  {s1_visible} visible flow(s), "
                         f"{s1_walls} dispatch wall(s) it cannot resolve, "
                         f"{s1_blind} implicit flow(s) it cannot see (dimmed)",
                include_pruned=True, metrics=_metrics(s1),
                inline_mermaid=args.inline_mermaid,
            )

            # stage 2 — resolution ONLY: walls resolved + implicit recovered, but
            # NO pruning and NO triage (candidates are unjudged — no triage_verdict).
            s2 = run(t, args.pysa_results, tr, classifier=args.classifier,
                     resolve=True, framework_registry_trust=args.framework_registry_trust,
                     agentdojo=ad, do_prune=False, do_triage=False, expand_sources=args.expand_sources)
            s2_resolved = sum(1 for f in s2 if f.via_dispatch)
            s2_implicit = sum(1 for f in s2 if f.kind == "implicit")
            p2 = f"{base}_stage2_resolved{ext}"
            write_report(
                s2, p2,
                title="Stage 2 — THIS WORK: resolution only (unjudged candidates)",
                subtitle=f"{t}  ·  fusion#4 resolves walls + implicit flows recovered, "
                         f"NO pruning, NO triage  ·  {len(s2)} candidate(s) "
                         f"({s2_resolved} resolved dispatch, {s2_implicit} implicit)",
                include_pruned=True, metrics=_metrics(s2),
                inline_mermaid=args.inline_mermaid,
            )

            # stage 3 — + PRUNING only (§4.5), still no LLM triage.
            s3 = run(t, args.pysa_results, tr, classifier=args.classifier,
                     resolve=True, framework_registry_trust=args.framework_registry_trust,
                     agentdojo=ad, do_prune=True, do_triage=False, expand_sources=args.expand_sources)
            s3_kept = sum(1 for f in s3 if not f.pruned)
            s3_dropped = sum(1 for f in s3 if f.pruned)
            p3 = f"{base}_stage3_pruned{ext}"
            write_report(
                s3, p3,
                title="Stage 3 — THIS WORK: + pruning (§4.5), no triage yet",
                subtitle=f"{t}  ·  static pruning applied, LLM triage NOT yet run  ·  "
                         f"{s3_kept} kept, {s3_dropped} pruned",
                include_pruned=True, metrics=_metrics(s3),
                inline_mermaid=args.inline_mermaid,
            )

            # stage 4 — FINAL: + LLM triage (§4.6) on top of pruning.
            s4 = run(t, args.pysa_results, tr, classifier=args.classifier,
                     resolve=True, framework_registry_trust=args.framework_registry_trust,
                     agentdojo=ad, do_prune=True, do_triage=True, expand_sources=args.expand_sources)
            # drop LLM-judged false positives from the final kept set
            for f in s4:
                if not f.pruned and f.triage_verdict == "false-positive":
                    f.pruned = True
                    f.prune_reason = (f"LLM triage: false-positive "
                                      f"({f.triage_confidence:.0%})"
                                      if f.triage_confidence is not None
                                      else "LLM triage: false-positive")
            s4_kept = sum(1 for f in s4 if not f.pruned)
            s4_tp = sum(1 for f in s4 if not f.pruned and f.triage_verdict == "true-positive")
            s4_fp = sum(1 for f in s4 if f.triage_verdict == "false-positive")
            p4 = f"{base}_stage4_final{ext}"
            write_report(
                s4, p4,
                title="Stage 4 — THIS WORK, FINAL: + LLM triage (§4.6)",
                subtitle=f"{t}  ·  pruning + LLM triage  ·  {s4_kept} kept "
                         f"({s4_tp} LLM-confirmed TP, {s4_fp} LLM-rejected FP)",
                include_pruned=True, metrics=_metrics(s4),
                inline_mermaid=args.inline_mermaid,
            )

            def _m(fs):
                m = _metrics(fs)
                return (f"P={m['precision']:.0%} R={m['recall']:.0%} F1={m['f1']:.2f}"
                        if m else "(no metrics)")
            print(f"\nStage comparison written (each shows metrics vs ground truth):")
            print(f"  1 classical    : {p1}  {_m(s1)}")
            print(f"  2 resolved-only: {p2}  {_m(s2)}")
            print(f"  3 +pruning     : {p3}  {_m(s3)}")
            print(f"  4 +LLM-triage  : {p4}  {_m(s4)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
