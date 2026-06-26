#!/usr/bin/env python3
"""Shared logic for the AgentDojo per-suite cross-tool implicit-flow audits.

Each suite script (analyze_banking.py, analyze_workspace.py, ...) just declares
its real tool registry as SOURCES/SINKS metadata dicts and calls `analyze()`.
The cross-tool implicit flow is modelled as registry + join-at-LLM (proposal
§4.2 wiring + §4.4 join): every co-registered (source, sink) pair is a candidate
because the LLM can route any source output to any sink input. §4.5 then prunes.

See corpus/agentdojo/README.md for why AgentDojo uses this enumeration approach
rather than the Pysa dataflow port (its tools are isolated functions with no
code path between them — only the LLM links them).
"""

from __future__ import annotations

import csv
from itertools import product
from pathlib import Path

# capacity lattice (§4.5(2)): bool ⊑ enum ⊑ string. numeric/date are enum-level —
# they cannot carry a free-form injected instruction. Only `string` can.
CAP = {"bool": 0, "enum": 1, "numeric": 1, "date": 1, "string": 2}


def _passes(s: dict, k: dict, *, use_schema=True, use_role=True,
            use_reach=True, use_hide=True) -> bool:
    """Does the (source s -> sink k) implicit-flow candidate survive §4.5?"""
    # §4.5(1) reachability: both endpoints reachable by the agent.
    if use_reach and not (s["reachable"] and k["reachable"]):
        return False
    # §4.5(2) channel capacity: the source must be able to carry a free-form
    # injected instruction (string). A numeric/enum/date source cannot, so it
    # can never steer the LLM regardless of the sink.
    if use_schema and CAP.get(s["capacity"], CAP["string"]) < CAP["string"]:
        return False
    # §4.5(3) role: source must be attacker-influenceable and sink sensitive.
    if use_role and not (s["attacker"] and k["sensitive"]):
        return False
    # §4.5(4) selective hiding (FIDES HIDE): a hidden source is sanitised.
    if use_hide and s.get("hidden", False):
        return False
    return True


def _flows(SOURCES, SINKS, **flags):
    return [(s, k) for s, k in product(SOURCES, SINKS)
            if _passes(SOURCES[s], SINKS[k], **flags)]


def _sink_guard(sink_meta: dict):
    """The in-function guard recorded on a sink, or None.

    A guard (e.g. ``_check_safety``) is a MITIGATING annotation, never a prune: a
    weak/incomplete guard can be bypassed, so the static flow still exists. We
    record it so the audit can rank UNGUARDED routings (the unintended/unguarded
    instances the sharpened RQ1 targets) above guarded ones."""
    return sink_meta.get("guard")


def split_by_guard(flows, SINKS):
    """Partition (source, sink) flows into (unguarded, guarded) by sink guard."""
    unguarded = [(s, k) for s, k in flows if not _sink_guard(SINKS[k])]
    guarded = [(s, k) for s, k in flows if _sink_guard(SINKS[k])]
    return unguarded, guarded


def render_flows_by_guard(flows, SINKS, *, title="cross-tool implicit flow",
                          source_suffix=":out") -> str:
    """Shared renderer: print surviving flows split into UNGUARDED (high) and
    GUARDED (noted). Used by analyze() (AgentDojo leg), the per-repo enumerations
    (shellgpt_enum / termwise_enum), and any other enumeration consumer."""
    unguarded, guarded = split_by_guard(flows, SINKS)
    out = [f"{title} — {len(flows)} pair(s) survive §4.5 "
           f"({len(unguarded)} UNGUARDED, {len(guarded)} guarded):", ""]
    out.append("UNGUARDED  (high priority — unintended/unguarded routing):")
    for s, k in unguarded:
        cat = SINKS[k].get("category", "sink")
        out.append(f"  [CWE-1426] {s}  ==(model routing)==>  {k}  [{cat}, guard: NONE]")
    if not unguarded:
        out.append("  (none)")
    out.append("")
    out.append("GUARDED    (flow exists but mitigated in-function — lower priority):")
    for s, k in guarded:
        cat = SINKS[k].get("category", "sink")
        out.append(f"  [CWE-1426] {s}  ==(model routing)==>  {k}  "
                   f"[{cat}, guard: {_sink_guard(SINKS[k])}()]")
    if not guarded:
        out.append("  (none)")
    return "\n".join(out)


def load_labels(path):
    positives, rows = set(), []
    with open(path) as fh:
        for row in csv.DictReader(fh):
            rows.append(row)
            if row.get("label", "0").strip() == "1":
                positives.add((row["source_tool"].strip(), row["sink_tool"].strip()))
    return positives, rows


# ablation display labels, in the order printed
_ABL = (("schema", "use_schema", "-schema(capacity)"),
        ("role", "use_role", "-role"),
        ("reachability", "use_reach", "-reachability"),
        ("hiding", "use_hide", "-hiding"))


def compute(suite: str, SOURCES: dict, SINKS: dict, labels_path) -> dict:
    """Pure metrics for one suite (no printing). Used by analyze() and by the
    eval real-corpus aggregator (ctaudit/eval/real_corpus.py)."""
    positives, _rows = load_labels(labels_path)
    raw = list(product(SOURCES, SINKS))
    pruned = _flows(SOURCES, SINKS)
    pset = set(pruned)
    ablation = {key: len(_flows(SOURCES, SINKS, **{flag: False}))
                for key, flag, _label in _ABL}
    kept = sorted(p for p in positives if p in pset)
    missed = sorted(p for p in positives if p not in pset)
    extra = sorted(p for p in pset if p not in positives)
    unguarded, guarded = split_by_guard(pruned, SINKS)
    return {
        "suite": suite,
        "n_sources": len(SOURCES), "n_sinks": len(SINKS),
        "raw": len(raw), "pruned": len(pruned),
        "n_unguarded": len(unguarded), "n_guarded": len(guarded),
        "ablation": ablation,
        "ablation_delta": {k: v - len(pruned) for k, v in ablation.items()},
        "positives": len(positives), "tp": len(kept), "fn": len(missed),
        "recall": (len(kept) / len(positives)) if positives else 1.0,
        "kept": kept, "missed": missed, "extra": extra,
    }


def analyze(suite: str, SOURCES: dict, SINKS: dict, labels_path) -> int:
    m = compute(suite, SOURCES, SINKS, labels_path)
    print("=" * 74)
    print(f"AgentDojo · {suite} · cross-tool implicit-flow audit (registry + join@LLM)")
    print("=" * 74)
    print(f"registered sources: {m['n_sources']}  |  registered sinks: {m['n_sinks']}")
    print(f"raw candidate flows (source × sink): {m['raw']}")

    print(f"after §4.5 pruning: {m['pruned']}  "
          f"({m['n_unguarded']} unguarded, {m['n_guarded']} guarded)")

    print("\nablation (flows when a single prune is disabled):")
    for key, _flag, label in _ABL:
        n = m["ablation"][key]
        print(f"  {label:18s}: {n:3d}   (Δ vs pruned = +{n - m['pruned']})")

    print(f"\nground-truth exploitable pairs (from injection tasks): {m['positives']}")
    for s, k in sorted(m["kept"] + m["missed"]):
        print(f"  [{'kept ' if (s, k) in m['kept'] else 'MISSED'}] {s} -> {k}")
    print(f"recall after pruning: {m['tp']}/{m['positives']} = {m['recall']:.0%}")
    print("  no false negatives — pruning preserved every tested attack path."
          if not m["missed"] else
          f"  FALSE NEGATIVES (pruning removed a real attack path!): {m['missed']}")

    print(f"\nsurviving-but-untested candidate flows: {len(m['extra'])}  "
          f"(AgentDojo has no injection task for these; candidates, not FPs)")
    for s, k in m["extra"][:8]:
        print(f"  · {s} -> {k}")
    if len(m["extra"]) > 8:
        print(f"  … and {len(m['extra']) - 8} more")

    print("\nNote: precision/FP require the defended-vs-undefended comparison or a")
    print("completed label set; see docs/stage4_evaluation.md §10. RECALL + prune")
    print("reduction + ablation are the meaningful metrics on AgentDojo positives.")
    return 0 if not m["missed"] else 1
