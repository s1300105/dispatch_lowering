"""ctaudit.render_html — graphical HTML reporting for cross-tool audit findings.

Consumes the project's own ``ctaudit.report.Finding`` objects and emits a single
HTML file with Mermaid diagrams.  It works uniformly for all three validation
paths in this repo, because every path yields the same ``Finding`` type:

  * self / fixture audit   ``ctaudit.analyze_path(...).findings``
  * real-repo hybrid audit ``hybrid.run(target, ...)``           (list[Finding])
  * AgentDojo applicability ``hybrid.run(target, agentdojo=True)``

The hybrid driver attaches a ``_provenance`` list (which static leg(s) found the
flow) onto each finding via ``setattr``; this renderer reads it when present.

Unlike a plain source→sink view, every diagram records the FULL chain of
waypoints the analysis actually traversed:

    [leg(s)]  source tool(s)  ──history──▶  LLM node(s)  ──tool_calls──▶
              ─(dispatch resolved: expr ▸ candidates)─▶  (guard?)  ▶  ⟦sink⟧

For a pure data-layer (explicit) flow there is no LLM node, and the edge is
drawn dotted (verbatim TITO), matching ``Finding.trace()``.

Public API
----------
    waypoints(f)                      -> list[Waypoint]     (the ordered path)
    mermaid_for_finding(f, idx=…)     -> str                (one flowchart)
    mermaid_overview(findings)        -> str                (whole-run graph)
    render_report(findings, …)        -> str                (full HTML document)
    write_report(findings, path, …)   -> None
"""
from __future__ import annotations

import html
import os
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

from .report import Finding, KIND_LABEL
from .labels import SourceMark  # noqa: F401  (kept for type clarity / re-export)


# --------------------------------------------------------------------------- #
# palette
# --------------------------------------------------------------------------- #
SEVERITY_FILL = {
    "critical": "#7f1d1d", "high": "#b91c1c",
    "medium": "#c2410c", "low": "#a16207",
}
KIND_ACCENT = {
    "implicit": "#dc2626",   # cross-tool implicit flow (the headline class)
    "dispatch": "#ea580c",   # LLM-controlled dispatch (wall, maybe unresolved)
    "explicit": "#2563eb",   # data-layer / verbatim TITO
}
STAGE_STYLE = {            # node fill/stroke/text per waypoint stage
    "leg":        ("#0f172a", "#475569", "#94a3b8"),
    "source":     ("#1e293b", "#64748b", "#e2e8f0"),
    "llm":        ("#312e81", "#818cf8", "#e0e7ff"),
    "dispatch":   ("#7c2d12", "#fb923c", "#ffedd5"),
    "unresolved": ("#3f2d0a", "#facc15", "#fde68a"),  # dispatch WALL, not yet resolved
    "guard":      ("#064e3b", "#34d399", "#d1fae5"),
    "sink":       ("#7f1d1d", "#fecaca", "#ffffff"),
}


def _is_unresolved_wall(f: Finding) -> bool:
    """True when this finding is a model-controlled dispatch that has NOT been
    resolved to a concrete sink (single-leg / no fusion#4).  Its ``sink_name`` is
    the dispatch *expression*, not a real dangerous operation."""
    return f.kind == "dispatch" and not f.via_dispatch


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _esc_mm(s) -> str:
    """Escape a label for safe use inside a Mermaid node body."""
    if s is None:
        return ""
    s = str(s).replace("\\", "/").replace('"', "'")
    s = s.replace("[", "(").replace("]", ")").replace("{", "(").replace("}", ")")
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace("|", "/").replace("`", "'")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _short_site(site: str) -> str:
    """``a/b/c/file.py:41:12`` -> ``file.py:41``."""
    if not site:
        return "?"
    site = str(site).replace("\\", "/")
    parts = site.split(":")
    path = parts[0].rsplit("/", 1)[-1]
    line = parts[1] if len(parts) > 1 else ""
    return f"{path}:{line}" if line else path


def _sink_loc(f: Finding) -> str:
    site = f.sink_site or ""
    if f.file and ":" not in str(site):
        site = f"{f.file}:{site}"
    return _short_site(site)


def _provenance(f: Finding) -> List[str]:
    return list(getattr(f, "_provenance", []) or [])


# --------------------------------------------------------------------------- #
# the ordered path of waypoints — the core "show everything in between" model
# --------------------------------------------------------------------------- #
@dataclass
class Waypoint:
    stage: str            # "leg" | "source" | "llm" | "dispatch" | "guard" | "sink"
    label: str            # short headline
    detail: str = ""      # secondary line (framework/role/site/…)
    edge: str = ""        # label of the edge leading INTO this waypoint


def waypoints(f: Finding) -> List[Waypoint]:
    """The full ordered chain the analysis traversed for this finding.

    leg(s) → source(s) → LLM node(s) → [dispatch resolution] → [guard] → sink.
    Every intermediate hop the engine recorded is represented, not just the
    endpoints.
    """
    wps: List[Waypoint] = []

    # 0) which static leg(s) produced this flow (hybrid only)
    legs = _provenance(f)
    if legs:
        wps.append(Waypoint("leg", "static leg(s)", ", ".join(legs)))

    # 1) source tool(s) — keep each mark's framework / role / out_type / hidden
    marks = list(f.source_marks or ())
    if not marks:
        wps.append(Waypoint("source", "untrusted source", "&lt;unknown&gt;",
                            edge="leg" if legs else ""))
    for m in marks:
        det = [m.framework, _short_site(m.site)]
        if getattr(m, "role", None):
            det.append(f"role={m.role}")
        if getattr(m, "out_type", None):
            det.append(f"type={m.out_type}")
        if getattr(m, "hidden", False):
            det.append("HIDDEN (cut)")
        wps.append(Waypoint("source", m.tool, " · ".join(d for d in det if d)))

    # 2) LLM node(s) the control taint passed through (join@LLM, §4.4)
    if f.exit_sites:
        for s in f.exit_sites:
            wps.append(Waypoint("llm", "LLM join", _short_site(s), edge="history"))
        last_edge = "tool_calls"
    else:
        # data layer — no LLM node; bytes flow verbatim into the sink (TITO)
        last_edge = "data (TITO)"

    # 3) dispatch resolution (fusion #4): the model-chosen routing made concrete
    if f.via_dispatch:
        cands = getattr(f, "framework_candidates", ()) or ()
        det = f"candidates: {', '.join(cands)}" if cands else "registry-narrowed"
        wps.append(Waypoint("dispatch", f"dispatch ▸ {f.via_dispatch}", det,
                            edge=last_edge))
        last_edge = "resolved"

    # 4) in-function guard preceding the sink (mitigating; never prunes)
    if f.guard:
        wps.append(Waypoint("guard", "guard", f.guard, edge=last_edge))
        last_edge = "guarded"

    # 5) the endpoint.  Normally a concrete dangerous sink — but if this finding
    # is a dispatch wall that was never resolved (single-leg, no fusion#4), the
    # "sink_name" is actually the dispatch EXPRESSION, so we draw it as an
    # unresolved wall (a routing point still to be resolved), not a sink.
    if _is_unresolved_wall(f):
        cands = getattr(f, "framework_candidates", ()) or ()
        det = (f"candidates: {', '.join(cands)}" if cands
               else "targets unresolved (run hybrid to resolve)")
        wps.append(Waypoint("unresolved", f"dispatch wall ▸ {f.sink_name}",
                            det, edge=last_edge))
        return wps

    sink_det = f"{f.sink_category} · {_sink_loc(f)}"
    if f.param_type:
        sink_det += f" · param={f.param_type}"
    wps.append(Waypoint("sink", f.sink_name, sink_det, edge=last_edge))
    return wps


# --------------------------------------------------------------------------- #
# per-finding Mermaid flowchart — every waypoint becomes a node
# --------------------------------------------------------------------------- #
def mermaid_for_finding(f: Finding, *, idx: int = 0) -> str:
    p = f"f{idx}_"
    accent = KIND_ACCENT.get(f.kind, "#64748b")
    sev_fill = SEVERITY_FILL.get((f.severity or "").lower(), "#475569")
    wps = waypoints(f)

    lines: List[str] = ["flowchart TD"]
    ids: List[str] = []
    for i, w in enumerate(wps):
        nid = f"{p}n{i}"
        ids.append(nid)
        body = _esc_mm(w.label)
        if w.detail:
            body += f"<br/><small>{_esc_mm(w.detail)}</small>"
        # node shape per stage
        if w.stage == "sink":
            lines.append(f'  {nid}[["{body}"]]')
        elif w.stage == "unresolved":
            lines.append(f'  {nid}[/"{body}"\\]')   # trapezoid = wall, not a sink
        elif w.stage == "llm":
            lines.append(f'  {nid}{{{{"{body}"}}}}')
        elif w.stage in ("dispatch", "guard"):
            lines.append(f'  {nid}(["{body}"])')
        else:                                 # leg / source
            lines.append(f'  {nid}["{body}"]')

    # edges follow the recorded order; sources fan into the first LLM/next node
    src_idx = [i for i, w in enumerate(wps) if w.stage == "source"]
    leg_idx = [i for i, w in enumerate(wps) if w.stage == "leg"]
    consumed = set()
    # leg -> each source
    for li in leg_idx:
        for si in src_idx:
            lines.append(f"  {ids[li]} --> {ids[si]}")
            consumed.add((li, si))
    # find the node that sources flow INTO (first non-source after the sources)
    after_src = next((i for i, w in enumerate(wps)
                      if w.stage not in ("leg", "source")), None)
    if after_src is not None:
        edge = wps[after_src].edge or "history"
        for si in src_idx:
            lines.append(f"  {ids[si]} =={edge}==> {ids[after_src]}")
            consumed.add((si, after_src))
    # chain the remaining waypoints sequentially (llm→…→sink)
    seq = [i for i, w in enumerate(wps) if w.stage not in ("leg", "source")]
    for a, b in zip(seq, seq[1:]):
        edge = wps[b].edge or ""
        arrow = f" =={edge}==> " if edge else " ==> "
        lines.append(f"  {ids[a]}{arrow}{ids[b]}")

    # styling
    for i, w in enumerate(wps):
        if w.stage == "sink":
            fill, stroke, txt = sev_fill, "#fecaca", "#ffffff"
        else:
            fill, stroke, txt = STAGE_STYLE[w.stage]
            if w.stage == "source":
                stroke = accent
        lines.append(f"  style {ids[i]} fill:{fill},stroke:{stroke},color:{txt}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# overview Mermaid graph — whole run as a tool/LLM/dispatch/sink influence graph
# --------------------------------------------------------------------------- #
def mermaid_overview(findings: Sequence[Finding], *, include_pruned: bool = False) -> str:
    shown = [f for f in findings if include_pruned or not f.pruned]
    if not shown:
        # no findings to lay out — don't strand a giant lone "LLM join" hexagon
        return ('flowchart LR\n'
                '  empty["no findings to display"]\n'
                '  style empty fill:#0f172a,stroke:#334155,color:#94a3b8')
    lines: List[str] = ["flowchart LR", "  LLM{{LLM join}}"]
    tool_ids: dict = {}
    sink_ids: dict = {}
    disp_ids: dict = {}
    t_n = s_n = d_n = 0
    # ordered edge list so each edge has a stable index for linkStyle coloring.
    # each entry: (edge_str, color_or_None, dotted_bool)
    edge_list: List[tuple] = []
    seen_edges: dict = {}   # edge_str -> first index (dedupe but keep first color)

    # distinct, readable hues cycled per finding so one src→LLM→sink path is
    # traceable by color. The LLM-join confluence is preserved: BOTH the
    # src→LLM and LLM→(dispatch→)sink edges of a finding take that finding's
    # colour, so the model's "all sources join at the LLM" claim still holds
    # while a reader can follow a single finding end to end by hue.
    _PALETTE = ["#60a5fa", "#f472b6", "#34d399", "#fbbf24", "#a78bfa",
                "#fb7185", "#22d3ee", "#a3e635", "#fb923c", "#e879f9",
                "#2dd4bf", "#facc15"]

    def _add_edge(s: str, color, dotted: bool):
        if s in seen_edges:
            return
        seen_edges[s] = len(edge_list)
        edge_list.append((s, color, dotted))

    for fi, f in enumerate(shown):
        color = _PALETTE[fi % len(_PALETTE)]
        unresolved = _is_unresolved_wall(f)
        # include the source file so sinks/walls at the same line in different
        # files (e.g. each suite's run_function wall) are not merged into one node
        _f = os.path.basename(f.file or "")
        skey = f"{_f}::{f.sink_name}@{_sink_loc(f)}"
        if skey not in sink_ids:
            sid = f"S{s_n}"; s_n += 1
            sink_ids[skey] = sid
            if unresolved:
                # a routing wall whose targets are unknown — not a sink
                lines.append(f'  {sid}[/"dispatch wall<br/>'
                             f'<small>{_esc_mm(f.sink_name)}</small>"\\]')
                lines.append(f"  style {sid} fill:#3f2d0a,stroke:#facc15,color:#fde68a")
            else:
                sev = SEVERITY_FILL.get((f.severity or "").lower(), "#475569")
                lines.append(f'  {sid}[["{_esc_mm(f.sink_name)}<br/>'
                             f'<small>{_esc_mm(f.sink_category)}</small>"]]')
                lines.append(f"  style {sid} fill:{sev},stroke:#fecaca,color:#fff")
        sid = sink_ids[skey]

        # optional dispatch hub between LLM and sink. Key by file+label so each
        # suite's run_function wall is its OWN hub (they all share the label
        # "runtime.run_function" but are independent walls in different files).
        mid = "LLM"
        if f.via_dispatch:
            _hf = os.path.basename(f.file or "")
            dkey = f"{_hf}::{f.via_dispatch}"
            if dkey not in disp_ids:
                did = f"D{d_n}"; d_n += 1
                disp_ids[dkey] = did
                # show the file stem (suite) under the dispatch label to
                # disambiguate multiple hubs in a combined report
                _stem = _hf[:-3] if _hf.endswith(".py") else _hf
                _suffix = f"<br/><small>{_esc_mm(_stem)}</small>" if _stem else ""
                lines.append(f'  {did}(["dispatch<br/>'
                             f'<small>{_esc_mm(f.via_dispatch)}</small>{_suffix}"])')
                lines.append("  style %s fill:#7c2d12,stroke:#fb923c,color:#ffedd5" % did)
            did = disp_ids[dkey]

        for m in (list(f.source_marks) or [None]):
            tkey = m.tool if m else "&lt;unknown&gt;"
            if tkey not in tool_ids:
                tid = f"T{t_n}"; t_n += 1
                tool_ids[tkey] = tid
                fw = f" · {_esc_mm(m.framework)}" if m else ""
                lines.append(f'  {tid}["{_esc_mm(tkey)}<br/>'
                             f'<small>tool output{fw}</small>"]')
                lines.append(f"  style {tid} fill:#1e293b,stroke:#475569,color:#e2e8f0")
            tid = tool_ids[tkey]
            if f.exit_sites:
                _add_edge(f"  {tid} ==> LLM", color, False)
                if f.via_dispatch:
                    _add_edge(f"  LLM ==> {did}", color, False)
                    _add_edge(f"  {did} ==> {sid}", color, False)
                else:
                    _add_edge(f"  LLM ==> {sid}", color, False)
            else:  # data layer
                if f.via_dispatch:
                    _add_edge(f"  {tid} -.data.-> {did}", color, True)
                    _add_edge(f"  {did} ==> {sid}", color, False)
                else:
                    _add_edge(f"  {tid} -.data.-> {sid}", color, True)

    if not tool_ids:
        lines.append('  empty["no findings"]')
        return "\n".join(lines)
    # emit edges in definition order, then per-edge linkStyle by index
    for s, _c, _d in edge_list:
        lines.append(s)
    for idx, (_s, c, dotted) in enumerate(edge_list):
        if c is None:
            continue
        stroke_dash = ",stroke-dasharray:4 3" if dotted else ""
        lines.append(f"  linkStyle {idx} stroke:{c},stroke-width:2px{stroke_dash}")
    lines.append("  style LLM fill:#312e81,stroke:#818cf8,color:#e0e7ff")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
def _badge(text: str, color: str) -> str:
    return f'<span class="badge" style="background:{color}">{html.escape(str(text))}</span>'


def _path_chips(f: Finding) -> str:
    """A compact textual rendering of the full waypoint chain (stage by stage)."""
    parts = []
    for w in waypoints(f):
        cls = f"wp wp-{w.stage}"
        d = f' <span class="wpd">{html.escape(w.detail)}</span>' if w.detail else ""
        if w.edge:
            parts.append(f'<span class="wpedge">{html.escape(w.edge)}▸</span>')
        parts.append(f'<span class="{cls}">{html.escape(w.label)}{d}</span>')
    return '<div class="path">' + "".join(parts) + "</div>"


def _finding_card(f: Finding, idx: int) -> str:
    accent = KIND_ACCENT.get(f.kind, "#64748b")
    sev = (f.severity or "").lower()
    sev_color = SEVERITY_FILL.get(sev, "#475569")
    title = html.escape(KIND_LABEL.get(f.kind, f.kind))

    state = []
    for leg in _provenance(f):
        state.append(_badge(leg, "#1e3a5f"))
    unresolved = _is_unresolved_wall(f)
    if unresolved:
        state.append(_badge("unresolved dispatch — run hybrid to resolve", "#854d0e"))
    if f.pruned:
        state.append(_badge(f"pruned: {f.prune_reason or 'yes'}", "#334155"))
    if not f.reachable:
        state.append(_badge("unreachable", "#334155"))
    if f.guard:
        state.append(_badge("guarded", "#065f46"))
    if f.triage_verdict:
        tv = {"true-positive": "#b91c1c", "false-positive": "#334155",
              "uncertain": "#a16207"}.get(f.triage_verdict, "#475569")
        conf = f" {f.triage_confidence:.0%}" if f.triage_confidence is not None else ""
        state.append(_badge(f"{f.triage_verdict}{conf}", tv))

    if unresolved:
        cands = getattr(f, "framework_candidates", ()) or ()
        c = (html.escape(", ".join(cands)) if cands
             else "unknown (resolve with hybrid + fusion#4)")
        endpoint_row = ("dispatch wall",
                        f"<code>{html.escape(f.sink_name)}</code> @ "
                        f"<code>{html.escape(_sink_loc(f))}</code><br/>"
                        f"<span class='muted'>model-chosen routing point; "
                        f"candidate targets: {c}</span>")
    else:
        endpoint_row = ("sink",
                        f"{html.escape(f.sink_name)} "
                        f"<span class='muted'>({html.escape(f.sink_category)})</span> @ "
                        f"<code>{html.escape(_sink_loc(f))}</code> "
                        f"<span class='muted'>param={html.escape(f.param_type or '?')}</span>")

    rows = [
        endpoint_row,
        ("tainted arg", f"<code>{html.escape(f.arg_expr or '—')}</code>"),
        ("source tools", html.escape(", ".join(f.source_tools) or "&lt;unknown&gt;")),
        ("frameworks", html.escape(", ".join(f.frameworks) or "—")),
        ("LLM nodes", html.escape(", ".join(_short_site(s) for s in f.exit_sites)
                                  or "(none — data layer)")),
    ]
    if f.via_dispatch:
        cands = getattr(f, "framework_candidates", ()) or ()
        c = f" → candidates: {html.escape(', '.join(cands))}" if cands else ""
        rows.append(("dispatch", f"<code>{html.escape(f.via_dispatch)}</code>{c}"))
    if f.guard:
        rows.append(("guard", f"<code>{html.escape(f.guard)}</code>"))
    rows.append(("full trace", f"<code class='trace'>{html.escape(f.trace())}</code>"))
    if f.triage_rationale:
        rows.append(("triage note", html.escape(f.triage_rationale)))

    rows_html = "\n".join(
        f'<div class="row"><div class="k">{k}</div><div class="v">{v}</div></div>'
        for k, v in rows)
    pruned_cls = " pruned" if f.pruned else ""
    return f"""
<section class="card{pruned_cls}" style="border-left-color:{accent}">
  <div class="card-head">
    <div class="card-title"><span class="idx">#{idx + 1}</span> {title}
      {_badge(sev or 'n/a', sev_color)} {''.join(state)}</div>
    {_path_chips(f)}
  </div>
  <div class="card-body">
    <div class="meta">{rows_html}</div>
    <div class="diagram"><pre class="mermaid">
{html.escape(mermaid_for_finding(f, idx=idx))}
    </pre></div>
  </div>
</section>"""


def _summary(findings: Sequence[Finding]) -> str:
    kept = [f for f in findings if not f.pruned]
    by_kind: dict = {}; by_sev: dict = {}; by_leg: dict = {}
    n_unresolved = 0
    for f in kept:
        if _is_unresolved_wall(f):
            n_unresolved += 1
        by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
        by_sev[(f.severity or "n/a").lower()] = by_sev.get((f.severity or "n/a").lower(), 0) + 1
        for leg in _provenance(f):
            by_leg[leg] = by_leg.get(leg, 0) + 1
    chips = []
    for k in ("implicit", "dispatch", "explicit"):
        if by_kind.get(k):
            if k == "dispatch":
                resolved = by_kind[k] - n_unresolved
                if resolved:
                    chips.append(_badge(f"dispatch → resolved sink: {resolved}",
                                        KIND_ACCENT["dispatch"]))
                if n_unresolved:
                    chips.append(_badge(f"unresolved dispatch wall: {n_unresolved}",
                                        "#854d0e"))
            else:
                chips.append(_badge(f"{KIND_LABEL.get(k, k).split(' (')[0]}: {by_kind[k]}",
                                    KIND_ACCENT.get(k, "#475569")))
    for s in ("critical", "high", "medium", "low"):
        if by_sev.get(s):
            chips.append(_badge(f"{s}: {by_sev[s]}", SEVERITY_FILL.get(s, "#475569")))
    for leg, n in sorted(by_leg.items()):
        chips.append(_badge(f"{leg}: {n}", "#1e3a5f"))
    pruned = sum(1 for f in findings if f.pruned)
    return (f'<div class="summary"><strong>{len(kept)}</strong> finding(s) after pruning '
            f'<span class="muted">({len(findings)} raw, {pruned} pruned)</span>'
            f'<div class="chips">{"".join(chips)}</div></div>')


_CSS = """
:root{--bg:#0b1120;--panel:#111827;--line:#1f2937;--text:#e2e8f0;--muted:#94a3b8;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
 font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;}
header{padding:26px 32px;border-bottom:1px solid var(--line)}
h1{margin:0 0 4px;font-size:20px}.sub{color:var(--muted);font-size:13px}
main{padding:22px 32px;max-width:1180px;margin:0 auto}
.summary{margin:6px 0 20px}.chips{margin-top:10px;display:flex;flex-wrap:wrap;gap:6px}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;
 font-weight:600;color:#fff;white-space:nowrap}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
 margin:30px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
.overview{background:var(--panel);border:1px solid var(--line);border-radius:12px;
 padding:18px;overflow:auto}
.card{background:var(--panel);border:1px solid var(--line);border-left-width:4px;
 border-radius:12px;margin:14px 0;overflow:hidden}.card.pruned{opacity:.62}
.card-head{padding:13px 18px;border-bottom:1px solid var(--line)}
.card-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-weight:600}
.idx{color:var(--muted);font-variant-numeric:tabular-nums}
.path{margin-top:10px;display:flex;flex-wrap:wrap;align-items:center;gap:5px;font-size:11px}
.wp{padding:2px 8px;border-radius:6px;border:1px solid var(--line);white-space:nowrap}
.wp .wpd{color:var(--muted);font-size:10px}
.wp-leg{background:#0f172a;border-color:#475569;color:#94a3b8}
.wp-source{background:#1e293b;border-color:#64748b}
.wp-llm{background:#312e81;border-color:#818cf8;color:#e0e7ff}
.wp-dispatch{background:#7c2d12;border-color:#fb923c;color:#ffedd5}
.wp-unresolved{background:#3f2d0a;border-color:#facc15;color:#fde68a}
.wp-guard{background:#064e3b;border-color:#34d399;color:#d1fae5}
.wp-sink{background:#7f1d1d;border-color:#fecaca;color:#fff}
.wpedge{color:var(--muted);font-size:10px}
.metrics-banner{background:var(--panel);border:1px solid var(--line);border-radius:12px;
 padding:14px 18px;margin:0 0 22px}
.mtitle{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
 margin-bottom:10px}
.metrics-grid{display:flex;flex-wrap:wrap;gap:22px}
.metric{min-width:70px}
.mlabel{font-size:11px;color:var(--muted)}
.mvalue{font-size:22px;font-weight:700;font-variant-numeric:tabular-nums}
.mnote{margin-top:10px;font-size:12px;color:var(--muted)}
.card-body{display:grid;grid-template-columns:minmax(360px,1fr) minmax(360px,1fr)}
@media(max-width:860px){.card-body{grid-template-columns:1fr}}
.meta{padding:15px 18px;border-right:1px solid var(--line)}
@media(max-width:860px){.meta{border-right:none;border-bottom:1px solid var(--line)}}
.row{display:grid;grid-template-columns:118px 1fr;gap:10px;padding:5px 0;
 border-bottom:1px dashed var(--line);font-size:13px}.row:last-child{border-bottom:none}
.k{color:var(--muted)}
.v code{background:#0b1220;padding:1px 6px;border-radius:5px;font-size:12px;
 color:#cbd5e1;word-break:break-all}
.v code.trace{display:block;padding:8px;white-space:pre-wrap;line-height:1.5}
.muted{color:var(--muted)}
.diagram{padding:14px 18px;display:flex;align-items:center;justify-content:flex-start;
 background:#0b1220;overflow:auto;min-height:220px}
.mermaid{margin:0;min-width:520px}
.mermaid svg{max-width:none!important;height:auto}
footer{padding:18px 32px;color:var(--muted);font-size:12px;border-top:1px solid var(--line)}
"""

_MERMAID_INIT = """
mermaid.initialize({startOnLoad:true,securityLevel:'strict',theme:'base',
 themeVariables:{fontSize:'12px',lineColor:'#64748b',primaryColor:'#1e293b',
 primaryTextColor:'#e2e8f0',primaryBorderColor:'#475569'},
 flowchart:{htmlLabels:true,curve:'basis'}});
"""


def _mermaid_script_tag(cdn: str, inline_path: Optional[str]) -> str:
    if inline_path:
        try:
            with open(inline_path, encoding="utf-8") as fh:
                return f"<script>{fh.read()}</script>"
        except OSError:
            pass
    return f'<script src="{cdn}"></script>'


def _metrics_banner(metrics: Optional[dict]) -> str:
    """A ground-truth comparison banner: TP/FP/FN + precision/recall/F1.

    `metrics` keys: tp, fp, fn (ints); precision, recall, f1 (floats, 0..1);
    optional `note` (str). Returns '' when metrics is None.
    """
    if not metrics:
        return ""
    tp = metrics.get("tp", 0); fp = metrics.get("fp", 0); fn = metrics.get("fn", 0)
    p = metrics.get("precision", 1.0); r = metrics.get("recall", 1.0)
    f1 = metrics.get("f1", 0.0)
    tn = metrics.get("tn")  # None unless the negative space is enumerated
    note = metrics.get("note", "")

    def _cell(label, value, color):
        return (f'<div class="metric"><div class="mlabel">{html.escape(label)}</div>'
                f'<div class="mvalue" style="color:{color}">{value}</div></div>')

    # colour precision/recall: green high, amber mid, red low
    def _pc(x):
        return "#4ade80" if x >= 0.8 else ("#fbbf24" if x >= 0.5 else "#f87171")

    confusion = [
        _cell("true positive", tp, "#4ade80"),
        _cell("false positive", fp, "#f87171" if fp else "#94a3b8"),
        _cell("false negative", fn, "#f87171" if fn else "#94a3b8"),
    ]
    if tn is not None:
        # true negative = correctly suppressed over-flags (green = good)
        confusion.append(_cell("true negative", tn, "#4ade80" if tn else "#94a3b8"))
    rates = [
        _cell("precision", f"{p:.0%}", _pc(p)),
        _cell("recall", f"{r:.0%}", _pc(r)),
        _cell("F1", f"{f1:.2f}", _pc(f1)),
    ]
    if tn is not None:
        denom = tp + fp + fn + tn
        acc = (tp + tn) / denom if denom else 1.0
        rates.append(_cell("accuracy", f"{acc:.0%}", _pc(acc)))
    cells = "".join(confusion + rates)
    note_html = f'<div class="mnote">{html.escape(note)}</div>' if note else ""
    return (f'<div class="metrics-banner"><div class="mtitle">vs Ground Truth</div>'
            f'<div class="metrics-grid">{cells}</div>{note_html}</div>')


def render_report(
    findings: Iterable[Finding],
    *,
    title: str = "Cross-Tool Audit Report",
    subtitle: str = "",
    include_pruned: bool = True,
    metrics: Optional[dict] = None,
    mermaid_cdn: str = "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js",
    inline_mermaid: Optional[str] = None,
) -> str:
    """Return a complete HTML document.

    ``inline_mermaid`` = path to ``mermaid.min.js`` embeds the library for a
    fully offline, self-contained report; otherwise it is loaded from a CDN.
    ``metrics`` = optional dict (tp/fp/fn/precision/recall/f1/note) rendered as a
    ground-truth comparison banner under the summary.
    """
    flist = list(findings)
    shown = [f for f in flist if include_pruned or not f.pruned]
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    kind_rank = {"implicit": 0, "dispatch": 1, "explicit": 2}
    shown.sort(key=lambda f: (f.pruned, kind_rank.get(f.kind, 9),
                              sev_rank.get((f.severity or "").lower(), 9)))
    cards = "\n".join(_finding_card(f, i) for i, f in enumerate(shown)) \
        or '<p class="muted">No findings.</p>'
    overview = mermaid_overview(flist, include_pruned=include_pruned)
    sub = html.escape(subtitle) if subtitle else \
        "full path: leg → source → LLM → dispatch → guard → sink"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>{_CSS}</style></head><body>
<header><h1>{html.escape(title)}</h1><div class="sub">{sub}</div></header>
<main>
  {_summary(flist)}
  {_metrics_banner(metrics)}
  <h2>Influence overview — which tools reach which sinks</h2>
  <div class="overview"><pre class="mermaid">
{html.escape(overview)}
  </pre></div>
  <h2>Findings — full waypoint paths</h2>
  {cards}
</main>
<footer>Generated by ctaudit · cross-tool implicit-flow static audit (CWE-1426).
 Every diagram shows the complete chain of waypoints the analysis traversed.
 Hexagon = LLM join node; stadium = resolved dispatch / guard; double box = sink;
 yellow trapezoid = unresolved dispatch wall (model-chosen routing not yet resolved to a concrete sink — run the hybrid driver to resolve it).
 Solid edges = control dependency through the LLM (implicit); dotted = data-layer (TITO).</footer>
{_mermaid_script_tag(mermaid_cdn, inline_mermaid)}
<script>{_MERMAID_INIT}</script>
</body></html>"""


def write_report(findings: Iterable[Finding], path: str, **kwargs) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_report(findings, **kwargs))
