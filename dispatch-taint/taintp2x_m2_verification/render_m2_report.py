#!/usr/bin/env python3
"""render_m2_report.py — TaintP2X M2 検証結果を Mermaid 付き HTML で可視化する。

cond_A（dispatch_lowering なし）と cond_B（dispatch_lowering あり）の
taint-output.json を読み込み、各 issue / dispatch 壁を Mermaid フローチャート付きカードで表示する。

Usage:
    python3 render_m2_report.py [--out-dir DIR] [--inline-mermaid JS]
                                [cond_A_json] [cond_B_json]
"""

from __future__ import annotations

import argparse
import html
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 定数
# ---------------------------------------------------------------------------
CODE_LABEL = {5001: "RemoteCodeExecution", 5005: "ExecArgSink"}
SINK_FILL = {
    "RemoteCodeExecution": "#b91c1c",
    "ExecArgSink":         "#c2410c",
}


# ---------------------------------------------------------------------------
# データモデル
# ---------------------------------------------------------------------------
@dataclass
class TaintIssue:
    """Pysa が検出した完全な source → sink フロー（issue エントリ）。"""
    idx: int
    callable_name: str
    callable_line: int
    code: int
    line: int
    filename: str
    message: str
    source_kind: str
    source_leaf: str
    source_port: str
    source_origin_line: int
    sink_kind: str
    sink_leaf: str
    sink_port: str
    resolves_to: List[str]
    features: List[dict] = field(default_factory=list)

    @property
    def sink_color(self) -> str:
        return SINK_FILL.get(self.sink_kind, "#7f1d1d")

    @property
    def code_label(self) -> str:
        return CODE_LABEL.get(self.code, str(self.code))


@dataclass
class DispatchWall:
    """Pysa が dispatch 壁で止まった部分フロー（model エントリから抽出）。

    taint は source → LLM join → dispatch 壁まで届いたが、
    unknown-callee のため sink には到達できなかった。
    """
    idx: int
    callable_name: str
    callable_line: int
    filename: str
    source_kind: str
    source_leaf: str
    source_port: str
    source_origin_line: int
    wall_line: int       # tito_positions の line（dynamic dispatch 呼び出し箇所）
    via_feature: str     # 例: "obscure:unknown-callee"


# ---------------------------------------------------------------------------
# JSON パーサ
# ---------------------------------------------------------------------------
def _iter_json(path: str):
    with open(path, encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip().rstrip(",")
            if not raw or raw in ("[", "]"):
                continue
            try:
                yield json.loads(raw)
            except Exception:
                pass


def parse_taint_json(path: str) -> List[TaintIssue]:
    """issue エントリを読み取り TaintIssue のリストを返す。"""
    issues: List[TaintIssue] = []
    for o in _iter_json(path):
        if o.get("kind") != "issue":
            continue
        d = o["data"]
        source_kind = source_leaf = source_port = ""
        source_origin_line = 0
        sink_kind = sink_leaf = sink_port = ""
        resolves_to: List[str] = []

        for tr in d.get("traces", []):
            if tr["name"] == "forward":
                for root in tr.get("roots", []):
                    for k in root.get("kinds", []):
                        source_kind = k.get("kind", "")
                        for lf in k.get("leaves", []):
                            source_leaf = lf.get("name", "")
                            source_port = lf.get("port", "")
                    if "origin" in root:
                        source_origin_line = root["origin"].get("line", 0)
            elif tr["name"] == "backward":
                for root in tr.get("roots", []):
                    for k in root.get("kinds", []):
                        sink_kind = k.get("kind", "")
                        for lf in k.get("leaves", []):
                            sink_leaf = lf.get("name", "")
                            sink_port = lf.get("port", "")
                    if "call" in root:
                        resolves_to = root["call"].get("resolves_to", [])

        issues.append(TaintIssue(
            idx=len(issues),
            callable_name=d.get("callable", ""),
            callable_line=d.get("callable_line", 0),
            code=d.get("code", 0),
            line=d.get("line", 0),
            filename=d.get("filename", ""),
            message=d.get("message", ""),
            source_kind=source_kind,
            source_leaf=source_leaf,
            source_port=source_port,
            source_origin_line=source_origin_line,
            sink_kind=sink_kind,
            sink_leaf=sink_leaf,
            sink_port=sink_port,
            resolves_to=resolves_to,
            features=d.get("features", []),
        ))
    return issues


def parse_dispatch_walls(path: str) -> List[DispatchWall]:
    """model エントリを読み取り、dispatch 壁で止まった部分フローを抽出する。

    LLMControlled な parameter_sources を持ち、かつ sources に
    always-via: obscure:unknown-callee が含まれるモデルを対象とする。
    """
    walls: List[DispatchWall] = []
    for o in _iter_json(path):
        if o.get("kind") != "model":
            continue
        d = o["data"]

        # LLMControlled が parameter source として存在するか確認
        has_llm = any(
            k.get("kind") == "LLMControlled"
            for ps in d.get("parameter_sources", [])
            for t in ps.get("taint", [])
            for k in t.get("kinds", [])
        )
        if not has_llm:
            continue

        for src_entry in d.get("sources", []):
            for taint in src_entry.get("taint", []):
                # obscure:unknown-callee を持つフローのみ
                via_feats = [
                    f.get("always-via", "")
                    for f in taint.get("local_features", [])
                    if "unknown-callee" in str(f.get("always-via", ""))
                ]
                if not via_feats:
                    continue

                origin = taint.get("origin", {})
                source_origin_line = origin.get("line", 0)
                tito = taint.get("tito_positions", [])
                wall_line = tito[0].get("line", 0) if tito else 0

                source_kind = source_leaf = source_port = ""
                for k in taint.get("kinds", []):
                    source_kind = k.get("kind", "")
                    for lf in k.get("leaves", []):
                        source_leaf = lf.get("name", "")
                        source_port = lf.get("port", "")

                if not source_kind:
                    continue

                walls.append(DispatchWall(
                    idx=len(walls),
                    callable_name=d.get("callable", ""),
                    callable_line=d.get("callable_line", 0),
                    filename=d.get("filename", ""),
                    source_kind=source_kind,
                    source_leaf=source_leaf,
                    source_port=source_port,
                    source_origin_line=source_origin_line,
                    wall_line=wall_line,
                    via_feature=via_feats[0],
                ))
    return walls


# ---------------------------------------------------------------------------
# Mermaid ヘルパ
# ---------------------------------------------------------------------------
def _esc(s) -> str:
    if s is None:
        return ""
    s = str(s).replace("\\", "/").replace('"', "'")
    s = s.replace("[", "(").replace("]", ")").replace("{", "(").replace("}", ")")
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace("|", "/").replace("`", "'")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _short(name: str) -> str:
    parts = name.rsplit(".", 2)
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


# ---------------------------------------------------------------------------
# per-issue Mermaid フローチャート
# ---------------------------------------------------------------------------
def mermaid_for_issue(issue: TaintIssue) -> str:
    """source → LLM join → dispatch(es) → sink を flowchart TD で描く。"""
    p = f"i{issue.idx}_"
    lines: List[str] = ["flowchart TD"]
    ids: List[str] = []

    # node 0: source
    src_lbl = _esc(issue.source_leaf)
    src_det = _esc(f"{issue.source_port} @ line {issue.source_origin_line}")
    lines.append(f'  {p}n0["{src_lbl}<br/><small>{src_det}</small>"]')
    ids.append(f"{p}n0")

    # node 1: LLM join
    llm_det = _esc(f"{_short(issue.callable_name)} @ {issue.filename}:{issue.callable_line}")
    lines.append(f'  {p}n1{{{{"LLM join<br/><small>{llm_det}</small>"}}}}')
    ids.append(f"{p}n1")

    # node 2…: dispatch 解決先
    n = 2
    dispatch_ids: List[str] = []
    for callee in (issue.resolves_to or ["(unresolved)"]):
        nid = f"{p}n{n}"
        disp_lbl = _esc(f"dispatch ▸ {_short(callee)}")
        disp_det = _esc(f"{issue.filename}:{issue.line}")
        lines.append(f'  {nid}(["{disp_lbl}<br/><small>{disp_det}</small>"])')
        ids.append(nid)
        dispatch_ids.append(nid)
        n += 1

    # node last: sink
    sink_id = f"{p}n{n}"
    sink_lbl = _esc(issue.sink_leaf)
    sink_det = _esc(f"{issue.sink_kind} \xb7 {issue.sink_port}")
    lines.append(f'  {sink_id}[["{sink_lbl}<br/><small>{sink_det}</small>"]]')
    ids.append(sink_id)

    # edges
    lines.append(f"  {ids[0]} ==history==> {ids[1]}")
    for did in dispatch_ids:
        lines.append(f"  {ids[1]} ==tool_calls==> {did}")
        lines.append(f"  {did} ==> {sink_id}")

    # styles
    lines.append(f"  style {ids[0]} fill:#1e293b,stroke:#64748b,color:#e2e8f0")
    lines.append(f"  style {ids[1]} fill:#312e81,stroke:#818cf8,color:#e0e7ff")
    for did in dispatch_ids:
        lines.append(f"  style {did} fill:#7c2d12,stroke:#fb923c,color:#ffedd5")
    lines.append(f"  style {sink_id} fill:{issue.sink_color},stroke:#fecaca,color:#ffffff")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# per-wall Mermaid フローチャート
# ---------------------------------------------------------------------------
def mermaid_for_wall(wall: DispatchWall) -> str:
    """source → LLM join → dispatch 壁（blocked）を flowchart TD で描く。"""
    p = f"w{wall.idx}_"
    lines: List[str] = ["flowchart TD"]

    # node 0: source
    src_lbl = _esc(wall.source_leaf)
    src_det = _esc(f"{wall.source_port} @ line {wall.source_origin_line}")
    lines.append(f'  {p}n0["{src_lbl}<br/><small>{src_det}</small>"]')

    # node 1: LLM join
    llm_det = _esc(f"{_short(wall.callable_name)} @ {wall.filename}:{wall.callable_line}")
    lines.append(f'  {p}n1{{{{"LLM join<br/><small>{llm_det}</small>"}}}}')

    # node 2: dispatch 壁（trapezoid = 黄色、sink 未解決）
    wall_det = _esc(f"command(**tool_call.arguments) @ {wall.filename}:{wall.wall_line}")
    wall_feat = _esc(f"via: {wall.via_feature}")
    lines.append(f'  {p}n2[/"dispatch wall (blocked)<br/>'
                 f'<small>{wall_det}</small><br/>'
                 f'<small>{wall_feat}</small>"\\]')

    # edges
    lines.append(f"  {p}n0 ==history==> {p}n1")
    lines.append(f"  {p}n1 ==tool_calls (blocked)==> {p}n2")

    # styles
    lines.append(f"  style {p}n0 fill:#1e293b,stroke:#64748b,color:#e2e8f0")
    lines.append(f"  style {p}n1 fill:#312e81,stroke:#818cf8,color:#e0e7ff")
    lines.append(f"  style {p}n2 fill:#3f2d0a,stroke:#facc15,color:#fde68a")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 全体 overview グラフ
# ---------------------------------------------------------------------------
@dataclass
class _Edge:
    src: str
    dst: str
    color: str
    thick: bool = True   # True = thick (==>), False = dotted (-..->)
    count: int = 1

    def mermaid_str(self) -> str:
        if self.count > 1:
            label = f"\xd7{self.count}"
            return (f"  {self.src} =={label}==> {self.dst}" if self.thick
                    else f"  {self.src} -.|{label}|-> {self.dst}")
        return (f"  {self.src} ==> {self.dst}" if self.thick
                else f"  {self.src} -.-> {self.dst}")


def mermaid_overview(issues: List[TaintIssue],
                     walls: Optional[List[DispatchWall]] = None) -> str:
    """全体影響グラフ（LR）。

    issues: 完全フロー（sink まで到達）→ 辺にカウントラベルを付けて全件を表現
    walls:  部分フロー（dispatch 壁で止まった）→ 壁ノードを黄色台形で表示
    """
    walls = walls or []
    if not issues and not walls:
        return ("flowchart LR\n"
                '  empty["no findings"]\n'
                "  style empty fill:#0f172a,stroke:#334155,color:#94a3b8")

    _PALETTE = ["#60a5fa", "#f472b6", "#34d399", "#fbbf24", "#a78bfa",
                "#fb7185", "#22d3ee", "#a3e635", "#fb923c", "#e879f9",
                "#2dd4bf", "#facc15"]

    lines: List[str] = ["flowchart LR", '  LLM{{"LLM join"}}']
    src_ids: Dict[str, str] = {}
    snk_ids: Dict[str, str] = {}
    dsp_ids: Dict[str, str] = {}
    wall_ids: Dict[str, str] = {}
    s_n = sn_n = d_n = w_n = 0

    # edges: key=(src,dst) → _Edge  (order tracked separately)
    edge_map: Dict[Tuple[str, str], _Edge] = {}
    edge_order: List[Tuple[str, str]] = []

    def _add(src: str, dst: str, color: str, thick: bool = True):
        key = (src, dst)
        if key in edge_map:
            edge_map[key].count += 1
        else:
            edge_map[key] = _Edge(src, dst, color, thick)
            edge_order.append(key)

    # --- 完全フロー（issues） ---
    for fi, issue in enumerate(issues):
        color = _PALETTE[fi % len(_PALETTE)]

        sk = issue.source_leaf
        if sk not in src_ids:
            sid = f"SRC{s_n}"; s_n += 1
            src_ids[sk] = sid
            lbl = _esc(_short(issue.source_leaf))
            det = _esc(issue.source_kind)
            lines.append(f'  {sid}["{lbl}<br/><small>{det}</small>"]')
            lines.append(f"  style {sid} fill:#1e293b,stroke:#64748b,color:#e2e8f0")
        src_id = src_ids[sk]

        tk = f"{issue.sink_leaf}:{issue.sink_kind}"
        if tk not in snk_ids:
            nid = f"SNK{sn_n}"; sn_n += 1
            snk_ids[tk] = nid
            lbl = _esc(issue.sink_leaf)
            det = _esc(issue.sink_kind)
            lines.append(f'  {nid}[["{lbl}<br/><small>{det}</small>"]]')
            lines.append(f"  style {nid} fill:{issue.sink_color},stroke:#fecaca,color:#fff")
        snk_id = snk_ids[tk]

        for callee in (issue.resolves_to or ["(unresolved)"]):
            dk = callee
            if dk not in dsp_ids:
                did = f"D{d_n}"; d_n += 1
                dsp_ids[dk] = did
                lbl = _esc(_short(callee))
                lines.append(f'  {did}(["dispatch<br/><small>{lbl}</small>"])')
                lines.append(f"  style {did} fill:#7c2d12,stroke:#fb923c,color:#ffedd5")
            did = dsp_ids[callee]

            _add(src_id, "LLM", color)
            _add("LLM", did, color)
            _add(did, snk_id, color)

    # --- 部分フロー（walls） ---
    for wall in walls:
        sk = wall.source_leaf
        if sk not in src_ids:
            sid = f"SRC{s_n}"; s_n += 1
            src_ids[sk] = sid
            lbl = _esc(_short(wall.source_leaf))
            det = _esc(wall.source_kind)
            lines.append(f'  {sid}["{lbl}<br/><small>{det}</small>"]')
            lines.append(f"  style {sid} fill:#1e293b,stroke:#64748b,color:#e2e8f0")
        src_id = src_ids[wall.source_leaf]

        wk = f"{wall.callable_name}:{wall.wall_line}"
        if wk not in wall_ids:
            wid = f"W{w_n}"; w_n += 1
            wall_ids[wk] = wid
            lbl = _esc(f"dispatch wall (blocked)")
            det = _esc(f"{wall.filename}:{wall.wall_line} \xb7 {wall.via_feature}")
            lines.append(f'  {wid}[/"dispatch wall (blocked)<br/><small>{det}</small>"\\]')
            lines.append(f"  style {wid} fill:#3f2d0a,stroke:#facc15,color:#fde68a")
        wid = wall_ids[wk]

        _add(src_id, "LLM", "#94a3b8")
        _add("LLM", wid, "#facc15")

    # emit edges
    for key in edge_order:
        lines.append(edge_map[key].mermaid_str())
    for idx, key in enumerate(edge_order):
        e = edge_map[key]
        lines.append(f"  linkStyle {idx} stroke:{e.color},stroke-width:2px")

    lines.append("  style LLM fill:#312e81,stroke:#818cf8,color:#e0e7ff")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML 部品
# ---------------------------------------------------------------------------
_CSS = """\
:root{--bg:#0b1120;--panel:#111827;--line:#1f2937;--text:#e2e8f0;--muted:#94a3b8;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
 font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;}
header{padding:26px 32px;border-bottom:1px solid var(--line)}
h1{margin:0 0 4px;font-size:20px}.sub{color:var(--muted);font-size:13px}
main{padding:22px 32px;max-width:1180px;margin:0 auto}
.summary{margin:6px 0 20px;background:var(--panel);border:1px solid var(--line);
 border-radius:12px;padding:16px 20px}
.chips{margin-top:10px;display:flex;flex-wrap:wrap;gap:6px}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;
 font-weight:600;color:#fff;white-space:nowrap}
.cond-count{font-size:36px;font-weight:700;font-variant-numeric:tabular-nums}
.cond-note{font-size:13px;color:var(--muted)}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
 margin:30px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
.overview{background:var(--panel);border:1px solid var(--line);border-radius:12px;
 padding:18px;overflow:auto}
.card{background:var(--panel);border:1px solid var(--line);border-left-width:4px;
 border-radius:12px;margin:14px 0;overflow:hidden}
.card-wall{border-left-color:#facc15}
.card-head{padding:13px 18px;border-bottom:1px solid var(--line)}
.card-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-weight:600}
.idx{color:var(--muted);font-variant-numeric:tabular-nums}
.path{margin-top:10px;display:flex;flex-wrap:wrap;align-items:center;gap:5px;font-size:11px}
.wp{padding:2px 8px;border-radius:6px;border:1px solid var(--line);white-space:nowrap}
.wp .wpd{color:var(--muted);font-size:10px}
.wp-source{background:#1e293b;border-color:#64748b}
.wp-llm{background:#312e81;border-color:#818cf8;color:#e0e7ff}
.wp-dispatch{background:#7c2d12;border-color:#fb923c;color:#ffedd5}
.wp-wall{background:#3f2d0a;border-color:#facc15;color:#fde68a}
.wp-sink{background:#7f1d1d;border-color:#fecaca;color:#fff}
.wpedge{color:var(--muted);font-size:10px}
.card-body{display:grid;grid-template-columns:minmax(360px,1fr) minmax(360px,1fr)}
@media(max-width:860px){.card-body{grid-template-columns:1fr}}
.meta{padding:15px 18px;border-right:1px solid var(--line)}
@media(max-width:860px){.meta{border-right:none;border-bottom:1px solid var(--line)}}
.row{display:grid;grid-template-columns:130px 1fr;gap:10px;padding:5px 0;
 border-bottom:1px dashed var(--line);font-size:13px}.row:last-child{border-bottom:none}
.k{color:var(--muted)}
.v code{background:#0b1220;padding:1px 6px;border-radius:5px;font-size:12px;
 color:#cbd5e1;word-break:break-all}
.muted{color:var(--muted)}
.diagram{padding:14px 18px;display:flex;align-items:center;justify-content:flex-start;
 background:#0b1220;overflow:auto;min-height:220px}
.mermaid{margin:0;min-width:520px}
.mermaid svg{max-width:none!important;height:auto}
footer{padding:18px 32px;color:var(--muted);font-size:12px;border-top:1px solid var(--line)}
"""

_MERMAID_INIT = """\
mermaid.initialize({startOnLoad:true,securityLevel:'strict',theme:'base',
 themeVariables:{fontSize:'12px',lineColor:'#64748b',primaryColor:'#1e293b',
 primaryTextColor:'#e2e8f0',primaryBorderColor:'#475569'},
 flowchart:{htmlLabels:true,curve:'basis'}});
"""


def _badge(text: str, color: str) -> str:
    return f'<span class="badge" style="background:{color}">{html.escape(str(text))}</span>'


def _path_chips_issue(issue: TaintIssue) -> str:
    parts: List[str] = []

    def chip(cls, label, detail=""):
        d = f' <span class="wpd">{html.escape(detail)}</span>' if detail else ""
        return f'<span class="{cls}">{html.escape(label)}{d}</span>'

    def arrow(lbl):
        return f'<span class="wpedge">{html.escape(lbl)}▸</span>'

    parts.append(chip("wp wp-source", _short(issue.source_leaf), issue.source_kind))
    parts.append(arrow("history"))
    parts.append(chip("wp wp-llm", "LLM join",
                       f"{_short(issue.callable_name)} :{issue.callable_line}"))
    for callee in (issue.resolves_to or ["(unresolved)"]):
        parts.append(arrow("tool_calls"))
        parts.append(chip("wp wp-dispatch", f"dispatch ▸ {_short(callee)}",
                          f"{issue.filename}:{issue.line}"))
    parts.append(arrow(""))
    parts.append(chip("wp wp-sink", issue.sink_leaf, issue.sink_kind))
    return '<div class="path">' + "".join(parts) + "</div>"


def _path_chips_wall(wall: DispatchWall) -> str:
    parts: List[str] = []

    def chip(cls, label, detail=""):
        d = f' <span class="wpd">{html.escape(detail)}</span>' if detail else ""
        return f'<span class="{cls}">{html.escape(label)}{d}</span>'

    def arrow(lbl):
        return f'<span class="wpedge">{html.escape(lbl)}▸</span>'

    parts.append(chip("wp wp-source", _short(wall.source_leaf), wall.source_kind))
    parts.append(arrow("history"))
    parts.append(chip("wp wp-llm", "LLM join",
                       f"{_short(wall.callable_name)} :{wall.callable_line}"))
    parts.append(arrow("tool_calls (blocked)"))
    parts.append(chip("wp wp-wall", "dispatch wall (blocked)",
                      f"{wall.filename}:{wall.wall_line} \xb7 {wall.via_feature}"))
    return '<div class="path">' + "".join(parts) + "</div>"


def _feature_tags(issue: TaintIssue) -> str:
    tags = []
    for f in issue.features:
        for k, v in f.items():
            tags.append(f"{k}:{v}" if v and v != k else k)
    return html.escape(", ".join(tags)) if tags else "—"


def _issue_card(issue: TaintIssue) -> str:
    sink_col = issue.sink_color
    resolves_html = html.escape(
        ", ".join(issue.resolves_to) if issue.resolves_to else "(unresolved)")

    rows = [
        ("source",    f"<code>{html.escape(issue.source_leaf)}</code>"
                      f" <span class='muted'>({html.escape(issue.source_kind)})</span>"
                      f" @ line {issue.source_origin_line}"),
        ("port",      f"<code>{html.escape(issue.source_port)}</code>"),
        ("callable",  f"<code>{html.escape(issue.callable_name)}</code>"
                      f" <span class='muted'>@ line {issue.callable_line}</span>"),
        ("dispatch→", f"<code>{resolves_html}</code>"
                      f" <span class='muted'>@ {html.escape(issue.filename)}:{issue.line}</span>"),
        ("sink",      f"<code>{html.escape(issue.sink_leaf)}</code>"
                      f" <span class='muted'>({html.escape(issue.sink_kind)})</span>"),
        ("sink port", f"<code>{html.escape(issue.sink_port)}</code>"),
        ("features",  f"<span class='muted'>{_feature_tags(issue)}</span>"),
    ]
    rows_html = "\n".join(
        f'<div class="row"><div class="k">{k}</div><div class="v">{v}</div></div>'
        for k, v in rows)

    return f"""\
<section class="card" style="border-left-color:{sink_col}">
  <div class="card-head">
    <div class="card-title">
      <span class="idx">#{issue.idx + 1}</span>
      {html.escape(issue.message)}
      {_badge(f"code {issue.code}", sink_col)}
      {_badge(issue.code_label, sink_col)}
    </div>
    {_path_chips_issue(issue)}
  </div>
  <div class="card-body">
    <div class="meta">{rows_html}</div>
    <div class="diagram"><pre class="mermaid">
{html.escape(mermaid_for_issue(issue))}
    </pre></div>
  </div>
</section>"""


def _wall_card(wall: DispatchWall) -> str:
    rows = [
        ("source",       f"<code>{html.escape(wall.source_leaf)}</code>"
                         f" <span class='muted'>({html.escape(wall.source_kind)})</span>"
                         f" @ line {wall.source_origin_line}"),
        ("port",         f"<code>{html.escape(wall.source_port)}</code>"),
        ("callable",     f"<code>{html.escape(wall.callable_name)}</code>"
                         f" <span class='muted'>@ line {wall.callable_line}</span>"),
        ("dispatch wall",f"<code>{html.escape(wall.filename)}:{wall.wall_line}</code>"
                         f" <span class='muted'>command(**tool_call.arguments)</span>"),
        ("blocked by",   f"<code>{html.escape(wall.via_feature)}</code>"),
        ("sink",         "<span class='muted'>— sink 未到達（dispatch が不透明）</span>"),
    ]
    rows_html = "\n".join(
        f'<div class="row"><div class="k">{k}</div><div class="v">{v}</div></div>'
        for k, v in rows)

    return f"""\
<section class="card card-wall">
  <div class="card-head">
    <div class="card-title">
      <span class="idx">W{wall.idx + 1}</span>
      dispatch 壁で停止 &mdash; sink 未到達
      {_badge("dispatch wall", "#854d0e")}
      {_badge(wall.source_kind, "#1e3a5f")}
    </div>
    {_path_chips_wall(wall)}
  </div>
  <div class="card-body">
    <div class="meta">{rows_html}</div>
    <div class="diagram"><pre class="mermaid">
{html.escape(mermaid_for_wall(wall))}
    </pre></div>
  </div>
</section>"""


def _summary(issues: List[TaintIssue], walls: List[DispatchWall],
             cond_note: str, count_color: str) -> str:
    total = len(issues) + len(walls)
    by_code: Dict[str, int] = {}
    by_dispatch: Dict[str, int] = {}
    for iss in issues:
        by_code[iss.code_label] = by_code.get(iss.code_label, 0) + 1
        for c in iss.resolves_to:
            key = _short(c)
            by_dispatch[key] = by_dispatch.get(key, 0) + 1

    chips: List[str] = []
    for lbl, n in sorted(by_code.items()):
        col = SINK_FILL.get(lbl, "#475569")
        chips.append(_badge(f"{lbl}: {n}", col))
    for lbl, n in sorted(by_dispatch.items()):
        chips.append(_badge(f"via {lbl}: {n}", "#7c2d12"))
    if walls:
        chips.append(_badge(f"dispatch wall: {len(walls)}", "#854d0e"))

    chips_html = f'<div class="chips">{"".join(chips)}</div>' if chips else ""
    return f"""\
<div class="summary">
  <span class="cond-count" style="color:{count_color}">{total}</span>
  <span class="cond-note">&nbsp;エントリ &mdash; {html.escape(cond_note)}</span>
  {chips_html}
</div>"""


def _mermaid_tag(cdn: str, inline_path: Optional[str] = None) -> str:
    if inline_path:
        try:
            return f"<script>{Path(inline_path).read_text(encoding='utf-8')}</script>"
        except OSError:
            pass
    return f'<script src="{cdn}"></script>'


# ---------------------------------------------------------------------------
# メイン出力
# ---------------------------------------------------------------------------
def render_report(
    issues: List[TaintIssue],
    walls: Optional[List[DispatchWall]] = None,
    *,
    title: str,
    subtitle: str,
    cond_note: str,
    count_color: str,
    findings_heading: str,
    mermaid_cdn: str = "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js",
    inline_mermaid: Optional[str] = None,
) -> str:
    walls = walls or []
    overview = mermaid_overview(issues, walls)

    issue_cards = "\n".join(_issue_card(iss) for iss in issues)
    wall_cards = "\n".join(_wall_card(w) for w in walls)
    all_cards = (issue_cards + "\n" + wall_cards).strip() \
        or '<p class="muted">No findings.</p>'

    return f"""\
<!doctype html>
<html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>{_CSS}</style></head><body>
<header>
  <h1>{html.escape(title)}</h1>
  <div class="sub">{html.escape(subtitle)}</div>
</header>
<main>
  {_summary(issues, walls, cond_note, count_color)}
  <h2>Influence overview &mdash; source &rarr; LLM &rarr; dispatch &rarr; sink</h2>
  <div class="overview"><pre class="mermaid">
{html.escape(overview)}
  </pre></div>
  <h2>{html.escape(findings_heading)}</h2>
  {all_cards}
</main>
<footer>
  Generated by render_m2_report.py &middot; TaintP2X M2 verification (AutoGPT v0.5.0).<br/>
  Hexagon = LLM join; stadium = resolved dispatch; double box = sink;
  yellow trapezoid = dispatch wall blocked by unknown-callee.<br/>
  Overview edge label \xd7N = N distinct issues share this path.
  Solid edges = LLM-controlled taint.
</footer>
{_mermaid_tag(mermaid_cdn, inline_mermaid)}
<script>{_MERMAID_INIT}</script>
</body></html>"""


def _filter_walls(issues: List[TaintIssue],
                  walls: List[DispatchWall]) -> List[DispatchWall]:
    """完全な issue が既に存在する callable の wall は除外する。

    dispatch_lowering は元の動的呼び出しを残したまま `if False:` ブロックを追記する。
    そのため cond_B でも wall が出るが、その callable は 7 件の issue で既に表現済みなので
    overview / カードに重複表示しない。
    """
    issue_callables = {iss.callable_name for iss in issues}
    return [w for w in walls if w.callable_name not in issue_callables]


def main() -> None:
    here = Path(__file__).parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("cond_a", nargs="?",
                    default=str(here / "results" / "cond_A_taint-output.json"))
    ap.add_argument("cond_b", nargs="?",
                    default=str(here / "results" / "cond_B_taint-output.json"))
    ap.add_argument("--out-dir", default=str(here / "results"),
                    help="出力ディレクトリ（デフォルト: results/）")
    ap.add_argument("--inline-mermaid", metavar="JS", default=None,
                    help="mermaid.min.js のパスを指定するとオフライン埋め込みになる")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    a_issues = parse_taint_json(args.cond_a)
    a_walls = _filter_walls(a_issues, parse_dispatch_walls(args.cond_a))
    b_issues = parse_taint_json(args.cond_b)
    b_walls = _filter_walls(b_issues, parse_dispatch_walls(args.cond_b))

    # cond_A レポート
    out_a = out_dir / "cond_A_report.html"
    out_a.write_text(render_report(
        a_issues, a_walls,
        title="TaintP2X M2 Verification — Condition A（lowering なし）",
        subtitle="素の AutoGPT agent.py （dispatch_lowering 適用前）を Pysa で解析（AutoGPT v0.5.0）",
        cond_note="lowering なし：dispatch 壁が Pysa に不透明なため sink 未到達",
        count_color="#4ade80" if not a_issues else "#f87171",
        findings_heading=f"Findings — cond_A（lowering なし）: {len(a_issues)} issue(s) / {len(a_walls)} wall(s)",
        inline_mermaid=args.inline_mermaid,
    ), encoding="utf-8")
    print(f"[render_m2_report] cond_A: {len(a_issues)} issue(s), "
          f"{len(a_walls)} wall(s) → {out_a}")

    # cond_B レポート
    out_b = out_dir / "cond_B_report.html"
    out_b.write_text(render_report(
        b_issues, b_walls,
        title="TaintP2X M2 Verification — Condition B（lowering あり）",
        subtitle="dispatch_lowering 適用後の AutoGPT agent.py を Pysa で解析（AutoGPT v0.5.0）",
        cond_note="lowering あり：dispatch 壁を展開することで Pysa が sink まで追跡",
        count_color="#f87171" if b_issues else "#4ade80",
        findings_heading=f"Findings — cond_B（lowering あり）全 {len(b_issues)} 件",
        inline_mermaid=args.inline_mermaid,
    ), encoding="utf-8")
    print(f"[render_m2_report] cond_B: {len(b_issues)} issue(s), "
          f"{len(b_walls)} wall(s) → {out_b}")


if __name__ == "__main__":
    main()
