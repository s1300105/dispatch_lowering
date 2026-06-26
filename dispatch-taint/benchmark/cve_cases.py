"""Curated CVE subset for comparison against TaintP2X (ICSE'26, Table 2).

WHY A SUBSET. TaintP2X's 35-vuln ground truth is dominated by the single-hop
prompt -> LLM -> sink pattern (a chain/query/text-to-SQL exec's the model's output).
ctaudit targets a different regime: **multi-tool agents** where an upstream tool's
output influences a downstream sink *through the model's decision* (cross-tool implicit
flow), and especially where the model's output selects *which* tool runs (dynamic
dispatch / tool registry) — the case TaintP2X lists as a limitation. We therefore
evaluate on the multi-tool-agent subset of that ground truth, and report the single-hop
cases as explicitly out of scope (we do not claim them).

HONESTY / PRE-REGISTRATION. The `scope` and `in_scope` fields below are *hypotheses set
before inspecting each repository*. The runner (`benchmark/cve_bench.py`) is empirical: it
reports what ctaudit actually detects. Final paper claims must follow (a) the empirical
run on the vulnerable versions and (b) a code inspection confirming the mechanism. The
`taintp2x` column reproduces the detected/missed result from TaintP2X Table 2 (Y =
detected, N = missed, "-" = not analyzed by that tool); `baseline` notes the LLMSmith /
AgentFuzz results where relevant.

VERSIONS / SLUGS may need adjustment on checkout (tags moved, some repos are commit- not
tag-versioned). Treat `ref`/`repo` as starting points to verify, not ground truth.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class CVECase:
    cve: str                 # CVE id (or huntr id)
    repo: str                # github "owner/name"
    ref: str                 # vulnerable tag / version / commit (verify on checkout)
    vuln_type: str           # paper's category
    sink_category: str       # ctaudit category: code_execution|sql|file_write|network
    scope: str               # HYPOTHESIS: dynamic_dispatch | cross_tool | single_hop
    in_scope: bool           # whether ctaudit *claims* to target this case
    taintp2x: str            # TaintP2X Table 2 result: Y | N | "-"
    baseline: str            # LLMSmith / AgentFuzz note
    src_rel: Optional[str]   # package subdir to analyse (None = repo root)
    note: str


# ---- in-scope: multi-tool agents / dynamic dispatch (ctaudit's regime) --------------- #
IN_SCOPE = [
    CVECase("CVE-2024-1881", "Significant-Gravitas/AutoGPT", "v0.5.0",
            "code_injection", "code_execution", "dynamic_dispatch", True,
            taintp2x="N", baseline="LLMSmith N, AgentFuzz Y", src_rel=None,
            note="HEADLINE: TaintP2X missed it. AutoGPT dispatches commands by name from a "
                 "command registry (execute_python_*). Verify the registry/dispatch site; "
                 "tag/path may live under autogpts/autogpt/."),
    CVECase("CVE-2024-23750", "geekan/MetaGPT", "v0.6.3",
            "code_injection", "code_execution", "cross_tool", True,
            taintp2x="Y", baseline="LLMSmith N", src_rel="metagpt",
            note="Multi-agent framework with tool use; confirm ctaudit also detects (parity "
                 "with TaintP2X) on a cross-tool exec path."),
    CVECase("CVE-2025-2733", "FoundationAgents/OpenManus", "main",
            "code_injection", "code_execution", "dynamic_dispatch", True,
            taintp2x="Y", baseline="LLMSmith N, AgentFuzz N", src_rel="app",
            note="Tool-using agent (formerly mannaandpoem/OpenManus). Both dynamic baselines "
                 "failed to build/run it; ctaudit is static so this is a good fit. Pin to the "
                 "advisory's commit/date 2025.3.13."),
    CVECase("HUNTR-Superagi-0.0.14", "TransformerOptimus/SuperAGI", "v0.0.14",
            "file_write", "file_write", "cross_tool", True,
            taintp2x="Y", baseline="AgentFuzz N", src_rel="superagi",
            note="Agent tool registry incl. a file-write tool; read-then-write across tools "
                 "via the model. No CVE (public huntr disclosure)."),
    CVECase("CVE-2024-5927", "stitionai/devika", "main",
            "file_write", "file_write", "cross_tool", True,
            taintp2x="Y", baseline="AgentFuzz N", src_rel=None,
            note="Agentic SWE assistant; file read/write via agent actions. Devika is "
                 "commit-versioned — checkout the commit referenced by the NVD/huntr advisory."),
    CVECase("CVE-2024-5821", "stitionai/devika", "main",
            "file_write", "file_write", "cross_tool", True,
            taintp2x="Y", baseline="AgentFuzz N", src_rel=None,
            note="Same repo as CVE-2024-5927; distinct file-operation path."),
    CVECase("CVE-2024-6331", "stitionai/devika", "main",
            "file_write", "file_write", "cross_tool", True,
            taintp2x="Y", baseline="AgentFuzz N", src_rel=None,
            note="Same repo; distinct file-operation path."),
]

# ---- out-of-scope: single-hop prompt->LLM->sink (listed for transparency, NOT run) ---- #
OUT_OF_SCOPE = [
    CVECase("CVE-2023-36258", "langchain-ai/langchain", "v0.0.236",
            "code_injection", "code_execution", "single_hop", False,
            taintp2x="Y", baseline="LLMSmith Y", src_rel=None,
            note="PALChain/LLMMathChain exec of model output — single hop, not cross-tool."),
    CVECase("CVE-2023-39659", "langchain-ai/langchain", "v0.0.232",
            "code_injection", "code_execution", "single_hop", False,
            taintp2x="N", baseline="LLMSmith Y", src_rel=None,
            note="TaintP2X missed, but single-hop chain exec — outside ctaudit's cross-tool claim."),
    CVECase("CVE-2023-39660", "sinaptik-ai/pandas-ai", "v0.8.0",
            "code_injection", "code_execution", "single_hop", False,
            taintp2x="Y", baseline="LLMSmith Y", src_rel=None,
            note="PandasAI runs model-generated code — single hop."),
    CVECase("CVE-2024-5565", "vanna-ai/vanna", "v0.3.1",
            "code_injection", "code_execution", "single_hop", False,
            taintp2x="Y", baseline="LLMSmith Y, AgentFuzz Y", src_rel=None,
            note="Text-to-SQL/plotly exec — single hop."),
    CVECase("CVE-2024-23751", "run-llama/llama_index", "v0.9.28.post2",
            "sql", "sql", "single_hop", False,
            taintp2x="N", baseline="-", src_rel=None,
            note="NLSQL query — single hop; TaintP2X missed."),
    CVECase("CVE-2023-32786", "langchain-ai/langchain", "v0.0.327",
            "ssrf", "network", "single_hop", False,
            taintp2x="N", baseline="-", src_rel=None,
            note="SSRF via chain — single hop; TaintP2X missed."),
]

ALL_CASES = IN_SCOPE + OUT_OF_SCOPE
