"""Ground-truth labels for the Stage-4 evaluation harness (§5 / RQ1–RQ4).

IMPORTANT — read this honestly: the cases below are the project's *own* fixtures.
Scoring the tool against them is therefore **circular** — the analyzer was built
and debugged to pass exactly these files, so it will (and does) score perfectly.
This benchmark exists to exercise and demonstrate the *harness*; the metrics it
prints are not external validation. The point of the harness is that it is ready
to be pointed at a real, independently-labeled corpus by swapping ``BENCHMARK``
(or passing ``--fixtures`` at a directory with a matching labels file).

Each case lists the findings the tool is *expected* to produce, so the harness
can compute true/false positives and negatives at every pipeline stage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple


@dataclass(frozen=True)
class ExpectedFinding:
    sink: str                       # expected Finding.sink_name, e.g. "subprocess.run"
    kind: str                       # "implicit" | "explicit"
    should_be_pruned: bool = False  # True => a candidate that a §4.5 prune must remove
    triage: str = "true-positive"   # expected triage verdict when the finding is kept
    line: Optional[int] = None       # optional sink line for tighter matching


@dataclass(frozen=True)
class LabeledCase:
    filename: str                   # basename inside the fixtures directory
    framework: str                  # langchain | langgraph | mcp | openai-agents | none
    expected: Tuple[ExpectedFinding, ...] = ()
    note: str = ""


# The bundled (self-authored) benchmark.
BENCHMARK: Tuple[LabeledCase, ...] = (
    LabeledCase(
        "langchain_2tool_vuln.py", "langchain",
        (ExpectedFinding("subprocess.run", "implicit"),),
        "canonical cross-tool implicit flow",
    ),
    LabeledCase(
        "langchain_2tool_safe.py", "langchain",
        (),  # the control edge is cut by selective hiding -> no finding expected
        "negative: hidden source, no viable flow",
    ),
    LabeledCase(
        "langgraph_state_app.py", "langgraph",
        (ExpectedFinding("requests.get", "implicit"),),
        "single-function reducer + loop fixpoint",
    ),
    LabeledCase(
        "langgraph_multinode_app.py", "langgraph",
        (ExpectedFinding("subprocess.run", "implicit"),),
        "cross-node (inter-procedural) reducer",
    ),
    LabeledCase(
        "mcp_sdk_app.py", "mcp",
        (ExpectedFinding("cursor.execute", "implicit"),),
        "MCP call_tool -> create_message",
    ),
    LabeledCase(
        "openai_agents_app.py", "openai-agents",
        (ExpectedFinding("os.system", "implicit"),),
        "OpenAI Agents Runner",
    ),
    LabeledCase(
        "data_layer_verbatim.py", "none",
        (ExpectedFinding("subprocess.run", "explicit"),),
        "explicit (TITO) flow, not implicit",
    ),
    LabeledCase(
        "schema_pruned_app.py", "langchain",
        (ExpectedFinding("subprocess.run", "implicit", should_be_pruned=True),),
        "must be pruned by schema/channel-capacity (§4.5(2))",
    ),
    LabeledCase(
        "unreachable_sink_app.py", "langchain",
        (ExpectedFinding("subprocess.run", "implicit", should_be_pruned=True),),
        "must be pruned by reachability (§4.5(1))",
    ),
)
