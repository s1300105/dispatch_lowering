"""Framework-managed dispatch benchmark (項目1 — effect demonstration).

This harness measures, on a controlled by-construction set, what the declarative
``DispatchSpec`` (項目1) adds: the ability to recover cross-tool implicit flows
(CWE-1426) from agents whose tool dispatch is **managed by the framework** and is
therefore invisible to a syntactic scan of user code.

It demonstrates three things:

  (1) Framework registration shapes — create_react_agent / create_agent /
      AgentExecutor, launched by .invoke / .stream — each have their dispatch wall
      detected and resolved to the concrete dangerous sink.
  (2) A SAFE framework agent (no dangerous tool registered) yields no flow: the
      wall is detected but resolves to nothing (no over-reporting).
  (3) Manual-loop vs framework PARITY: the same threat written as a hand-written
      dispatch loop (visible wall) and as a framework-managed agent (hidden wall)
      is detected in BOTH — the framework version is what a syntactic-only scan
      misses, and 項目1 recovers it.

Detection uses the SAME end-to-end pipeline a user runs (the heuristic tool-model
classifier, then resolve_dispatch), so the numbers reflect the shipped behaviour,
not a hand-fed model.  ``via_framework`` marks flows recovered through a framework
DispatchSpec (the launch site carries ``framework_candidates``); ``via_syntactic``
marks flows from a wall visible in user code.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ctaudit import analyze_path
from ctaudit.analysis import resolve_dispatch
from ctaudit.toolmodel import get_classifier

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_CAT = {"exec": "code_execution"}


def _norm(c: str) -> str:
    return _CAT.get(c, c)


@dataclass(frozen=True)
class Case:
    fixture: str
    kind: str                 # "framework" | "manual" | "safe"
    expect_sink: Optional[str]    # the dangerous tool/sink expected, or None for safe
    expect_category: Optional[str]
    note: str


# By-construction cases.  The manual/framework pair encodes the SAME threat
# (fetch untrusted page -> model -> run a shell command) two ways.
CASES: List[Case] = [
    # (1) framework registration shapes, each a real cross-tool implicit flow
    Case("langgraph_react_agent.py", "framework", "run_cmd", "code_execution",
         "create_react_agent + .invoke"),
    Case("langchain_agentexecutor_vuln.py", "framework", "run_shell", "code_execution",
         "AgentExecutor + .invoke"),
    Case("langchain_create_agent_stream_vuln.py", "framework", "exec_python", "code_execution",
         "create_agent + .stream"),
    # (2) safe framework agent: wall detected, but no dangerous tool registered
    Case("langgraph_react_agent_safe.py", "safe", None, None,
         "create_react_agent, only benign tools"),
    # (3) manual-loop counterpart of the same threat (visible wall in user code)
    Case("langchain_2tool_vuln.py", "manual", "subprocess.run", "code_execution",
         "hand-written dispatch loop (baseline)"),
]


@dataclass
class Result:
    case: Case
    wall_detected: bool          # was a dispatch wall recorded at all?
    via_framework: bool          # did the wall carry framework_candidates?
    resolved_sink: Optional[str]
    resolved_category: Optional[str]
    correct: bool


def _run(case: Case) -> Result:
    path = str(FIXTURES / case.fixture)
    findings = [f for f in analyze_path(path).findings if not getattr(f, "pruned", False)]

    wall = [f for f in findings if f.kind == "dispatch"]
    wall_detected = bool(wall)
    via_framework = any(getattr(f, "framework_candidates", ()) for f in wall)

    # end-to-end: build the tool model with the shipped heuristic classifier.
    mdl = get_classifier("heuristic").classify(path)
    resolved = [f for f in resolve_dispatch(findings, mdl, repo=path)
                if f.kind in ("implicit", "explicit")]
    sink = cat = None
    if resolved:
        # report the (first) dangerous resolved sink
        f0 = resolved[0]
        sink, cat = f0.sink_name, _norm(f0.sink_category)

    if case.kind == "safe":
        correct = (sink is None)
    else:
        correct = (sink == case.expect_sink and cat == case.expect_category)
    return Result(case, wall_detected, via_framework, sink, cat, correct)


def evaluate() -> List[Result]:
    return [_run(c) for c in CASES]


def main(argv=None) -> int:
    results = evaluate()

    print("framework-managed dispatch benchmark (項目1 — by-construction)\n")
    hdr = f"{'fixture':40} {'kind':10} {'wall':5} {'via-fw':6} {'resolved sink':22} {'ok'}"
    print(hdr)
    print("-" * len(hdr))
    for r in results:
        wall = "yes" if r.wall_detected else "no"
        fw = "yes" if r.via_framework else "-"
        rs = (f"{r.resolved_sink} ({r.resolved_category})"
              if r.resolved_sink else "(none)")
        ok = "ok" if r.correct else "DIFF"
        print(f"{r.case.fixture:40} {r.case.kind:10} {wall:5} {fw:6} {rs:22} {ok}")

    # headline numbers
    fw_cases = [r for r in results if r.case.kind == "framework"]
    fw_ok = sum(r.correct for r in fw_cases)
    fw_recovered = sum(r.via_framework and r.correct for r in fw_cases)
    safe_cases = [r for r in results if r.case.kind == "safe"]
    safe_ok = sum(r.correct for r in safe_cases)
    manual = [r for r in results if r.case.kind == "manual"]
    manual_ok = sum(r.correct for r in manual)
    total_ok = sum(r.correct for r in results)

    print(f"\nframework shapes detected & resolved : {fw_ok}/{len(fw_cases)} "
          f"(all via framework DispatchSpec: {fw_recovered}/{len(fw_cases)})")
    print(f"safe agent — no false flow           : {safe_ok}/{len(safe_cases)}")
    print(f"manual-loop baseline (visible wall)  : {manual_ok}/{len(manual)}")
    print(f"overall correct                      : {total_ok}/{len(results)}")

    # the differentiation statement, spelled out
    print("\nparity (same threat, two encodings):")
    print("  manual  langchain_2tool_vuln.py        -> "
          + ("detected" if manual_ok else "MISSED"))
    print("  framework langgraph_react_agent.py     -> "
          + ("detected (recovered by 項目1)" if fw_cases[0].correct else "MISSED"))
    print("  => a syntactic-only scan sees the manual wall but not the framework"
          " one; 項目1 recovers the framework case.")
    return 0 if total_ok == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
