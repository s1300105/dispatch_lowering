# 項目1 Evaluation — Framework-Managed Dispatch (方向A)

This documents the controlled, by-construction evaluation of 項目1 (the declarative
`DispatchSpec`): recovering cross-tool implicit flows (CWE-1426) from agents whose
tool dispatch is **managed by the framework** and therefore invisible to a
syntactic scan of user code.

Run it with:

    python3 benchmark/framework_dispatch_bench.py

Detection uses the **same end-to-end pipeline a user runs** — the heuristic
tool-model classifier, then `resolve_dispatch` — so the numbers reflect shipped
behaviour, not a hand-fed model.

## Result

```
fixture                                  kind       wall  via-fw resolved sink             ok
------------------------------------------------------------------------------------------
langgraph_react_agent.py                 framework  yes   yes    run_cmd (code_execution)  ok
langchain_agentexecutor_vuln.py          framework  yes   yes    run_shell (code_execution) ok
langchain_create_agent_stream_vuln.py    framework  yes   yes    exec_python (code_execution) ok
langgraph_react_agent_safe.py            safe       yes   yes    (none)                    ok
langchain_2tool_vuln.py                  manual     no    -      subprocess.run (code_execution) ok

framework shapes detected & resolved : 3/3 (all via framework DispatchSpec: 3/3)
safe agent — no false flow           : 1/1
manual-loop baseline (visible wall)  : 1/1
overall correct                      : 5/5
```

## What each row shows

- **`wall`** — was a dispatch wall recorded at all?
- **`via-fw`** — did the wall carry `framework_candidates` (i.e. it was recovered
  through a framework `DispatchSpec`, not a syntactic `TOOL_MAP[name]()` in user
  code)?
- **`resolved sink`** — the concrete dangerous tool the wall resolved to (end-to-end).

## The three claims, demonstrated

1. **Framework registration shapes are detected and resolved (3/3).**
   Three different real LangChain/LangGraph shapes — `create_react_agent` + `.invoke`,
   classic `AgentExecutor` + `.invoke`, and new `create_agent` + `.stream` — each
   have their hidden dispatch wall detected and resolved to the concrete
   code-execution sink. All three are recovered *through the framework DispatchSpec*
   (`via-fw = yes`), i.e. they would be invisible to a scan that only looks for a
   syntactic dispatch in user code.

2. **A safe framework agent produces no false flow (1/1).**
   `langgraph_react_agent_safe.py` uses the *same* `create_react_agent` + `.invoke`
   wiring but registers only benign tools (`fetch_url`, `echo`). The wall is still
   detected (`wall = yes`), but because no dangerous tool is reachable it resolves
   to nothing (`resolved sink = (none)`). Detecting the wall is not enough to raise
   a flow — a dangerous tool must actually be reachable. This guards against
   over-reporting.

3. **Manual-loop vs framework parity — the differentiation evidence.**
   `langchain_2tool_vuln.py` encodes the *same* threat (fetch an untrusted page →
   model → run a shell command) as a **hand-written dispatch loop**, whose wall is
   visible in user code (`via-fw = -`, recovered by the pre-existing syntactic
   path). Its framework-managed counterpart `langgraph_react_agent.py` hides the
   wall inside LangGraph's ToolNode. **Both are detected.** A syntactic-only scan
   sees the manual wall but not the framework one; 項目1 recovers the framework
   case — which is the encoding the majority of real agents actually use.

## Scope and honest limitations (unchanged by this evaluation)

- This is a **controlled, by-construction** benchmark with exact ground truth. It
  shows the mechanism works on the framework shapes it models; it is not a measure
  of real-world recall (which, on real repos, is not measurable as a whole — see
  the project's evaluation notes).
- **LangChain/LangGraph only.** MCP / OpenAI Agents dispatch specs are not yet
  modelled (future work, 方向B).
- The framework specs are **manual and version-dependent** (the registration and
  launch APIs are fixed per framework version).
- Tool-internal argument flow is **not** analyzed: a tool is treated as a sink when
  its body contains a dangerous call, regardless of whether the dispatched argument
  actually reaches it (over-approximation, recall-first). Tightening this is the
  separate precision direction (方向C).
