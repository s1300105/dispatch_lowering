# Real-Repository Check (方向A + 方向B)

How ctaudit behaves on **real, third-party** LangChain/LangGraph agent code across
several writing styles, after 項目1 (framework `DispatchSpec`) and 方向B (known
dangerous library-tool registry).

All targets live in `realworld/`, are faithful transcriptions of public repositories
for **static analysis only** (never executed), and trim only boilerplate (prompt
text, comments) — the tool definitions and the agent construction/launch are kept as
published. The judgement criterion is **flow reachability** (does source → LLM →
dangerous tool connect in the code?), not whether the code is an exploitable
vulnerability.

## Four real cases, four writing styles — all resolve

| target (public source) | tool style | tool list | sink location | wall | resolves to |
|---|---|---|---|---|---|
| `dylancastillo_react_exec.py` (dylancastillo.co) | `@tool` | variable | user code (`exec`) | yes | `run_python_code` (code_exec) |
| `langgraph_supervisor_style.py` (langgraph-supervisor-py) | **undecorated** plain fns | literal | user code (`os.popen`) | yes | `run_command` (code_exec) |
| `botextract_react_agent.py` (botextractai/ai-langchain-react-agent) | `Tool()` wrapper | variable | **library** (`PythonAstREPLTool`) | yes | `python_repl_tool` (code_exec) |
| `a2a_calculator_basetool.py` (python-a2a docs) | **class** `BaseTool` (`_run`/`_arun`) | literal | user code (`eval`) | yes | `calculator` (code_exec) |

A fifth target, `maxscheijen_dict_registry.py` (a hand-written no-framework agent on
the raw OpenAI SDK), is **partially handled** — the wall is now detected via 1-hop
cross-method propagation, but stays unresolved; see below.

Run end-to-end with `python3 hybrid.py realworld/<file>.py`.

## What this shows

**The framework wall is detected in all three cases**, across `@tool`-decorated
functions, **undecorated** plain functions, and `Tool(...)`-wrapped tools, with the
tool list given as a literal or bound to a variable. A scan that only looks for a
syntactic `TOOL_MAP[name]()` in user code would miss every one.

**All three now resolve to the concrete dangerous sink** — including the
library-internal one, after 方向B.

### The three grounding situations, and how each is handled

1. **Sink in a `@tool` body (user code).** `dylancastillo_react_exec.py` — the
   classifier reads `exec(code, ...)` in the tool body. Resolved directly.

2. **Sink in an UNDECORATED function (user code).** `langgraph_supervisor_style.py`
   — a plain function with `os.popen(cmd)`, registered via `create_react_agent`.
   Handled by treating **framework registration as a tool-ness signal** (a function
   named in `tools=[...]` is a tool even without `@tool`). In scope for 項目1 (uses
   the framework's *declared* tool set).

3. **Sink in a LIBRARY tool (not in user code).** `botextract_react_agent.py` — the
   dangerous `exec` lives inside LangChain's `PythonAstREPLTool`. Handled by 方向B:
   a small **declarative registry of known dangerous library tools** (keyed by class
   name) supplies the sink semantics. The classifier resolves the construction chain
   (`python_repl_tool = Tool(func=python_repl.run)` → `python_repl =
   PythonAstREPLTool()` → known code-execution sink) and grounds it.

4. **Sink in a class-based `BaseTool` (user code).** `a2a_calculator_basetool.py` — a
   `BaseTool` subclass with `eval(query)` in its `_run` method, plus an async
   `_arun` that delegates to `_run`. The classifier already recognises tool classes;
   the wrinkle this real case exposed is that a class with **both** `_run` and
   `_arun` was emitting the tool twice (one ToolSpec per method), producing duplicate
   findings. A `BaseTool` subclass is a single tool, so tool methods are now deduped
   by the resulting tool name within each class (preferring the sink-bearing, sync
   method) — exactly one `calculator` finding results. 方向C marks the argument as
   reaching, since `eval(query)` passes the parameter straight through.

## 方向B — known dangerous library-tool registry (this round)

Real agents frequently register prebuilt tools whose dangerous operation lives inside
the library, not in user code (`PythonAstREPLTool`, `ShellTool`, `PythonREPL`,
`BashProcess`, …). A body scan of the analysed file cannot ground these. 方向B adds a
**declarative table** (class name → sink category), the same philosophy as the
framework `DispatchSpec`: plain data, extends by appending rows, no engine change.
The classifier resolves the common construction chains:

- `x = PythonAstREPLTool()` (direct constructor)
- `r = PythonAstREPLTool(); x = Tool(func=r.run)` (variable + wrapper)
- `x = Tool(func=ShellTool().run)` (inline-constructor wrapper)

and emits a sink ToolSpec **only for variables actually registered with an agent**,
so a dangerous tool that is constructed but never given to an agent is not flagged.

### Safety check (no over-reporting)

`fixtures/langgraph_react_agent_safe.py` registers only benign tools (`fetch_url`,
`echo`). 方向B does not flag them (they are not in the registry), so the safe agent
still yields **no flow** — the wall is detected but resolves to nothing.

## A fifth pattern — partially closed (dict-registry on the raw OpenAI SDK)

`maxscheijen_dict_registry.py` (transcribed from a public blog) is a hand-written
agent with **no framework**: it builds a tool registry as a dict
(`self.tool_mapping = {t.__name__: t for t in self.tools}`) and dispatches with
`self.tool_mapping[name](**args)`, driving the loop with the raw OpenAI SDK
(`client.chat.completions.create(...)`), with the LLM call in `run()` and the manual
dispatch wall in a separate `call_tool()` method.

This case originally produced **no finding at all**. After the 1-hop cross-method
control seeding (below), the **dispatch wall is now detected**: the control mark born
at the LLM call in `run()` is propagated into the `call_tool()` parameter, so the
manual `tool_mapping[name](...)` wall is recorded. It remains **unresolved**, because
the tools are plain functions registered through a hand-written `Agent(tools=[...])`
dataclass (not `@tool` / `BaseTool` / a framework factory), so the classifier
recognises no sink tool to resolve the wall against. The status moved from
*"invisible"* to *"wall detected, unresolved"* — partial, honest progress.

### 1-hop cross-method propagation (項目1, recall-safe)

Two recall-safe, single-hop cross-method improvements were added. Both only ADD wall
detection (never remove or narrow a flow), and both are bounded to one hop between
methods of the same module:

1. **Instance-attribute agent bindings.** `self.agent = create_react_agent(...)` in
   `__init__` and `self.agent.invoke(...)` in another method now connect: the factory
   binding is recorded in a module-scoped registry keyed by the attribute name, so a
   launch on `self.<attr>` in any method resolves to the registration.
   (`fixtures/method_split_framework.py`.)

2. **Manual-dispatch control seeding.** When a method that contains an LLM call passes
   a control-derived value (a for-loop variable over the LLM result) to a sibling
   method `self._helper(v)`, the helper's corresponding parameter is seeded with a
   control mark, so a manual `dict[name](...)` wall inside the helper is recorded.
   (`fixtures/method_split_manual.py`.)

These deliberately do NOT attempt full inter-procedural analysis (which would
undermine the recall-first discipline and the ability to state soundness precisely);
they are a single, conservative hop, and a benign dynamic dispatch in a helper is
still only surfaced as an *unresolved* wall (it resolves to no dangerous sink). The
remaining `maxscheijen` gaps — recognising hand-written `Agent(tools=[...])`
registration, and the raw-SDK source/exit specifics — are separate, and left as
future work.

## Scope and honest limitations

- These are a handful of transcribed public repos, analysed statically. They are
  illustrative real-world data points, **not** a measure of recall (which is not
  measurable as a whole on real repos — see the project's evaluation notes).
- The known-tool registry is **manual and version-dependent** (like the framework
  specs): a dangerous library tool not in the table is still missed.
- 方向B is a **recall** improvement (grounds more true sinks). It does NOT address
  the over-approximation that an argument may be sanitised inside the tool before
  reaching the dangerous call — that is the separate precision direction (方向C).
- TP here means "the source → LLM → dangerous-tool flow connects in the code,"
  judged by reading the code — not "exploitable vulnerability."
