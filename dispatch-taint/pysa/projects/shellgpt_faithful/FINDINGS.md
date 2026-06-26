# shell_gpt structure, lit END-TO-END on Pysa (faithful, dependency-light)

Run from `pysa/projects/shellgpt_faithful/`:
```
pyre analyze --save-results-to ./res && python ../../postprocess.py ./res
```
Result: **Pysa finds 1 cross-tool flow end-to-end** — source (`execute_shell`
return = attacker-influenceable tool output) → shared history → aliased LLM call
→ model response → registry dispatch → `execute_shell(shell_command)` sink. The
recursive fixpoint converges over `get_completion` (iterations #1→#4).

This is shell_gpt's real structure: aliased `completion = client.chat.completions.create`,
`get_function(name)(...)` registry dispatch, tool output appended to a shared
`messages` history, re-entry by recursion, `subprocess`-class shell sink.

## What it took (the RQ4 wiring cost), and Pyre's exact resolution boundaries

Established by controlled experiments (each isolated):

| element | Pysa behavior | needed |
|---|---|---|
| aliased LLM call `completion(...)` | **resolved by type** to `Completions.create` | model the real method (TITO `Via[llm_node]`) |
| registry dispatch `get_function(name)(...)` | **if/return getter: resolved**; **dict-subscript getter: NOT**; **@classmethod tool: NOT** | resolvable getter, else model/enumerate the dispatch |
| `**kwargs` splat, `json.loads`, deep attr chain, response iteration, dict-wrap list-concat | all **propagate taint** | nothing |
| inter-procedural + **recursion** (value-threaded history) | **handled automatically** (fixpoint) | nothing |
| history append | value-threaded: auto; **in-place `list.append`/mutation: needs §4.3 bridge model** (`Updates`), and does NOT cross intermediate wrapper fns | model the append primitive |
| heavy deps (openai→pydantic) on the LITERAL repo | Pyre **stalls** type-checking pydantic | stub the deps |

## The 3 walls that need a model (everything else is free)
1. **dict-subscript / @classmethod dispatch** — Pyre's higher-order call graph
   does not resolve `get_function(name)(...)` when the getter is a dict lookup
   or returns a `@classmethod`. shell_gpt's `Function.execute` is a classmethod,
   so its dispatch must be modeled or handed to the enumeration leg (b) /
   ctaudit's standalone dispatch recognition (part-B).
2. **in-place history mutation across wrappers** — `messages.append(...)` in a
   helper does not propagate back to the caller without an `Updates` model on the
   append primitive (the §4.3 bridge); value-threading avoids it.
3. **heavy-dep type-check cost** — stub deps for tractable analysis (RQ3 caveat).

## One remaining wrinkle: implicit-vs-explicit TAGGING — NOW FIXED (option a)
The flow is **found**, but was initially tagged *data-layer/explicit*: the
`llm_node` breadcrumb attached at the LLM-call TITO **drops over the long
projection chain** `response → choices[0].message.tool_calls[0].function.arguments
→ json.loads → **splat → sink` (Pysa `tito-broadening`), and the aliased
`completion(...)` call is even `obscure:unknown-callee` so the model's breadcrumb
never attaches. Detection was sound; only the implicit/explicit label degraded.

**Fix implemented in `postprocess.py`:** classify a flow as implicit by a
layered rule —
1. `llm_node` breadcrumb present → implicit (precise, unchanged); else
2. **structural**: does any callable on the flow's trace (`resolves_to` callees
   + the issue callable) invoke a function modeled as an LLM node? The LLM-node
   names are parsed from the `.pysa` models; aliased calls
   (`completion = client.chat.completions.create`) are resolved with the same
   binding resolver the standalone engine uses (§6.4 part-A).

Result (verified, no regression):
* faithful shell_gpt structure → **CROSS-TOOL IMPLICIT FLOW (CWE-1426)** ✓
  (passes `--implicit-only`)
* bundled example, recursion_demo value_threaded → still IMPLICIT (breadcrumb) ✓
* a true verbatim flow with NO LLM node on the path → still EXPLICIT (the
  structural check does not over-fire) ✓

