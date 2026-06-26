# (C) on the REAL shell_gpt repo — what Pysa does, and the two real walls

Pyre/Pysa **0.9.25**, run here (not just designed). shell_gpt = `TheR1D/shell_gpt`
(raw OpenAI SDK function-calling loop; sink = `subprocess.Popen(shell_command, shell=True)`).

## Established by actually running Pysa

1. **Pysa leg executes and finds the flow on faithful, dependency-free repros**
   (see `recursion_demo/`): the bundled example (taint crosses UNMODELED
   helpers — inter-procedural for free); value-threaded inter-procedural +
   **recursion**; and the shared-mutable-history + recursion shape once the
   §4.3 history-append is modeled as a propagator (`Updates`). The (C)
   inter-procedural+recursion gap that defeated the standalone engine is closed.

## Two real walls on the LITERAL repo

2. **Operational cost (RQ3).** Pointing Pyre at shell_gpt + its real deps makes
   it type-check the whole closure; `openai` 2.x pulls **pydantic**, and Pyre
   stalls >100 s on a single `pydantic.json_schema` function. Running Pysa on a
   real heavy-dep agent is expensive — you must **stub the deps** (a few-line
   `openai` stub) to make analysis tractable. This is a concrete scalability
   caveat for the Pysa leg.

3. **Dynamic registry dispatch — a wall for BOTH engines.** Isolated test
   (stubbed, fast):

   | call shape | Pysa result |
   |---|---|
   | `execute(**dict_args)` (direct) | **1 issue** — source→sink found, `**kwargs` splat handled |
   | `get_function(name)(**dict_args)` (registry getter) | **0 issues** — NOT resolved |

   So `get_function(name)(...)` (shell_gpt's exact dispatch) is not resolved by
   Pysa's call graph out of the box. The model-chosen registry dispatch is
   precisely the §4.5/§6.1(b) "registry + join@LLM" situation — the part the
   proposal handles by **enumeration**, not pure dataflow. Plus the raw
   `messages.append({...})` history mutation needs the §4.3 bridge model (Pysa
   does not propagate `list.append` self-update by default), and builtin
   `list`/`subprocess` need typeshed wired in.

## Conclusion: a real repo is a HYBRID

shell_gpt needs **Pysa for the inter-procedural/recursion value flow** PLUS the
proposal's wiring models (exit alias resolves by type once `openai` is typed;
sink modeled in user code; §4.3 history bridge) PLUS the **enumeration / explicit
dispatch model** for the model-chosen `get_function(name)(...)` routing — because
dynamic registry dispatch defeats pure dataflow in *both* engines. This directly
motivates the proposal's dual (a Pysa dataflow + b enumeration) design and shows
a single real repo can require both legs at once.

## Concrete next steps to make the literal repo fire end-to-end
* keep the `openai` stub (avoids the pydantic type-check stall);
* model the exit (`openai...Completions.create` → `TaintInTaintOut[Via[llm_node]]`)
  and the sink (`ExecuteShell.execute(shell_command)` param, or `subprocess.Popen`
  once typeshed is wired);
* model the §4.3 bridge: `Handler.handle_function_call`'s `messages` param as
  `Updates`, or a `list.append` collection model;
* resolve the dispatch: either an explicit model for `get_function`'s returned
  callable, or hand the `get_function(name)(...)` site to ctaudit's enumeration /
  dispatch-recognition (the standalone engine's part-B already flags it).
