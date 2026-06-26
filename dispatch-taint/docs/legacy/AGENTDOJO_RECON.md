# AgentDojo connection — reconnaissance & baseline (option う → あ)

Static-only feasibility study of connecting ctaudit to **AgentDojo** (Debenedetti
et al., 2024; 97 user tasks, 629 security cases; banking / Slack / travel /
workspace). AgentDojo 0.1.35 installed for source inspection.

## 1. Architecture (confirmed by reading the source)

- **Pipeline**: `AgentPipeline([system_message, init_query, llm, tools_loop])` with
  `tools_loop = ToolsExecutionLoop([ToolsExecutor(...), llm], max_iters=15)`.
  Each element exposes `.query(query, runtime, env, messages, extra_args)`.
- **LLM call**: a separate pipeline element (`agent_pipeline/llms/*_llm.py`).
- **Dispatch wall**: `FunctionsRuntime.run_function` in `functions_runtime.py`:
  ```python
  f = self.functions[function]      # line 275: dict-registry lookup by LLM-chosen name
  ...
  return f(**kwargs_with_deps), None # line 305: the call (the wall)
  ```
  `self.functions` is populated by `register_function` (`self.functions[name] = f`);
  a suite is built as `TaskSuite("banking", Env, [make_function(t) for t in TOOLS])`.
- **Tools**: plain functions with `Annotated[X, Depends("...")]` params, e.g.
  `def send_money(account: Annotated[BankAccount, Depends("bank_account")], recipient,
  amount, subject, date)`. Listed in a module-level `TOOLS = [...]`.

### Key structural fact
The wall is the **textbook `REGISTRY[llm_choice]()` dict-registry** — the exact
shape ctaudit's core targets — but it lives in **library code**, the LLM call is in
a **different pipeline element / file**, and the lookup is **indirected through a
local** (`f = self.functions[name]; f(...)`), not a direct `REGISTRY[name](...)`.

## 2. Sink question — RESOLVED: no syntactic sinks anywhere

Swept every tool module under `default_suites/v1/tools/` for
`subprocess|os.system|exec|eval|open|requests|Popen|socket|pickle|yaml.load|smtplib`:
**zero hits.** Every tool only mutates simulated internal state:
- `send_money` / `schedule_transaction` → `account.transactions.append(Transaction(...))`
- `read_file` → `filesystem.files.get(file_path, "")`
- `web.py` "requests" → `web.web_requests.append(url)` (not a real HTTP call)

Danger is **domain-semantic** (sending money, changing a password, exfiltrating
data), not syntactic. ⇒ ctaudit's current sink detection (dangerous call in the
body) will NOT classify these. A **方向B-style domain-tool declaration** is required
(declare `send_money`, `update_password`, `send_email`, … as sinks).

## 3. Source question — RESOLVED: tool-output marking suffices

- Attacker strings live in external YAML (`data/suites/banking/injection_vectors.yaml`,
  e.g. `injection_bill_text` carrying a fake transfer instruction); environment data
  (transaction history) loads from `environment.yaml`.
- Tools like `get_most_recent_transactions` **return that environment data** to the
  LLM — i.e. their return value is the tool-output source.

So the "this tool output is attacker-influenceable" mark can be attached **statically
from the tool definition** (fits ctaudit's `match_result_source`); the YAML *contents*
need not be known. ctaudit's claim is *flow reachability* (tool-output → LLM →
dangerous tool exists in code), not "which injection string fires" (that is
AgentDojo's dynamic GT). ⇒ source identification is **static-feasible**; (C) survives.

## 4. Baseline — current behaviour BEFORE any change ("zero point")

| target | result | why |
|---|---|---|
| `functions_runtime.py` | 0 findings | LLM call is in another file; wall is `f = REGISTRY[name]; f(...)` (indirected), not detected |
| `banking/task_suite.py` | 0 findings | tools via `make_function`; no LLM / dispatch in this file |
| `banking_client.py` | 0 findings, tools=[] | plain undecorated functions, no syntactic sink → nothing recognised |

Precise gaps observed in output:
1. **Indirected wall not detected.** `_is_dynamic_callee` fires only on a subscript
   *directly* in callee position; `f = self.functions[name]; f(...)` is missed (the
   `f` Name call is not recognised as dynamic). Confirmed on a 6-line repro.
2. **Tool recognition = 0.** Undecorated functions registered via `make_function` /
   a `TOOLS` list are not recognised as tools.
3. **Sink judgement = 0.** No syntactic sink, so even a recognised tool would not be
   a sink without a domain declaration.

## 5. Verdict — GO for (あ), declaratively (no library penetration)

- The 629 cases are a **dynamic GT** (attack success / utility), **NOT** a static
  flow GT. We do **not** use them as a denominator for flow recall/precision
  (category error). AgentDojo value is reframed as **(A) applicability demo**,
  **(B) domain-tool sinks**, **(C) static⇔dynamic coverage** — never "flow
  recall/precision on 629".
- The wall, candidate set, and source can all be supplied **declaratively** (an
  "AgentDojo runtime spec": `run_function` as the wall, each suite's `TOOLS` as the
  candidate set, tool returns as sources). This **bypasses the cross-file / indirected
  flow** the same way the LangChain DispatchSpec bypassed `create_react_agent`
  internals — so the recall-safe **1-hop limit is NOT broken**.

### (あ-1) minimal-implementation scope (one domain: banking)
1. **AgentDojo runtime DispatchSpec** — declare `run_function` as the wall; recover
   the candidate set from a suite's `TOOLS` list.
2. **Domain-tool sink declaration** — extend the known-tool table with AgentDojo
   domain sinks (`send_money`, `update_password`, …).
3. **Tool-output source declaration** — mark banking tool returns as sources.
Goal: on the banking suite (or a minimal fixture mirroring its structure), detect
"tool-output source → LLM → dangerous tool (send_money)" and resolve the wall.

## 6. Notes
- `pip install agentdojo` pulled `click 8.4.1`, conflicting with `pyre-check<8.2.0`.
  ctaudit's Pysa-port leg depends on pyre-check, so the implementation phase may need
  a **separate environment**. Does not block static reconnaissance.

## 7. (あ-1) RESULT — applicability achieved on REAL AgentDojo code

The minimal implementation is in place and **resolves on the real AgentDojo source**
(not only a fixture). Opt-in via `--agentdojo` / `hybrid.run(..., agentdojo=True)`.

### What was added (all opt-in, additive, recall-safe)
- `ctaudit/models/agentdojo.py`: a DispatchSpec (`FunctionsRuntime(TOOLS)` factory,
  `.run_function` wall) + 16 declared domain sinks (`send_money`, `update_password`,
  `send_email`, …) + a tool-output source list (`get_most_recent_transactions`, …).
- `toolmodel/classify.py`: `agentdojo` flag; `_framework_registered_tool_names`
  extended to `FunctionsRuntime` / `TaskSuite[...]` (incl. the
  `[make_function(t) for t in TOOLS]` comprehension); a name-based domain
  sink/source override; and **registration-only grounding** (a tool registered in
  the suite file is grounded from the declared tables even when its definition lives
  in another module — the sink-ness comes from the name, not the body).
- `analysis/taint_engine.py`: an **AgentDojo runtime presumption** — `run_function`
  is AgentDojo's fixed dispatcher whose receiver (the runtime) is created elsewhere
  and passed in, so the wall is presumed on any `.run_function` launch even when the
  receiver is an unbound parameter (an empty candidate set is intentional; resolution
  falls back to the model's declared sinks, recall-first).
- A subscripted-generic callee unwrap (`TaskSuite[Env](...)`).

### The three gaps, resolved per the planned 2 steps
- **Gap 3 (bug — subscripted callee):** fixed with `_callee_final_name` (unwraps
  `Generic[...]`). Required first so the other gaps could be seen clearly.
- **Gap 2 (tool def vs registration in different files):** **vanished** once Gap 3
  was fixed. Because sink-ness is supplied by the declared name tables, grounding
  needs only the suite file's `TOOLS` registration, not the definition file. The
  banking suite file now grounds `send_money` / `update_password` / … as sinks and
  `get_most_recent_transactions` / `read_file` as sources.
- **Gap 1 (wall definition vs call in different files):** solved **declaratively**
  (runtime presumption), NOT by cross-file dataflow — the recall-safe 1-hop limit is
  preserved. The wall in the real `tool_execution.py` (`runtime.run_function(...)`,
  `runtime` an unbound parameter) is now detected.

### End-to-end on real files
Running `--agentdojo` over the real `tool_execution.py` + `functions_runtime.py` +
banking `task_suite.py` + `banking_client.py` together yields **resolved CWE-1426
findings**: the `run_function` wall resolved to the domain sinks
(`schedule_transaction`, `update_password`, `update_user_info`, `send_money`, …) with
full provenance (`<agentdojo-tools>` source → LLM → domain tool, via the wall).

### Honest precision note
The runtime presumption fires on *any* `run_function` call, so it also flags the
runtime's internal recursive `self.run_function(...)` (in `_execute_nested_calls`) as
a wall, not only the external dispatch site in `tool_execution.py`. Both are genuine
`run_function` calls; flagging the wall is recall-safe and correct for the demo, but
the more meaningful site is the external one. Tightening this (prefer the external
call site) is a possible refinement.

### Framing (unchanged)
This is **(A) applicability + (B) domain-tool sinks**, demonstrating that ctaudit's
core dynamic-dispatch resolution fires on a standard public benchmark's runtime. It
is **NOT** "flow recall/precision on the 629 cases" (those are a dynamic
attack-success GT, a category mismatch). (C) static⇔dynamic coverage remains the
strongest follow-up and is now unblocked (wall + sinks + sources all resolve).

## 8. (C′) coverage result — soundness + over-approximation cost (banking)

`benchmark/agentdojo_coverage.py` computes, **statically and without running any
model**, two sink sets on the banking suite and compares them:

- **S_dyn** — sinks the 9 banking injection-tasks' ``ground_truth`` methods actually
  call. ``ground_truth`` is AgentDojo's OWN definition of "this injection succeeded
  == these FunctionCalls", so S_dyn is the *defined attack-success* sink set. Read by
  AST-parsing ``injection_tasks.py`` (no execution, no API key).
- **S_static** — sinks ctaudit resolves the AgentDojo dispatch wall to (``--agentdojo``).

Result:

    injection tasks: 9
    S_dyn   [3]: send_money, update_password, update_scheduled_transaction
    S_static[5]: send_money, schedule_transaction, update_scheduled_transaction,
                 update_password, update_user_info
    soundness:  S_static ⊇ S_dyn  = True  (missed attack sinks: NONE)
    over-approx rate = |S_static \ S_dyn| / |S_static| = 2/5 = 0.40

### Why this matters (and is NOT trivial)
The trivialisation worry was real and was checked: trivialisation needs **both** sets
to be the full sink set. They are not — **S_dyn (3) ⊊ S_static (5)**. So:

- **Soundness (R ⊇ R\*), empirically:** ctaudit flags every sink a defined banking
  attack uses — zero missed attack sinks. This is the empirical confirmation of the
  recall-first / over-approximation discipline on a standard benchmark.
- **Over-approximation cost = 40%:** ctaudit also flags 2 sinks no defined attack uses
  (``schedule_transaction``, ``update_user_info``). This is **not a defect** — it is the
  quantified price of staying sound when an LLM can route any source to any sink
  (the very dynamic-dispatch dilemma the project targets). It makes the (C) result
  *non-trivial and honest*: "covers all real-attack sinks, at the cost of 40% extra
  warnings", rather than a vacuous "100% coverage".

### Honest scope of S_dyn
S_dyn is the sink set of the injection tasks **shipped with** AgentDojo's banking suite,
i.e. the benchmark's *defined* attacks — not "all conceivable attacks" (AgentDojo is a
dynamic environment where attacks can be swapped in). And S_dyn is the *defined*
attack-success sink (what ``ground_truth`` asserts), not an *observed* model run; using
the GT is deliberate (it is the benchmark's own success criterion and keeps the measure
deterministic and reproducible, with no model/API dependency).

### A side fix this surfaced
Distinct domain sinks sharing one wall-site and one category (e.g. ``send_money`` and
``schedule_transaction`` both ``transaction``) collided under the pipeline's merge key
``(file, sink_site, category)`` and silently collapsed to one finding. Registration-only
ToolSpecs now carry a per-tool site (``…:registered:<name>``), so all five banking sinks
survive into S_static. (No effect on non-AgentDojo paths.)


