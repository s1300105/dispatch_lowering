# Real-repo corpus evaluation — standalone leg + what it tells us

Goal: run `ctaudit` on real GitHub agents (not synthetic), tally detections, and
judge whether anything is a *disclosable* vulnerability. This is the RQ1
(prevalence / real applicability) and RQ4 (portability) reality check.

**Corpus (7 real repos, fetched from GitHub):**

| # | repo | ~stars | kind | LLM call | dangerous sink |
|---|------|-------:|------|----------|----------------|
| 1 | TheR1D/shell_gpt | ~12100 | shell assistant | raw OpenAI, **aliased** `completion=…create` | `subprocess.Popen(shell=True)` (separate file, dict/`@classmethod` dispatch) |
| 2 | silvanmelchior/IncognitoPilot | ~440 | code interpreter | **legacy** `openai.ChatCompletion.create` | code → IPython subprocess (stdin write) |
| 3 | djcopley/ShellOracle | ~340 | command generator | raw OpenAI `chat.completions.create` (per-provider) | **none in-repo** (user/shell runs it) |
| 4 | haseeb-heaven/code-interpreter | ~280 | code interpreter | **litellm** `litellm.completion(...)` | generated-code exec (sandbox; prompt forbids subprocess) |
| 5 | LaphaeL12304/LaphaeL-aicmd | ~60 | shell assistant | raw OpenAI `chat.completions.create` | **none modeled** (types the command into the terminal) |
| 6 | gitstq/termwise | small | terminal coding | **provider abstraction** (no direct SDK call at loop) | `subprocess.run(command, shell=True)` **with `_check_safety()`** (separate module) |
| 7 | ShaoBuFan/codeCLI | small | terminal coding | **custom JSON protocol** (no SDK tool_calls) | tool dispatch in orchestrator |

## Result — standalone leg

| repo | raw candidates | flagged |
|------|---------------:|--------:|
| all 7 | **0** | **0** |

The intra-procedural, name-based standalone engine raises **zero candidates** on
every real repo — not even before pruning. This is an honest, important
negative result, and it is fully explained by structure, not by absence of risk.

## Why 0 — four miss-categories (the RQ4 content)

1. **Cross-method + dynamic dispatch** (shell_gpt): exit is aliased, the loop is
   split across `get_completion`/`handle_function_call`, the sink sits behind a
   dict/`@classmethod` registry dispatch in another file. The intra-procedural
   engine cannot thread taint across the method boundary, and Pyre/standalone
   cannot resolve the dict/`@classmethod` dispatch. → needs the **Pysa leg**
   (inter-proc value flow) **+ enumeration** (dispatch). Already shown to light
   end-to-end in `pysa/projects/shellgpt_faithful` + `hybrid.py`.
2. **Unmodeled LLM-call surface** (haseeb_ci=litellm, incognito=legacy
   `openai.ChatCompletion`, termwise=provider wrapper): the exit isn't one of the
   modeled forms, so no CTL is ever born. → RQ4 wiring work: add `litellm`,
   legacy, and provider-wrapper exit models (each is a few lines).
3. **No in-repo sink** (ShellOracle, aicmd): the tool only *generates* a command;
   a human/the shell runs it (ShellOracle) or it is typed into the terminal
   (aicmd). There is genuinely no code-execution sink in the repo to flag.
4. **Custom non-SDK protocol** (codeCLI): `tool_calls` is hand-rolled JSON with no
   SDK call to recognize. → would need a per-app entry/exit model.

**Takeaway:** the standalone engine's addressable surface is *single-function,
direct-SDK loops with an in-repo modeled sink* — common in tutorials, rare in
shipped tools, which abstract providers, split methods, dispatch dynamically, or
hand the command to the user/sandbox. Real coverage therefore depends on the
Pysa leg + a modest library of exit/sink/bridge models (RQ4), exactly as the
hybrid demonstrates.

## Responsible disclosure — none warranted here (and why)

Every repo in this corpus is a **by-design** command/code executor: running the
model's output *is the product*, and the cross-tool implicit flow `ctaudit`
targets is the intended behavior, typically shipped **with a mitigation**:

- ShellOracle — the user confirms before the command runs (human-in-the-loop);
- code-interpreter / IncognitoPilot — execution is **sandboxed**;
- termwise — a `_check_safety()` guard runs before `subprocess.run`;
- shell_gpt / aicmd — documented "this runs commands on your machine" tools.

So none of these are *hidden* defects, and **no responsible-disclosure action is
appropriate** — reporting "your shell tool runs shell commands" is not a
vulnerability report. The audit signal here is a **review aid** (it surfaces the
dangerous wiring and whether a guard exists), not a 0-day.

A genuinely disclosable finding would be a repo that wires an **attacker-readable
tool output** (web page, email, file) into a dangerous sink **unintentionally** —
e.g., an agent advertised as read-only that nonetheless routes fetched content to
a code/file/network sink with no guard. None of the seven qualifies. The
disclosure *methodology* (when such a case is found) remains: minimal PoC,
private report to maintainers, coordinated timeline — to be exercised once the
Pysa-leg corpus run (next step) surfaces an unintended flow.

## What this unblocks / next

* The honest RQ1 reading is **not** "few real flows exist" — it is "the dangerous
  wiring is pervasive but usually *intended + guarded*; the research question
  that matters is detecting **unintended/unguarded** instances." That sharpens
  the framing.
* RQ4 to-do, prioritized by how many corpus repos it unblocks: (a) `litellm` exit
  model, (b) provider-wrapper / legacy `ChatCompletion` exit models, (c) run the
  **Pysa leg** (with dep-stubbing) on the repos that *do* have an in-repo
  model-driven sink (shell_gpt, termwise) to confirm the hybrid recovers the flow
  on literal code, and record whether a guard (`_check_safety`) is present.
* The dep-stubbing + per-repo modeling cost is the operational bottleneck (RQ3);
  automating stub generation is the highest-leverage engineering task to make a
  large literal-repo run feasible.

## Update — RQ4 exit models added (done) and what they (don't) change

Acting on (a)/(b) above, two exit models were added to `_generic_raw_api()` (a
few lines each — the RQ4 portability cost the proposal predicts):

```python
ExitSpec(P("create", recv_contains="chatcompletion"), prompt_kwargs=("messages",))  # legacy openai 0.x
ExitSpec(P("completion", recv_contains="litellm"),    prompt_kwargs=("messages",))  # litellm
```

* **Verified they work**: on minimal single-function loops using `litellm.completion(...)`
  and legacy `openai.ChatCompletion.create(...)`, the standalone engine now emits
  the CWE-1426 implicit finding (it found 0 before). So a new LLM-call surface is
  genuinely a few-line model — concrete RQ4 evidence. No regression (78 tests,
  eval 6/100%).
* **Corpus tally unchanged (still 0)**: adding the exit models is *necessary but
  not sufficient* for the literal repos. haseeb_ci (litellm) and incognito
  (legacy) still don't fire because they *also* have the cross-method structure
  and non-modeled sinks (sandboxed exec / stdin-write) of categories (1) and (3).
  This pins the result precisely: the standalone leg's ceiling on real shipped
  agents is set by **inter-procedural structure + sink reachability**, not by the
  LLM-call surface — i.e., the Pysa leg is required, not optional, for real
  coverage.

---

# Pysa leg on LITERAL repos (done) — shell_gpt & termwise

Acting on next-step (c): run the Pysa leg on the two repos that *do* have an
in-repo, model-driven sink, with dependency stubbing, and record guards.

## shell_gpt (literal)
* **Made it analyzable**: the literal repo pulls `pydantic` (both via `openai`
  and directly in the tool classes `Function(BaseModel)`), which stalls Pyre's
  type-check. Adding **minimal `openai` + `pydantic` stubs** (search_path) let
  Pyre analyze all 22 modules with no stall — a concrete RQ3 recipe.
* **Pysa data-flow result: 0 issues.** Root cause: `get_function(name)(**dict_args)`
  loads the tool module by **`importlib`** (`sgpt/function.py`), so the dispatch
  is fully dynamic and gates BOTH ends of the loop — the tool output never
  reaches the history (source side) and the model response never reaches a
  resolvable sink (sink side). Pure data-flow can't even start.
* **Enumeration leg (b) recovers it** (`corpus/shellgpt_enum.py`, reusing the same
  §4.5 enumeration as AgentDojo): scanning the loadable `Function` tools under
  `sgpt/llm_functions/` and classifying them yields **4 CWE-1426 routing pairs**
  (`execute_shell_command` / `execute_apple_script`, each both source-output and
  code-exec sink). **In-function guard: NONE** — `subprocess.Popen(shell=True)`
  and `osascript` run the model-chosen command directly (any mitigation is at the
  CLI/confirmation layer, not the tool).
* **Conclusion**: literal shell_gpt is the textbook case where the dispatch is so
  dynamic (importlib) that *every* data-flow leg sees nothing and the
  **enumeration leg is both necessary and sufficient** — precisely the proposal's
  (a)+(b) split, on real code.

## termwise (literal)
* Distinct exit surface: the LLM call is a **raw HTTP POST** (`self._client.post(
  "/chat/completions", …)` via httpx) inside a provider class — *not* an SDK
  `chat.completions.create`. So it needs an **HTTP-provider exit model** (model
  the provider's `chat()` method, or `httpx.Client.post`, as the `llm_node`
  TITO) — a different few-line model than the SDK forms.
* Tool dispatch is a **dict registry of `Tool` objects** (`self.tools[name].execute`).
* **Guard present**: the shell tool runs `subprocess.run(command, shell=True)`
  **only after `_check_safety(command)`** — a real, in-function mitigation.

## Guard contrast (the audit's actual value here)
| repo | model-driven shell sink | in-function guard |
|---|---|---|
| shell_gpt | `subprocess.Popen(shell=True)` / `osascript` | **NONE** |
| termwise   | `subprocess.run(shell=True)` | **`_check_safety()`** |

Both flows are *real and by-design*; the useful, reportable output is **which
agents guard the sink and which don't** — a review signal, not a 0-day. This is
the honest role of the tool on this corpus.

## Net
* Pysa leg on literal repos is **operationally feasible with dep-stubbing**
  (RQ3 recipe demonstrated), but on shell_gpt the **importlib dispatch makes
  data-flow blind → enumeration (b) is the load-bearing leg**, recovering 4
  CWE-1426 routing pairs.
* RQ4 surfaces still to model for full corpus coverage: **HTTP-provider exit**
  (termwise) and **custom-JSON-protocol entry/exit** (codeCLI).

---

# Guard-aware enumeration (done) — operationalizing the sharpened RQ1

The sharpened RQ1 is "detect **unintended / unguarded** dangerous routings", not
"agents run model output". So the enumeration leg now **records the in-function
guard on each sink** and prioritizes accordingly (the guard is noted, never used
to prune — a weak `_check_safety` can be bypassed, so the static flow remains).

`corpus/shellgpt_enum.py` and `corpus/termwise_enum.py` apply the SAME §4.5
enumeration to the two repos' real registries:

| repo | pairs | unguarded (high) | guarded (noted) | sinks |
|---|---:|---:|---:|---|
| shell_gpt | 4 | **4** | 0 | `execute_shell` / `apple_script` — code-exec, **NO guard** |
| termwise  | 6 | **3** | 3 | `write_file` (no guard) vs `shell` (**`_check_safety`**) |

termwise output:
```
UNGUARDED (high): read_file:out / search:out / shell:out  ==model==>  write_file   [file_write, NONE]
GUARDED  (noted): read_file:out / search:out / shell:out  ==model==>  shell         [code_exec, _check_safety()]
```

This is the audit's real, reportable value on by-design agents: not "it runs
commands" but **which model-controlled routings reach an UNGUARDED dangerous
sink**. shell_gpt's code-exec tools are entirely unguarded; termwise guards its
shell sink but leaves `write_file` open — exactly the kind of asymmetric,
reviewable signal a maintainer can act on. (Guard-aware ranking is a small,
reusable addition to the enumeration; it does not touch the §4.5 core.)

## Guard-awareness is now in the CORE (not per-repo scripts)
Integrated end-to-end:
* `corpus/agentdojo/_common.py` — `split_by_guard()` + `render_flows_by_guard()`;
  `compute()`/`analyze()` report `(N unguarded, M guarded)`. `_passes` is
  unchanged: the guard NEVER prunes (a weak guard can be bypassed).
* `corpus/shellgpt_enum.py`, `corpus/termwise_enum.py` — refactored to call the
  shared renderer (no duplicated logic).
* the AgentDojo leg now prints the guard split (uniform `NONE` — its tools have
  no in-function guard).
* the **standalone engine** gained a conservative in-function guard detector
  (`Analyzer._detect_guard`: a `_check_safety`/`is_safe`/`validate`/… call textually
  before the sink, in the same function) → `Finding.guard`; surfaced in the
  `ctaudit --json` output and in the **hybrid report** (`[guard: …]` per finding).
  Verified: a single-function loop with `if is_safe(cmd): subprocess.run(cmd)` is
  tagged `guard=is_safe`; the same loop without the check is `guard=None`. No
  regression (78 tests, eval 6/100%).

## Update — HTTP-provider exit model (done) + literal termwise
RQ4 gap (b) closed: agents whose LLM call is a **raw HTTP POST in a provider
abstraction** (termwise) are modeled in one line —
`def httpx.Client.post(self, url, json: TaintInTaintOut[Via[llm_node]], **kwargs)`.
* **Proven** on `pysa/projects/http_provider_demo`: Pysa threads the cross-tool
  flow inter-procedurally *through the provider abstraction* and the (strengthened,
  bounded-call-closure) structural classifier tags it IMPLICIT (CWE-1426).
* **Literal termwise**: Pyre's analyzer **crashes** on the full repo
  (`Base__Sys0.getenv`) — an RQ3 tooling-robustness data point; a scoped 10-module
  flow slice analyzes cleanly but returns 0 (the `ConversationManager` history
  bridge + dict-of-`BaseTool`-subclass dispatch are the walls). termwise's concrete
  sinks + `_check_safety` guard are surfaced by the enumeration leg
  (`corpus/termwise_enum.py`). See http_provider_demo/README.md.
