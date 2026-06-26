# ctaudit on Pysa — resolving limitations (1) and (2)

This directory ports the novel cross-tool implicit-flow layer onto **Pysa** (the
taint-analysis mode of Meta's **Pyre**). Doing so resolves the two limitations of
the standalone prototype:

* **(1) builds on a real taint engine** — Pysa provides the mature, scalable data
  layer (and, by including Pyre's stdlib taint stubs, the full ~236-sink catalog),
  instead of the prototype's hand-rolled AST analyzer;
* **(2) general inter-procedural data flow** — Pysa analyses the whole call graph,
  so tool→…→LLM→…→sink flows that pass through ordinary helper/wrapper functions
  are tracked automatically, not just the single reducer shape.

> **Honesty note.** These artifacts were written from Pysa's documented behavior
> but were **not executed here** (Pysa needs a built Pyre environment). The
> post-processor *is* verified (see `tests/test_pysa_postprocess.py`). The Pysa
> model DSL — especially `ModelQuery` predicates — is **version-sensitive**;
> validate with `pyre validate-models` and adjust to your `pyre-check` version.

## The one idea that makes it work

A control-dependency (implicit) flow is not classic data flow: the tool output
does not appear verbatim at the sink; it steers the LLM's *choice* of the next
tool. We turn it into a data flow Pysa can follow:

| ctaudit concept (proposal §) | Pysa encoding |
|---|---|
| attacker-influenceable tool output (source) | `TaintSource[ToolOutput]` |
| **join at the LLM node (§4.4)** | model the LLM call as **`TaintInTaintOut[Via[llm_node]]`** (prompt → response), tagging the trace with `llm_node` |
| dangerous operation (sink) | `TaintSink[CodeExecution\|SQL\|SSRF\|FileSystem\|Deserialization]` |
| selective hiding / FIDES HIDE (§4.5(4)) | model `hide()` as a **`Sanitize`** |
| schema / channel capacity (§4.5(2)) | source via-feature `cap_bool\|cap_enum\|cap_string`, pruned in post |
| role (§4.5(3)) | source via-feature `role_*`, pruned in post |
| reachability (§4.5(1)) | Pysa's own path analysis |
| implicit vs explicit | a flow is **implicit (CWE-1426)** iff its trace carries `llm_node`; otherwise explicit/verbatim |

So Pysa emits raw source→sink flows; `postprocess.py` keeps the `llm_node` ones
as implicit findings and runs the project's existing §4.5 pruning and §4.6 triage
on them — the novel layer rides on top, unchanged.

## Files

```
pysa/
  .pyre_configuration     points Pyre at the example + ./models taint models
  models/                 <- loaded by default (kept minimal so the example verifies cleanly)
    taint.config          sources / sinks / features / rules (codes 9001–9005)
    example.pysa          models for the bundled self-contained example
  frameworks/             <- NOT loaded by default; for real projects
    frameworks.pysa       LangChain/LangGraph/MCP/OpenAI LLM-TITO + tool sources + hide sanitizer
  example/agent.py        dependency-free target (validates the toolchain)
  postprocess.py          Pysa JSON -> ctaudit findings (+ prune + triage)
  setup_project.py        discover LLM calls/tools/hide in a target; emit config
  run_pysa.sh             pyre analyze -> postprocess
  requirements.txt
```

`frameworks.pysa` lives outside `models/` on purpose: it references libraries
(`langchain_core`, `mcp`, …) that aren't installed for the dependency-free
example, so keeping it out of the default `taint_models_path` lets the example
run with a clean model verification. Enable it for real projects (see below).

## Prerequisites

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # pyre-check (+ optional anthropic)
# recommended: install watchman (brew install watchman / distro package)
```

`postprocess.py` imports the `ctaudit` package from the parent directory, so run
it from inside `pysa/` (it adds the parent to `sys.path`) or set
`PYTHONPATH=..`.

## Quick start — validate the toolchain on the bundled example (no deps)

```bash
cd pysa
pyre analyze --save-results-to ./pysa-results
python postprocess.py ./pysa-results --implicit-only
# …or both steps at once:
./run_pysa.sh
```

Expected: **one** implicit finding (code 9001) at `run_command`, with the trace
carrying `llm_node`. Crucially, the taint reaches it through `summarize()` and
`build_request()` — helpers that are **not modeled** — which is the proof that
Pysa supplies the general inter-procedural flow of limitation (2).

Two things to know:
* The example's `call_model` body deliberately ignores its argument so the only
  taint on the response comes from the `TaintInTaintOut[Via[llm_node]]` *model*
  (mirroring a real external `llm.invoke`). That is what makes the flow carry the
  `llm_node` feature and count as **implicit**. Run without `--implicit-only` to
  also see explicit (verbatim) flows.
* If verification ever blocks a run, `pyre analyze --no-verify --save-results-to
  ./pysa-results` skips model verification and still produces results.

## Running it on YOUR project

**Start with the discovery helper** — it scans the target and tells you exactly
what to model, and writes a `.pyre_configuration` for it:

```bash
python setup_project.py --target /path/to/your/package
# add Pyre's bundled stdlib sink stubs (the ~236 sinks) to the model path too:
python setup_project.py --target /path/to/your/package --with-bundled-sinks \
    --out /path/to/your/package/.pyre_configuration
```

It prints (1) LLM entry points to model as `TaintInTaintOut[Via[llm_node]]`,
(2) `@tool`/`@function_tool` decorators (already covered by the source
ModelQueries), (3) `hide()`/by-reference helpers to model as `Sanitize`, and
(4) the path + sink kinds of Pyre's bundled stdlib taint stubs.

Then:

1. **Install the project's dependencies** into this venv so Pyre can resolve
   types (`langchain_core`, `mcp`, `agents`, `httpx`, your app). This also clears
   the "no module … in search path" model errors.
2. In `frameworks/frameworks.pysa`, make the LLM entry points from discovery
   step (1) are modeled as `TaintInTaintOut[Via[llm_node]]`, and point the
   `hide()` sanitizer (no `#`, real module path) at the helper from step (3).
   The `@tool`/`@function_tool` `ModelQuery`s cover step (2) generically.
3. **Sinks — pick one:**
   * *Simplest first run:* keep ctaudit's own kinds and model only the dangerous
     calls your project actually makes. `subprocess.run` and `os.system` are
     already active and verify cleanly; add any others your code calls (with
     `CodeExecution`/`SQL`/`SSRF`/`FileSystem`/`Deserialization`).
   * *Full catalog:* run with `--with-bundled-sinks` and add rules
     `ToolOutput -> <kind>` to `models/taint.config` for the bundled sink kinds
     discovery step (4) printed (these are correct for your Pyre version, so you
     avoid hand-writing stdlib signatures). New rule codes → add them to
     `postprocess.py`'s `CODE_TO_CATEGORY`.
4. Run `./run_pysa.sh ./pysa-results --triage anthropic` (set `ANTHROPIC_API_KEY`
   for live triage; omit `--triage` for the offline mock), or the two commands
   `pyre analyze --save-results-to ./pysa-results` then
   `python postprocess.py ./pysa-results --implicit-only`.

## Tuning / troubleshooting

* `pyre validate-models` flags model syntax errors per your version — fix those
  first; the `ModelQuery` predicate spelling (`Decorator(name.matches(...))`) is
  the part most likely to need a tweak. See the Pysa model-DSL docs.
* If `postprocess.py` prints "No Pysa issues found" with the JSON shape, your
  pyre version's output schema differs slightly — adjust `_iter_issues()` /
  `_first()` (one place) to match; the feature extraction is already recursive
  and schema-agnostic.
* `--implicit-only` keeps just the CWE-1426 flows; drop it to also see explicit
  (verbatim TITO) flows. `--show-pruned` shows what the §4.5 prunes removed and
  why. `--json` emits machine-readable output for CI.

## What this does and does not establish

It establishes that the novel layer is expressible on a production engine and
that, on the example, the implicit flow is found across unmodeled helpers (so (1)
and (2) are addressed in the design). It does **not** by itself constitute the
Stage-4 empirical study — for that, run this pipeline over a real, independently
labeled corpus and feed `postprocess.py`'s output into the evaluation harness
(`python -m ctaudit.eval` with a fixtures/labels set built from that corpus).
