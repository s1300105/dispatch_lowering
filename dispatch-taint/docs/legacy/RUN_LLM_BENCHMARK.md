# Running the real LLM-discovery benchmark (measuring held-out recall)

This measures how high the **real** LLM-discovery backend pushes held-out tool
recall, versus the heuristic baseline (which scores 0% recall on held-out
tool-bearing repos). You supply the `ANTHROPIC_API_KEY` and run it.

## Prerequisites
* Python 3.9+ and `pip`.
* An Anthropic API key.

## 1. Unpack and install
```bash
unzip cross_tool_audit_system.zip
cd cross_tool_audit
pip install -e . --break-system-packages

# install the SDK for YOUR provider:
pip install anthropic --break-system-packages   # if using Claude
pip install openai    --break-system-packages   # if using DeepSeek / OpenAI / any OpenAI-compatible API
# (or, cleaner, a venv:  python -m venv .venv && . .venv/bin/activate && pip install -e . openai)
```

## 2. Pick a provider + set its key

The classifier's LLM is independent of whatever LLM the analysed agent uses. Choose ONE:

**DeepSeek** (OpenAI-compatible — this is what you have):
```bash
export DEEPSEEK_API_KEY=sk-...
# optional model (default deepseek-chat; deepseek-reasoner also works)
export CTAUDIT_TOOLMODEL_MODEL=deepseek-chat
#   then use:  --classifier deepseek
```

**Anthropic / Claude**:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
export CTAUDIT_TOOLMODEL_MODEL=claude-sonnet-4-5-20250929   # optional
#   then use:  --classifier anthropic
```

**Any other OpenAI-compatible endpoint** (Together/Groq/OpenRouter/Ollama/vLLM):
```bash
export OPENAI_API_KEY=...
export CTAUDIT_TOOLMODEL_BASE_URL=https://your-endpoint/v1
export CTAUDIT_TOOLMODEL_MODEL=your-model
#   then use:  --classifier openai
```

In the commands below, replace `--classifier anthropic` with `--classifier deepseek`
(or `--classifier openai`) to match your provider.

> If a key/SDK is missing the run prints a loud `!! WARNING ... FALL BACK TO THE
> HEURISTIC`; if the key is set but a *call fails* you now get a visible
> `[ctaudit.toolmodel] LLM discovery failed: <error>` line (e.g. auth error) instead
> of a silent fallback.

## 3. Minimal verification — KEY ONLY, no corpus needed
Runs the real LLM discovery on the bundled synthetic dict-registry repo:
```bash
python -m benchmark.run_benchmark --classifier deepseek      # or anthropic / openai
```
* If the key/SDK are missing you'll see the loud `!! WARNING ... FALL BACK` — fix
  that first (numbers under it are NOT the LLM). If a *call* fails you'll see a
  `LLM discovery failed: <error>` line.
* When it works: **no warning/error**, and `synthetic-dict` should show
  `recall 100%` (the model recovers `read_file` + `write_file`, including the
  cross-layer `confirm_action` guard). Real-corpus rows say *skipped* until step 5.

Sanity-check on any repo (your own agent), no scoring:
```bash
ctaudit-toolmodel /path/to/your/agent --src-root /path/to/your/agent \
    --classifier anthropic --emit enum
```

## 4. (reference) Reproduce the captured preview without a key
```bash
python -m benchmark.run_benchmark --classifier replay     # uses benchmark/llm_fixtures/
```

## 5. Full held-out measurement — KEY + CORPUS
Point the benchmark at the directory that holds the corpus repos, then run the
baseline and the real LLM and compare:
```bash
export CTAUDIT_CORPUS_BASE=/path/to/your/corpus   # dir containing the repos below
python -m benchmark.run_benchmark --classifier heuristic    # baseline (held-out recall ~0%)
python -m benchmark.run_benchmark --classifier deepseek     # real LLM (or anthropic / openai)
```
The harness expects each repo at `$CTAUDIT_CORPUS_BASE/<rel>`, with `<rel>` /
`src_rel` as listed in `benchmark/labels.py`:

| key | rel | src_rel | idiom |
|-----|-----|---------|-------|
| shellgpt | shellgpt | shellgpt | class+schema-method (tuning) |
| termwise | termwise | termwise | class+BaseTool (tuning) |
| codecli | codecli | codecli/app | dict-registry+dispatcher (held-out) |
| aicmd | aicmd | aicmd/src | verbatim-exec (held-out, empty gold) |
| shelloracle | shelloracle | shelloracle/src | verbatim-exec (held-out, empty gold) |
| incognito | incognito | incognito | chat-service (held-out, empty gold) |
| haseeb_ci | haseeb_ci | haseeb_ci | code-interpreter (held-out, empty gold) |

If your directory layout differs, edit the `rel` / `src_rel` fields in
`benchmark/labels.py` (or symlink the repos into one folder). Any repo not found is
listed under "skipped" and excluded — the run still works on whatever is present.

## What to read in the output
* **`held_out` aggregate line** — the headline. `recall` is how many held-out gold
  tools the LLM recovered; `precision` is whether it invented tools. Compare the
  `anthropic` run against the `heuristic` baseline (held-out recall 0.0%).
* **`codecli` row** — the key held-out case (dict-registry). Did the model recover
  all 5 tools and the cross-layer `confirm_action` guard?
* **`role / sink-cat / guard-presence`** — agreement on the matched tools.
* **`recall holes`** — any gold tools still missed.
* The empty-gold repos (aicmd/shelloracle/incognito/haseeb_ci) test precision: the
  model should add nothing there (candidate-file gating means it isn't even shown
  tool files for a chat/verbatim app).

## Notes
* **Grounding (default on)**: LLM-discovered source/sink roles are kept only if
  backed by real I/O (recall-first); this deterministically drops spurious non-I/O
  tools (e.g. phase-control `report_*`) that the model occasionally over-enumerates.
  Compare with/without:
  ```bash
  python -m benchmark.run_benchmark --classifier deepseek --repeat 10              # grounded (default)
  python -m benchmark.run_benchmark --classifier deepseek --repeat 10 --no-ground  # raw LLM
  ```
  Expected: grounding lifts held-out precision toward ~100% and shrinks its variance,
  with recall unchanged at 100%.
* **Run-to-run variance**: LLM output varies between runs even at `temperature=0`.
  Characterise the backend with the distribution, not one run:
  ```bash
  python -m benchmark.run_benchmark --classifier deepseek --repeat 5
  ```
  This prints each metric as `mean ± popstdev [min–max]` and a stability list (which
  gold tools are missed in some runs, which spurious tools appear in some runs).
  In our runs, held-out **recall was stably 100%** while **precision varied**
  (e.g. 63.6% ↔ 100%) — so report the spread.
* **Cost / determinism**: one discovery call per found repo per run (`--repeat N`
  multiplies that). `temperature=0` is set, but is not a determinism guarantee.
* **Guardrails**: the LLM can only *add* tools/roles (recall-first union with the
  heuristic), never prune; with no transport it degrades to the heuristic floor.
* **Validity**: this is the automated measurement the preview in
  `BENCHMARK_RESULTS.md` could not run (no key here). For a fully independent
  result, also have the gold in `benchmark/labels.py` reviewed by another annotator
  and add more idioms (`@tool`/LangChain, MCP `tools/list`).
* To classify a single repo into the shared model (and emit both legs):
  `ctaudit-toolmodel <repo> --src-root <root> --classifier anthropic --emit both`.
