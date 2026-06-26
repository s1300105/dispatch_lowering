# dispatch_lowering + Pysa — resolving dynamic dispatch walls for static taint

This directory provides the **TaintP2X** leg of the system: `dispatch_lowering.py`
preprocesses a target's source tree to connect dynamic dispatch walls, then Pysa
(the taint-analysis mode of Meta's Pyre) performs full inter-procedural taint analysis.

**Verified result**: Semantic Kernel 1.39.3 — LLM-controlled tool argument reaching
`eval()` (CWE-1426/RCE, rule 5001) — `cond_A=0 issues`, `cond_B=1 issue`.
See `projects/sk_real/VERIFICATION_REPORT.md`.

## How it works

Dynamic dispatch creates "walls" where static taint analysis stops:

```python
update_func = filter_update_function or default_dynamic_filter_function
inner_options.filter = update_func(kwargs, ...)   # wall: update_func is unknown statically
```

`dispatch_lowering.py` inserts `if __ctaudit_unreachable__:` blocks that resolve
the wall to concrete candidates, so Pysa can trace through them:

```python
if __ctaudit_unreachable__:  # [ctaudit] resolved dynamic dispatch -> 1 targets
    from semantic_kernel.data._shared import default_dynamic_filter_function
    __ctaudit_ret = default_dynamic_filter_function(kwargs, ...)
    inner_options.filter = __ctaudit_ret
```

Pyre analyses `if __ctaudit_unreachable__:` (undefined name → potentially truthy)
but prunes `if False:` as dead code. This is the key mechanism.

## Files

```
pysa/
  models/                 taint models (sources / sinks / rules)
    taint.config          rule codes (5001 = LLMControlled → RemoteCodeExecution, etc.)
    *.pysa                sink/source/TITO declarations
  frameworks/             LangChain/LangGraph/MCP/OpenAI TITO + tool sources (for real projects)
  example/agent.py        dependency-free target (validates the toolchain)
  setup_project.py        discover LLM calls/tools in a target; emit .pyre_configuration
  run_pysa.sh             pyre validate-models + pyre analyze
  requirements.txt
  projects/
    sk_real/              Semantic Kernel 1.39.3 real verification (cond_A=0, cond_B=1)
    sk_inmemory/          SK InMemory demo
    dvla/                 DVLA demo
    http_provider_demo/   HTTP provider demo
    recursion_demo/       recursive dispatch demo
    shellgpt_faithful/    ShellGPT demo
    hybrid_demo/          hybrid dispatch demo
```

## Prerequisites

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # pyre-check 0.9.25
```

## Quick start — validate the toolchain on the bundled example

```bash
cd pysa
pyre analyze --no-verify --save-results-to ./pysa-results
```

Expected: one finding (code 9001) at `run_command`, taint carrying `llm_node`.

## Running on a real project

1. Run `setup_project.py` to discover LLM entry points and generate `.pyre_configuration`:
   ```bash
   python setup_project.py --target /path/to/your/package
   ```
2. Run `dispatch_lowering.py` on dispatch walls identified in the target.
3. Install project dependencies, then run:
   ```bash
   pyre analyze --no-verify --save-results-to ./pysa-results
   ```
4. Inspect `pysa-results/errors.json` (or use `jq`) for findings.

## Tuning / troubleshooting

* `pyre validate-models` flags model syntax errors per your Pyre version — fix these
  first; `ModelQuery` predicate spelling is the part most likely to need adjustment.
* New sink rule codes → add `<kind>: <code>` entries to `models/taint.config`.
* If Pyre hangs: do **not** add all of site-packages to `search_path`. Add only the
  specific packages the target actually imports.
