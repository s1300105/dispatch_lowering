# dispatch_lowering — Dynamic Dispatch Wall Resolution for Static Taint Analysis

`dispatch_lowering.py` is a preprocessing pass that resolves **dynamic dispatch
walls** in Python agent code so that static taint analysis (Pysa/TaintP2X) can
trace taint across them. It detects BoolOp walls, attribute dispatch, and subscript
dispatch, and inserts `if __ctaudit_unreachable__:` blocks that connect concrete
candidate callees to the static call graph without modifying observable semantics.

**Verified on two real OSS targets:**

| Target | Result |
|--------|--------|
| AutoGPT v0.5.0 (CVE-2024-1881) | cond_A = 0 issues → cond_B = 7 issues |
| Semantic Kernel 1.39.3 (CWE-1426/RCE) | cond_A = 0 issues → cond_B = 1 issue (code 5001) |

---

## Repository layout

```
dispatch-taint/
├── taintp2x_extension/          # dispatch_lowering.py — the preprocessing pass
├── taintp2x_m2_verification/    # AutoGPT M2 verification (cond_A=0, cond_B=7)
│   ├── reproduce_m2.sh          # end-to-end reproduction script
│   ├── ablation_helpers.py      # ablation setup helpers
│   └── run_ablation.sh          # ablation runner
├── pysa/                        # Pysa integration: models, setup tools, demo projects
│   ├── models/                  # taint rules (rule 5001, 9001, etc.)
│   ├── frameworks/              # framework TITO models (LangChain, MCP, OpenAI, ...)
│   ├── projects/
│   │   ├── sk_real/             # Semantic Kernel 1.39.3 real verification
│   │   │   ├── cond_A/          # without lowering: 0 issues
│   │   │   ├── cond_B/          # with lowering: 1 issue (code 5001)
│   │   │   └── VERIFICATION_REPORT.md
│   │   └── ...                  # other demo projects
│   ├── setup_project.py         # discover LLM calls/tools; emit .pyre_configuration
│   └── run_pysa.sh              # pyre validate-models + pyre analyze
├── fixtures/                    # example agent fixtures (analysis targets)
├── corpus/ realworld/           # corpora and real-repo materials
└── docs/                        # research and evaluation notes
```

---

## How dispatch_lowering works

Static taint analysis stops at dynamic dispatch walls:

```python
# Wall: update_func is only known at runtime
update_func = filter_update_function or default_dynamic_filter_function
inner_options.filter = update_func(kwargs, ...)
```

`dispatch_lowering.py` inserts an unreachable block that Pyre can still analyze:

```python
if __ctaudit_unreachable__:  # [ctaudit] resolved dynamic dispatch -> 1 targets
    from semantic_kernel.data._shared import default_dynamic_filter_function
    __ctaudit_ret = default_dynamic_filter_function(kwargs, ...)
    inner_options.filter = __ctaudit_ret
```

`__ctaudit_unreachable__` is an undefined name (→ potentially truthy), so Pyre
analyzes the block. `if False:` would be pruned as dead code.

---

## AutoGPT M2 verification

```bash
cd taintp2x_m2_verification
./reproduce_m2.sh
```

Expected: `Found 0 issues` (cond_A) → `Found 7 issues` (cond_B). The only
difference is the lowering insertion in `agent.py`.

Full details: [`taintp2x_m2_verification/README.md`](taintp2x_m2_verification/README.md)

## Semantic Kernel verification

```bash
cd pysa/projects/sk_real/cond_B
timeout 600 pyre analyze --no-verify --save-results-to ./r
```

Expected: `Found 1 issues`, code 5001 (LLMControlled → RemoteCodeExecution).

Full details: [`pysa/projects/sk_real/VERIFICATION_REPORT.md`](pysa/projects/sk_real/VERIFICATION_REPORT.md)

---

## Scope and honest limits

The lowering pass restores **reachability** — that attacker-influenced LLM output
can reach a dangerous sink across a dynamic dispatch wall. It does not detect logical
flaws in sanitizers along the path. `if TYPE_CHECKING:` imports at the top of target
files are currently a manual pre-processing step (needed so Pysa resolves concrete
method signatures inside lowering blocks); automating this is future work.
