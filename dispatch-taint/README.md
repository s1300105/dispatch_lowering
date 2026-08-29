# dispatch_lowering — Dynamic Dispatch Wall Resolution for Static Taint Analysis

`dispatch_lowering.py` is a preprocessing pass that resolves **dynamic dispatch
walls** in Python agent code so that static taint analysis (Pysa/TaintP2X) can
trace taint across them. It detects BoolOp walls, attribute dispatch, and subscript
dispatch, and inserts `if __ctaudit_unreachable__:` blocks that connect concrete
candidate callees to the static call graph without modifying observable semantics.

**Verified on two real OSS targets:**

| Target | Result |
|--------|--------|
| AutoGPT v0.5.0 (CVE-2024-1881) | cond_A = 0 issues → cond_B = 7 issues (5 distinct (sink kind, sink method) pairs) |
| Semantic Kernel 1.39.3 (CWE-1426/RCE) | cond_A = 0 issues → cond_B = 1 issue (code 5001) |

The AutoGPT result is identical at *port* level to the pre-2026-08 form
(same set of (code, sink kind, sink method, `formal(param, position)`) — 7 issues
because `execute_python_file` receives taint on both `filename` and `args`).
`ablation_helpers.py count/table` also prints the distinct (sink kind, sink
callee) pairs, a coarser measure that does not depend on Pysa's per-argument
issue counting; `EXPECT_SINKS_B` asserts it alongside the raw count.

---

## Repository layout

```
dispatch-taint/
├── taintp2x_extension/          # the preprocessing pass
│   ├── dispatch_lowering.py     #   wall detection, candidate recovery, emitters (inline / redirector)
│   ├── links.py                 #   DispatchLink IR: wall x candidate join, precision filters, links.json
│   ├── pipeline.py              #   driver: providers (auto / hand-written links) -> passes -> instrument
│   ├── bench/                   #   per-idiom micro-benchmark (run_bench.py [--pyre])
│   └── test_registration.py     #   candidate recovery + link round-trip tests
├── taintp2x_m2_verification/    # AutoGPT M2 verification (cond_A=0, cond_B=7; 5 sink pairs)
│   ├── reproduce_m2.sh          # end-to-end reproduction script
│   ├── ablation_helpers.py      # ablation setup helpers (lower = pipeline; table = stats + A/B)
│   └── run_ablation.sh          # ablation runner (EMIT=inline|redirector, LINKS_IN=links.json)
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

`dispatch_lowering.py` inserts an unreachable block that Pyre can still analyze
(the real output for that wall, `semantic_kernel/data/vector.py`):

```python
inner_options.filter = update_func(filter=inner_options.filter, parameters=parameters, **kwargs)
if __ctaudit_unreachable__:  # [ctaudit] resolved dynamic dispatch -> 1 targets | wall=vector.py:2103
    __ctaudit_ret = default_dynamic_filter_function(filter=inner_options.filter, parameters=parameters, **kwargs)  # S0L0
    inner_options.filter = __ctaudit_ret
```

(The block is placed before the wall here — `insert_before` in that spec. A
`from <module> import <target>` line is added when the wall file does not
already bind the target's name.)

`__ctaudit_unreachable__` is an undefined name (→ potentially truthy), so Pyre
analyzes the block. `if False:` would be pruned as dead code. The name is never
defined anywhere, so the block is unreachable *for the analyzer's purposes* but
would raise `NameError` if the code ran: `cond_B` is an analysis-only copy of
the target (as the ablation treats it), never a runnable tree.

### Pipeline (IccTA-style)

The pass is structured after IccTA (Li et al., ICSE 2015), which solves the
same shape of problem for Android ICC: resolve the runtime-selected callee to
explicit *links*, then instrument ordinary code so an unmodified taint engine
(FlowDroid there, Pysa here) follows the edge.

```
wall files ──► find_walls ─────┐
                               ├─► links.build_links ──► DispatchLink[] ──► emit ──► cond_B/src
cand_dir   ──► collect_candidates ┘      │  (links.json / stats.json)         │
                                         │ filters:                            ├ inline:     block at the wall
                                         │  • registry / BoolOp membership     └ redirector: __ctaudit_redirect.py
                                         │  • argument compatibility               (one redirector_N per link)
```

| IccTA | here |
|---|---|
| `ICCLink` row (source stmt, destination, kind) | `links.DispatchLink` — same shape, persisted as `links.json` with each link's decision |
| `ICCLinksProvider`: Epicc / IC3 (DB) or config file | `pipeline.AutoLinksProvider` (spec-driven recovery) / `FileLinksProvider` (hand-written `links.json`) |
| `UnreasonableLinksRemover` — drop a link whose exit kind contradicts the destination's component type | argument-compatibility filter (`filter_unreasonable`) — drop a link whose target signature cannot accept the wall's arguments |
| explicit-Intent links (`ICCLinker`): the destination is named at the call site | registry / BoolOp membership narrowing (`narrow`) — the wall's registry names its members |
| `INTENT_MATCH_LEVEL` (1 action/category < 2 +mime < 3 +data) | `match_level` (1 registry member < 2 decorator/registration < 3 scan-all). Different quantities; the shared principle is `DefaultMatchAlgo`'s "we can give up some links, but we had better not introduce false positives" |
| `IpcSC.redirectorN` + `ICCInstrumentSource` | `emit="redirector"`: `__ctaudit_redirect.redirector_N(...)` called from the wall |
| `ICCInstrumentSource` AssignStmt case: `lhs = IpcSC.redirectorN(...)` (ContentProvider path) | writeback `x = __ctaudit_ret` |
| `JimpleIndexNumberTag` / `copyTags` | `wall=<file>:<line>` header tag + `# <link id>` on every inserted call; `lowered_line` in `links.json` |
| `InfoStatistic` (Jimple lines/methods before and after) | `LoweringStats` (`stats.json`; `ablation_helpers.py table`) |
| `updateJimpleForICC` pass order | `pipeline.LoweringPipeline` (pre-passes → provider → instrument → post-passes) |
| `NoCodeElimination` + `fuzzyMe()` keep synthetic branches from being pruned | `if __ctaudit_unreachable__:` keeps the inserted block from being pruned |

**Where the analogy stops** — worth stating precisely, because these are the
differences an examiner will ask about:

- **Link discovery.** IccTA's links come from an external value analysis
  (IC3/Epicc) of the Intent at each call site, so a link is a *resolved*
  (call site → component) pair. `build_links` does not analyse the dispatch key:
  it enumerates wall × candidate and prunes with the two filters above, so an
  un-narrowed wall fans out to every surviving candidate (recall-first).
- **Instrumented sides.** IccTA instruments both: the destination gets a
  generated `<init>(Intent)` that stores the Intent, a `getIntent()` override
  and a lifecycle `dummyMain`. Here only the caller side is rewritten; a class
  target is invoked on `Cls.__new__(Cls)`, an instance whose `__init__` did not
  run, so only argument-carried taint crosses the wall — receiver state and
  lifecycle callbacks are not modelled.
- **Reachability.** IccTA's redirect call is unconditional, always-taken code
  and the original ICC statement is deleted (`AndroidIPCManager.postProcess`).
  Here the original call is kept and the inserted calls sit under an opaque
  guard: the analysis effect is the same (the block is analysed) but the
  inserted edge is not a feasible runtime path.
- **Multi-hop chains.** IccTA resolves all links up front and instruments a
  chain in one pass. A second-hop wall here only becomes visible after the first
  hop is inserted (it reads `__ctaudit_ret`), so chains are lowered as
  sequential `stages`, each over the previous stage's output.
- **No counterpart.** The Android lifecycle model (`dummyMain`), the
  `setResult` → `onActivityResult` result *callback*, and the MySQL link store.

```bash
# one-off, any target
python3 taintp2x_extension/pipeline.py --src-root cond_B/src --spec spec.json \
    --walls agent.py --emit redirector --links-out links.json --stats-out stats.json
# idiom / precision-mechanism micro-benchmark: 26 fixtures x both emission modes
#   --pyre also analyses each fixture with and without lowering: cond_A must be 0
#   (the wall really blocks Pysa) and cond_B must reach the fixture's sink callee.
#   Status 2026-08-29: 26/26 pass in both modes, AST-level and with Pysa.
python3 taintp2x_extension/bench/run_bench.py
# candidate recovery + links.json round-trip
python3 taintp2x_extension/test_registration.py
```

---

## AutoGPT M2 verification

```bash
cd taintp2x_m2_verification
export TYPESHED=<repo>/.venv/lib/pyre_check/typeshed
./reproduce_m2.sh                       # needs the AutoGPT clone (see SETUP.md)

# or, from the committed cond_A/src — no AutoGPT clone needed:
TARGET_SRC=$PWD/cond_A/src WALL_FILES=agent.py \
PYSA_MODELS=$PWD/cond_A/source/autogpt_v05.pysa SPEC_JSON=$PWD/spec.autogpt.json \
EXPECT_A=0 EXPECT_B=7 EXPECT_SINKS_B=5 ./run_ablation.sh
```

Expected: `Found 0 issues` (cond_A) → `Found 7 issues` (cond_B), 5 distinct
(sink kind, sink method) pairs. The only difference is the lowering insertion in
`agent.py`. (`EMIT=redirector` additionally writes
`cond_B/src/__ctaudit_redirect.py`; `LINKS_IN=cond_B/links.json` replays the same
result from the saved links, isolating the emitter from the resolver. See
README_ABLATION.md.)

Full details: [`taintp2x_m2_verification/README.md`](taintp2x_m2_verification/README.md)

## Semantic Kernel verification

```bash
cd pysa/projects/sk_real
cp -r cond_A cond_B_new && rm -rf cond_B_new/r
python3 ../../../taintp2x_extension/pipeline.py --src-root cond_B_new/src \
    --spec spec.sk_real.json --walls semantic_kernel/data/vector.py --links-out cond_B_new/links.json
cd cond_B_new && timeout 600 pyre analyze --no-verify --save-results-to ./r
```

Expected: `Found 1 issues`, code 5001 (LLMControlled → RemoteCodeExecution).
`spec.sk_real.json` is a two-stage spec: the BoolOp wall (stage 1) and the
`self.search(...)` wall whose target and forwarded argument are analyst-pinned
(stage 2, `forward`), the way IccTA's config-file provider pins a link.

Full details: [`pysa/projects/sk_real/VERIFICATION_REPORT.md`](pysa/projects/sk_real/VERIFICATION_REPORT.md)

---

## Scope and honest limits

The lowering pass restores **reachability** — that attacker-influenced LLM output
can reach a dangerous sink across a dynamic dispatch wall. It does not detect
logical flaws in sanitizers along the path. Concretely:

- **Argument forwarding is an over-approximation.** The wall's own simple
  arguments are forwarded verbatim (keeping positional slots aligned; a
  non-forwardable positional does not let later ones slide into its slot). A
  `**d`/`*a` splat — the usual `command(**tool_call.arguments)` — is delivered to
  *every* parameter the wall did not fill (`filename=d, args=d`, plus `**d` when
  the target takes `**kwargs`), so a parameter that only ever receives a clean
  key of `d` is nevertheless treated as tainted. Only when nothing at all can be
  forwarded do the arguments fall back to every parameter/local of the enclosing
  scope. A hand-written link's `forward` pins the exact expression instead.
- **Registry narrowing is a heuristic, not a proof.** A registry is trusted only
  when it is a single dict literal with statically known members that is never
  rebound, mutated (`REG[k] =`, `.update`, `|=`), aliased or built with `{**other}`
  anywhere in the scanned tree, and bindings are resolved in the wall's own
  scope. It still keys registries by bare name (not by module), so a name defined
  identically in two modules is trusted as one. When any condition fails the
  candidate set is kept whole.
- **The `unreasonable` filter assumes the wall calls the target with the
  target's own signature.** That holds for a direct dispatch; it does not hold
  through a framework's dispatch method (`tool.run(x, verbose=…)` reaching
  `_run`) or a decorator that returns a wrapper (`@tool` → `StructuredTool`), so
  the filter is skipped for those and the link is kept.
- **Only argument-carried taint crosses the wall.** A class target is called on
  `Cls.__new__(Cls)`, so taint that would reach the sink through constructor
  state (`self.cmd` set at registration) is not modelled.
- **The lowered tree does not run.** `__ctaudit_unreachable__` is undefined, so
  evaluating a lowered wall raises `NameError`. `cond_B` is an analysis-only copy.

Every dropped wall or link is recorded with its reason in `links.json`, and each
reason has its own counter in `stats.json` (`filtered_registry`,
`filtered_level`, `unreasonable`, `no_args`, `phantom`), so a coverage claim can
be checked against the numbers rather than assumed.
