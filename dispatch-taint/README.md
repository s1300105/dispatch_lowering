# dispatch_lowering — Dynamic Dispatch Wall Resolution for Static Taint Analysis

`dispatch_lowering.py` is a preprocessing pass that resolves **dynamic dispatch
walls** in Python agent code so that static taint analysis (Pysa/TaintP2X) can
trace taint across them. It detects BoolOp walls, attribute dispatch, and subscript
dispatch, and inserts `if __ctaudit_unreachable__:` blocks that connect concrete
candidate callees to the static call graph without modifying observable semantics.

**Verified on two real OSS targets:**

| Target | Result |
|--------|--------|
| AutoGPT v0.5.0 (CVE-2024-1881) | cond_A = 0 issues → cond_B = 7 issues; 5 distinct (sink kind, first-hop callee) pairs under the legacy gate key = 2 distinct (sink kind, issue callable) pairs under the current key (re-measured 2026-08-31, version 8092345c) |
| Semantic Kernel 1.39.3 (CWE-1426/RCE) | cond_A = 0 issues → cond_B = 1 issue (code 5001) |

The AutoGPT result is identical at *port* level to the pre-2026-08 form
(same set of (code, sink kind, sink method, `formal(param, position)`) — 7 issues
because `execute_python_file` receives taint on both `filename` and `args`).
**Sink pair** = `(sink kind, issue callable)`: the sink kind of an issue and the
callable Pysa reports the issue in (`SINK_PAIRS`, the key used by `row.json` /
`summary.md`). `ablation_helpers.py count/table` prints it next to the *legacy*
key `(sink kind, first hop)` — the first entry of `resolves_to` at the root of
the backward trace, which is neither the sink method nor stable when the
engine's resolved set shrinks (`SINK_FIRST_HOPS`, kept as a diagnostic only;
review C2). `EXPECT_SINKS_B` gates the legacy first-hop count (the AutoGPT
regression is defined on it: 5); the same run has 2 `(sink kind, issue
callable)` pairs. A coarser measure than raw issues either way, since it does
not depend on Pysa's per-argument issue counting.

---

## Repository layout

```
dispatch-taint/
├── taintp2x_extension/          # the preprocessing pass
│   ├── dispatch_lowering.py     #   wall detection, candidate recovery, emitters (inline / redirector)
│   ├── links.py                 #   DispatchLink IR: wall x candidate join, precision filters, links.json
│   ├── pipeline.py              #   driver: providers (auto / hand-written links) -> passes -> instrument
│   ├── engine_walls.py          #   engine-driven wall discovery from Pysa's own cond_A artifacts (no extra pyre run)
│   ├── draft.py                 #   engine rows + derived spec + dry run -> plan.json / walls.md / report.md (review bundle)
│   ├── anchoring.py             #   registry anchoring (explicit-Intent analogue): anchors, members, reads; joins the engine rows
│   ├── catalog.py               #   spec.presets.json match/dispatch rows (IPCMethods.txt analogue): detect / stale
│   ├── r_min/                   #   in-repo excerpts of real result dirs (AutoGPT, LangChain, SK, dataset) for tests
│   ├── bench/                   #   per-idiom micro-benchmark (run_bench.py [--pyre] [--engine]); 31 fixtures in fixtures.py (2026-08-30)
│   ├── test_registration.py     #   candidate recovery + link round-trip tests; section (G) pins the links-side
│                                #   inline-receiver idiom (self.tools[k].run / getattr(o, k).m / (a or b).m -> method_call; review M1)
│   ├── test_engine_walls.py     #   engine_walls on r_min/ (pyre not needed; all checks pass — run it for the count); pins residual()'s
│                                #   relative-path keying with a same-basename, different-directory links.json (review C1) and the
│                                #   S2 stub policy (lc_0_0_131 agent.py:176/194 unlowerable, a synthetic abstract/empty fixture; review C5)
│   ├── run_benchmark.py         #   the 23 TaintP2X targets + 3 derived rows (26-row manifest): fetch -> env -> draft -> [review] -> condB -> row; aggregate; ablate
│   ├── benchmark.json           #   manifest (fetch spec, pkg_root, manual pysa_models, dataset dir, preset)
│   ├── benchmark_models/        #   the manual per-target .pysa files (sources / extra sinks)
│   ├── test_draft.py            #   draft + run_plan on r_min/ (pyre not needed; DRAFT_FULL_TREE=1 adds the untracked sk_real probe)
│   ├── test_anchoring.py        #   anchoring on a synthetic tree (incl. the review-C6 negative cases)
│   ├── test_pipeline.py         #   run_plan / providers: relative-path keys (K1), stats merge (M2), cond_A-line pins (M3), CAND_DIR (C4)
│   ├── test_ablation_helpers.py #   row.json writer: sink-pair key, net outcome set, review_edits vs plan.draft.json
│   └── test_benchmark.py        #   runner state machine / env assembly / aggregate (no network, no real pyre); runs run_ablation.sh
│                                #   once end to end with a stub pyre (cond_B timeout guard, review M5) and pins the ablate done / --force contract (review C3)
│                                #   (check counts are not written down here on purpose: every suite prints N/N passed — run it)
├── taintp2x_m2_verification/    # AutoGPT M2 verification (cond_A=0, cond_B=7; 5 legacy first-hop pairs = 2 (sink kind, callable) pairs)
│   ├── reproduce_m2.sh          # end-to-end reproduction script
│   ├── ablation_helpers.py      # ablation setup helpers (lower = pipeline / run_plan; draft; table; row.json)
│   └── run_ablation.sh          # ablation runner (EMIT=inline|redirector, LINKS_IN, DRAFT=1 / PLAN_JSON / ACCEPT_DRAFT=1 / FORCE_DRAFT=1; CAND_DIR defaults to the wall tree $WORK/cond_B/src)
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
| `JimpleIndexNumberTag` / `copyTags` | `wall=<src_root-relative file>:<cond_A line>` header tag + `# <link id>` on every inserted call; `lowered_line` (the line in the rewritten file) on both walls and links in `links.json` |
| `InfoStatistic` (Jimple lines/methods before and after) | `LoweringStats` (`stats.json`; `ablation_helpers.py table`) |
| `updateJimpleForICC` pass order | `pipeline.LoweringPipeline` (pre-passes → provider → instrument → post-passes) |
| `NoCodeElimination` + `fuzzyMe()` keep synthetic branches from being pruned | `if __ctaudit_unreachable__:` keeps the inserted block from being pruned |
| where to instrument | **not isomorphic — see "Link discovery" below.** IccTA instruments the statements an *external* ICC link analysis names; here `engine_walls.py` reads Pysa's own `call-graph.json` / `higher-order-call-graph.json` / models of cond_A plus the dispatch rows of `spec.presets.json` (`catalog.dispatch_rows`, the one vocabulary; `engine_walls.FALLBACK_DISPATCH` only when the presets file is missing): a wall is where the *engine* loses taint |

**Where the analogy stops** — worth stating precisely, because these are the
differences an examiner will ask about:

- **Link discovery, and where to instrument.** IccTA's links come from an
  external value analysis (IC3/Epicc, read from its DB or a links file) of the
  Intent at each call site, so a link is a *resolved* (call site → component)
  pair, and the statements IccTA instruments are the ones that analysis names,
  filtered by the ~30 ICC signatures of `IPCMethods.txt` (the non-comment lines:
  30 of 34 lines in `res/IPCMethods.txt` of the `soot-infoflow-android-iccta`
  checkout under `Master_Project/`; the `release/res` copy has 25). FlowDroid then
  runs unmodified. This tool has **no external link analysis**: the primary
  catalogue of where to instrument is the engine's own unresolved-call records
  (S1) and its resolutions to stubs / obscure bodies / dispatch methods (S2/S3),
  and `build_links` does not analyse the dispatch key — it enumerates wall ×
  candidate and prunes with the two filters above, so an un-narrowed wall fans
  out to every surviving candidate (recall-first). (Review M8: an earlier
  version of this table listed the row as isomorphic; RESEARCH_DIRECTION.md 追記9
  item 1 already stated the difference.)
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
  sequential `stages`, each over the previous stage's output. Positions stay in
  cond_A coordinates throughout: a later stage's (or group's) `wall_positions` /
  `reject_walls` name cond_A lines, the pipeline translates them through the
  earlier insertions (the pass only inserts lines) and translates the records
  and the `wall=<file>:<line>` header tags back, so `links.json` never mixes
  coordinate systems and `lowered_line` alone gives the final-text line. A pin
  that is not an original line — inside a generated block, or written with a
  post-stage line number — is refused as `unmatched_position` rather than
  re-located by the on-line fallback (review M3). A pin-less detect stage
  re-detects (and re-lowers) the earlier stage's wall and is translated back the
  same way.
- **No counterpart.** The Android lifecycle model (`dummyMain`), the
  `setResult` → `onActivityResult` result *callback*, and the MySQL link store.

```bash
# one-off, any target
python3 taintp2x_extension/pipeline.py --src-root cond_B/src --spec spec.json \
    --walls agent.py --emit redirector --links-out links.json --stats-out stats.json
# idiom / precision-mechanism micro-benchmark: 31 fixtures x both emission modes
#   --pyre also analyses each fixture with and without lowering: cond_A must be 0
#   (the wall really blocks Pysa) and cond_B must reach the fixture's sink callee.
#   --engine checks the engine status recorded per wall (a detected wall missing
#   from a fixture's per-line `engine` dict fails it); --record prints every
#   non-resolved engine site of the wall files to fill those dicts. run_bench
#   writes links.json / stats.json next to each cond_B tree; temp trees are per
#   fixture and removed in a finally.
#   Status 2026-08-30: all 31 pass in both modes, AST-level and with Pysa
#   (`--pyre --engine`; the two_walls_before_stub fixture is the review-C1 case).
python3 taintp2x_extension/bench/run_bench.py
# candidate recovery + links.json round-trip
python3 taintp2x_extension/test_registration.py
```

### Engine-driven wall discovery (`engine_walls.py`)

`WALL_FILES` and the spec's wall detection are the target-specific manual
inputs the scale-out design (`docs/SCALE_OUT_DESIGN.md`) removes. Instead of
asking the AST what *looks like* a wall, `engine_walls.py` reads the results
Pysa already wrote for cond_A and lists every in-repo call site where the
unmodified engine loses taint. **A wall is an in-repo call site the unmodified
engine either cannot name (S1) or names but cannot carry taint into (S2/S3) —
nothing else.** There is no reachability condition: the taint tiers T1/T2/T3
below are reported, never a gate (review M7; the `.pysa` cycle — before a
target's sources are declared every tier is empty — is why), and `none` includes
sites behind other walls or under generic models. `plan.json` `counts` carries
`accepted_by_tier` so the distribution is visible per target (whole trees such
as llama_index-0.9.28, litellm and SK show most accepted walls at tier `none`):

| status | meaning |
|---|---|
| `unresolved:<reason>` (S1) | `call-graph.json` could not name the callee — `UnknownIdentifierCallee` (`f = resolve(k); f(..)`, BoolOp), `UnknownCallCallee` (`REG[k](..)`, `getattr(o, k)(..)`), `UnknownBaseType` (`t = REG[k]; t.run(..)`; a wall only when the receiver was *selected* — a receiver returned by a call such as `logging.getLogger(__name__)` is a type gap, not a dispatch, and goes to `env_report`) |
| `resolved_stub` / `resolved_obscure` (S2) | the engine names a callee but cannot carry taint into it: an in-repo def whose body is `pass` / `...` / `raise` / abstract (`VannaBase.run_sql`, a `Protocol.__call__`), or an `Obscure` model. Only with a dynamic receiver (`self.m()`, a variable) — a stub called by its own name is not a dispatch. Its candidate set is the **class-hierarchy (CHA) destination set narrowed by the receiver's static class**: the overrides of the stub that belong to `receiver_class` (read from `call-graph.json`) or its transitive subclasses (CHA over `override-graph.json` plus in-repo `ClassDef` bases) — `BaseCache.lookup` on a `BaseCache` receiver → `InMemoryCache / RedisCache / SQLAlchemyCache`. Each row records `receiver_class`, `target_form` (`plain` / `overrides`) and `s2_reason`: `receiver_subclasses`; `receiver_subclass_no_overrides` (no override reachable from the receiver — what happens next depends on the **stub kind** (`_stub_kind`, policy decided 2026-08-30): *abstract* = `@abstractmethod` / `abc.abstractmethod` / `abstractproperty`, or a body that raises `NotImplementedError`; *empty* = `pass` / docstring-only / `...` / any other `raise`. An **empty** stub on a concrete leaf receiver with no overriding subclass is `resolved` — the bare resolution was exact, not a wall (`Agent._validate_tools`, body `pass`, on a `ChatAgent` receiver: the three sibling `cls._validate_tools` sites of langchain-0.0.131). An **abstract** stub whose receiver is the owner itself or a non-implementing subclass with no in-tree override reachable from it stays a wall, an *unlowerable* one: status `resolved_stub`, 0 candidates, `confidence: proposed`, `accept: false`, note `unlowerable: no in-tree implementation of <owner>.<m>`, counted in `residual_unlowerable` — `self.output_parser.parse` at `agents/agent.py:176/194` (`AgentOutputParser.parse`, `@abstractmethod`, receiver == owner). Rationale: under the wall definition — a site the engine names but cannot carry taint into — the abstract call is a wall even though nothing in the tree can be linked; hiding it would understate the residual. Open edge: a trivial body raising an exception other than `NotImplementedError` counts as *empty*); `receiver_unknown` (the engine typed no receiver, incl. `typing.Protocol` receivers — the candidates then come from decorator / anchor recovery, not overrides; such rows stay pre-accepted, the unlowerable rule never widens to them). Plain functions are unreasonable for it (they cannot override a method). (Review C5: an earlier version took every override of the declaring class, regardless of receiver.) |
| `resolved_dispatch:<api>` (S3) | a framework dispatch method (catalogue row such as `BaseTool.run`, or the callee's own higher-order record forwarding to `Overrides{BaseTool._run}`). **In a typed tree the engine follows the override set itself** — LangChain's typed cond_A already reports the issue — so such rows are `proposed`, not pre-accepted; they become real walls when types are erased or the framework body is not in the tree |

Each row carries the idiom, the resolver and key expression
(`self._get_command[tool_call.name]`, `name_to_tool_map[agent_action.tool]`),
the taint tier (T1 a source / parameter-source position of a model touches the
call — tito and sink summaries do not count —, T2 the enclosing callable carries
a source, T3 reachable from one — an ordering aid, never a gate), the receiver
column of `walls.md` (`receiver` = receiver class short name, `(plain|overrides)`,
`s2_reason`, between `engine` and `tier`) and a pre-set review flag. On AutoGPT's cond_A (150 in-repo call sites, 96
unresolved) exactly one row is accepted: `agent.py:277:21`.

```bash
python3 taintp2x_extension/engine_walls.py scan cond_A --out draft/      # walls.md, engine_walls.json, env_report.json
python3 taintp2x_extension/engine_walls.py residual cond_B --links cond_B/links.json
python3 taintp2x_extension/engine_walls.py dataset-scan <TaintP2X dataset>/call-graph.json   # count-only, no tree needed
python3 taintp2x_extension/test_engine_walls.py                            # all checks on r_min/, no pyre (prints N/N passed)
python3 taintp2x_extension/bench/run_bench.py --engine                     # Pysa on each fixture + engine status check
```

**Residual** (`residual`, `row.json` `residual`): the T1/T2 walls that are still
`unresolved` / `resolved_stub` / `resolved_obscure` in cond_B, *excluding* sites
inside generated guard blocks and redirector modules (status `generated`,
`counts.generated`), keyed by src_root-relative file, with cond_B lines mapped
back to cond_A through the generated spans (so a lowered wall shifted by an
insertion is netted, not counted). Output keys: `residual_raw` / `residual`
(net) / `lowered_walls` / `generated_excluded` / `remapped` / `legacy_links`, plus
the two splits of the net — `residual_confirmed` (net walls whose `confidence`
is `confirmed`, i.e. the rows the draft pre-accepts: the engine or the draft's
recovery named their candidates and the lowering still left them) and
`residual_unlowerable` (net walls with `s2_reason == receiver_subclass_no_overrides`:
abstract stubs with no in-tree implementation, nothing to link by
construction) — and rows with `line_cond_b` / `line_cond_a` / `confidence` /
`s2_reason` / `engine_status`. `row.json` carries them as `residual.confirmed` /
`residual.unlowerable` and `residual_rows[].confidence`; `summary.md` has the
columns `residual_confirmed` / `residual_unlowerable` next to `residual_net`
(blank for rows made before the split); the `residual` CLI prints a one-line
summary on stderr (`residual: raw N net M (confirmed X, unlowerable Y); …`) and
keeps the JSON document on stdout. Reading rule: `residual_net − residual_unlowerable`
= walls that could have been lowered but were not; `residual_confirmed` = the
subset of those with a confirmed idiom. A pre-C1 `links.json` (basename keys) is
accepted with a warning and `legacy_links: true`. Proposed rows count as well
(constant-key inline subscript receivers such as `output['k'].strip()` are
now `method_call` walls) — `residual_confirmed` is the pre-accepted-only view
(the answer to the accepted-only question).
Every residual figure in the committed `benchmark_out` is now measured under this
definition at one tool version (re-measured 2026-08-31, version 8092345c), with
`residual_confirmed` / `residual_unlowerable` filled on every row that has a net
residual.
### Draft → review → run (`draft.py`, `plan.json`)

`draft.py` turns the engine's rows into one reviewable `plan.json`: a group per
wall file whose spec pins the walls (`wall_positions`, every `detect_*` false —
detection never runs on a draft), a recovery spec derived from the tree with a
`_provenance` line per key (`tool_decorators: ["command"]` ← `forge.command.command x4`
in `decorator-counts.json`), and a **dry run** of the pipeline
(`run_spec(write=False)`) that records every accepted wall's fan-out
(lowered / filtered / unreasonable / phantom). Rows that fan out to more than
`FANOUT_MAX` (16) targets without any narrowing are demoted to `proposed`; the
group is then dry-run again with the row off, so a demoted wall's links are not
in `links.draft.json` / the `dry_run` stats and the row keeps its first-pass
fan-out under `dry_run.demoted` (regression: `test_draft.py::test_stub_wall_fixture`,
a stub wall with 17 decorated methods → proposed). A
BoolOp wall gets its def-valued alternatives as level-1 candidates
(`boolop_member`, the explicit-Intent case) and a per-wall `match_level: 1`, so
`update_func = filter_update_function or default_dynamic_filter_function` lowers to
the one named function even though `@kernel_function` marks 48 others.
`plan['hints']` lists what the reviewer should look at, one entry per kind:
`stage2` (a lowered target itself contains engine walls), `no_candidates` (an
accepted wall with no link at all), `phantom`, `fan_out` (more than 8 lowered
targets), `unlowerable` (a `resolved_stub` row with 0 candidates and
`s2_reason: receiver_subclass_no_overrides` — an abstract stub with no in-tree
implementation; it stays a proposed, off row and will show up in
`residual_unlowerable`), `env` and `catalog`. `build_plan` never accepts such a
zero-candidate `resolved_stub` row — `--include-proposed` included — unless an
anchor read supplied members for it; the row's note names the missing
implementation.

```
cond_A/r ──► engine_walls.scan ──► rows ──► derive_spec ──► dry run ──► plan.json + walls.md + report.md
                                                                          │  (review: flip accept, prune keys,
                                                                          │   add analyst-pinned `stages`)
                                                                          ▼
                                                 pipeline.run_plan ──► cond_B/src  (G<i>W.. / G<i>S<j>L.. ids)
```

The bundle (`$WORK/draft/`): `plan.json`, `plan.draft.json` (the untouched
original, mode 0444 — `row.json` `review_edits` is the diff between it and the
plan cond_B was built from; review C7), `walls.md`, `report.md`,
`spec.draft.json`, `wall_files.txt`, `candidates.draft.json`,
`links.draft.json`, `anchors.json`, `env_report.json`. `PLAN_VERSION` is 2 (a v1
plan is still readable via `draft.load_plan`): `plan['tool_version']` = sha256 of
`engine_walls / links / draft / anchoring / catalog / pipeline / dispatch_lowering /
spec.presets.json / ablation_helpers / run_ablation.sh` (`toolver.py`, also
stamped on `row.json`, `ablation.json` and `state.json`; the summary flags rows
whose fingerprint differs from the current code as `versions_match: no` and
plans without one as `plan unversioned`); `plan['counts']` has `walls` /
`accepted` recomputed from the table plus `engine_walls` / `engine_accepted`,
`by_origin`, `accepted_by_tier`, `accepted_by_origin`; `plan['catalog']['top']`
is the seeding preset. An explicit `--preset` beats the detected one; the keys
taken from a preset are `tool_decorators, tool_base_classes, tool_impl_methods,
register_methods, tool_list_names, tool_wrappers, registry_vars,
wrapper_func_kwargs, scan_all_callables, candidate_module_root`, and
`_provenance` names the supplier per key (`preset X (--preset)` /
`preset Y (detected by catalog.detect)`).

```bash
# the ablation runner drives all of it (WALL_FILES / SPEC_JSON are no longer needed):
DRAFT=1        ./run_ablation.sh    # cond_A + pyre once, writes $WORK/draft/{plan.json,plan.draft.json,walls.md,...}, stops (exit = outcome)
PLAN_JSON=$WORK/draft/plan.json ./run_ablation.sh      # cond_B from the REVIEWED plan.json (never plan.draft.json: the preflight refuses it), diff, pyre, table, row.json
ACCEPT_DRAFT=1 ./run_ablation.sh    # unattended: draft and lower it as is (regression / batch)
#   a DRAFT=1 / ACCEPT_DRAFT=1 re-run keeps $WORK/draft/plan.json when it differs from plan.draft.json
#   (= carries review work); FORCE_DRAFT=1 discards it. CAND_DIR (candidate scan root) defaults to the
#   wall tree $WORK/cond_B/src — scanning TARGET_SRC *and* its copy saw every registry twice and
#   untrusted all of them, which silently switched registry narrowing off in the real cond_B (review C4).
#   A cond_B pyre timeout / failure writes row.json (env_failed) and exits 1; cond_{A,B}/pyre_rc
#   (124 = timeout) sits next to pyre_seconds.
python3 taintp2x_extension/pipeline.py --src-root cond_B/src --plan plan.json [--walls agent.py] [--emit redirector]
python3 taintp2x_extension/test_draft.py                                   # draft + run_plan on r_min/, no pyre (all checks pass)
python3 taintp2x_extension/test_pipeline.py                                # run_plan / providers (K1 / K2 / C4 / M2 / M3)
```

### Anchoring and the catalogue (`anchoring.py`, `catalog.py`, `spec.presets.json`)

Two complements of the engine rows, both on the AST side:

- **Registry anchoring** — IccTA's *explicit* Intent: a call site that names its
  own destination set. An *anchor* is a dict/list literal whose values resolve
  to defs or classes, an attribute assigned a def (`self.run_sql = run_sql_sqlite`,
  once per backend in vanna), a registration call (`mcp.add_tool(fn)`), or a
  `self.attr[k] = fn` assignment. Anchors are keyed by their defining module
  (`pkg.mod.REGISTRY`, `pkg.mod.Cls.attr`; `anchors.json` `name` is the
  qualified name, `short` the display name) — two modules' `type_to_loader_dict`
  are two anchors, never one. An anchor is **closed** only under the conditions
  the implementation checks (review C6): every member is a visible def / class /
  instance; the name is bound once at module level and never mutated in any
  scope — item assignment `NAME[k] = v`, `del`, `.update / .pop / …`, `+=` /
  `|=`, `global NAME` + assignment — including through imports and module-level
  aliases (an alias `ALIAS = NAME` itself opens the anchor); and for `Cls.attr`
  additionally no `self.attr = <runtime value>` (parameter, call, `None`, empty
  literal, …) anywhere, no class-body declaration of the attribute
  (`Field(...)`, `PrivateAttr`, an annotation) in the class or its in-tree
  bases, and no subclass binding it. Registrations into objects outside the
  tree (`os.environ`, `loguru.logger`) are not anchors. Its reads (`A[k](..)`,
  `A.get(k)(..)`, `t = A[k]; t.run(x)`, `for t in A: t.run(x)`, `self.attr(..)`)
  join the engine rows: an engine wall reading a closed anchor gets the members
  as level-1 candidates *and* narrowing; a read the engine resolved (typed
  registry) or has no site for is listed `proposed` (off). A `self.attr` read
  from a *subclass* of the anchor's class is an **inherited** read
  (`AnchorRead.binding = "inherited"`, `anchor_closed` false): candidates only,
  never narrowing, never confirmed; unrelated classes that merely share the
  attribute name are never joined. Anchors carry their evidence lines and can be
  rejected by the qualified name printed in `anchors.json` (`--reject-anchor
  pkg.mod.NAME`; the short name is still accepted) — provider maps and logging
  callbacks are the usual false anchors, and a map of strings is never an
  anchor. Not a value analysis; documented limits: a registration that stores
  into `self.<attr>` through a method is not linked to the attribute, members
  of a comprehension over a parameter are unknown, inherited reads never narrow
  (a vanna-style subclass reading a base-assigned attribute stays proposed),
  and a registry defined outside `src_root` but filled in-tree is invisible.
- **Catalogue** — `spec.presets.json` carries, per framework, `match` (import
  roots / base classes / decorators that mean "this tree uses it") and
  `dispatch` rows (`BaseTool.run → _run`, `KernelFunction.invoke → _invoke_internal`,
  `ToolCollection.execute → execute`, …): one file, 17 rows (langchain 4,
  semantic_kernel 2, openmanus 2, llama_index 5, fastmcp 2, openai_agents 1,
  superagi 1), the `IPCMethods.txt` analogue. `match.imports` entries are dotted
  prefixes (plus imported names for from-imports); relative imports never count;
  openmanus matches `app.tool` / `app.agent` (+ the `ToolCallAgent` base),
  openai_agents `agents.tool / agents.run / agents.function_tool / agents.Runner /
  agents.RunContextWrapper`. `catalog.detect` scores the frameworks a tree
  uses (import / base-class / decorator counts);
  `catalog.top_preset` is the preset a draft seeds recovery keys from (import
  or discriminating base-class evidence, never a decorator alone) and
  `catalog.framework_of` the framework a draft is *attributed* to in every
  table (`plan.catalog.framework`, `row.json` `draft_framework`, the
  summary.md "by framework" table): the seeding preset only when its score
  reaches `match.min_score` (default `FW_MIN_SCORE` = 20), else `(none)`.
  When a draft accepts nothing and the attributed framework has none of its
  dispatch APIs defined *in the tree* (`env_report.json` `catalog_status`: the
  `functions.json` names whose module is an in-repo file — a row found only on
  the analysis search path such as the venv is listed separately as
  `catalog_status_search_path` and named "on the analysis search path only"),
  the outcome is `catalog_stale` (exit 3) rather than `no_surface` (exit 2):
  **`catalog_stale` = the framework's dispatch API is absent from the in-repo
  callables** — a row present only in the venv still counts as stale, so it can
  now fire for frameworks installed only in the venv (review M4). An incidental
  import below the threshold never makes the catalogue stale; a decorator-only
  hit (click `@command`) never seeds, so litellm is attributed `(none)` and
  SuperAGI `superagi`.

```bash
python3 taintp2x_extension/anchoring.py cond_A/src --engine cond_A     # anchors, members, reads, engine join
python3 taintp2x_extension/catalog.py detect cond_A/src                # frameworks matched, with counts
python3 taintp2x_extension/draft.py cond_A --reject-anchor PROVIDERS --disable S3   # review knobs / leave-one-out
python3 taintp2x_extension/test_anchoring.py                          # synthetic tree, all checks pass
```

`--disable S1,S2,S3,anchoring` (draft / engine_walls) is the leave-one-out
axis of the evaluation: each engine class or the anchoring complement can be
switched off and the plan records which, so `row.json` rows are comparable.

### Batch: the 23 TaintP2X Benchmark targets + 3 derived rows (`run_benchmark.py`, `benchmark.json`)

`benchmark.json` is the manifest (one row per target: `fetch` as a git tag /
pypi sdist / local path, `pkg_root` dirs copied under `src/`, the **manual**
`pysa_models` file from `benchmark_models/`, the dataset's own `pysa-runs` dir
for a count-only pre-check and the reference issue count, a preset hint, and
optionally `subset: {"pkg", "entries"}` — the import closure of the package
from the entry files, with external deps isolated by `subset_extractor`
(`deps_iso` / `stubs_min` on the search path instead of the venv) — for the
trees that do not finish within the 1200 s budget as a whole).
The 26 rows are the 23 TaintP2X Benchmark targets plus 3 **derived** rows
(`"derived": true`, `derived_from` = the Benchmark target they come from) that are
not Benchmark targets themselves: the committed AutoGPT M2 subset
(`AutoGPT-classic-subset`, with its manual `.pysa`) and the two import-closure
`*-agents-subset` rows of the langchain trees that time out as a whole. A derived
row is a separate tree with its own draft / review / cond_B; the dataset reference
count is shown on its parent row only (review M11). A derived row is **not a
controlled comparison** with its parent: AutoGPT whole tree vs
`AutoGPT-classic-subset` and langchain-0.0.327 whole vs `-agents-subset` differ
in fetch / `pkg_root` / `search_venv` / `.pysa` naming / `deps_iso` at the same
time; the subset + `.pysa` rows are delta_pos and the whole + generic rows
`no_sources` / `env_failed`, and because venv exclusion and subsetting were
applied together the factors are not separated (review M9).
`run_benchmark.py` drives each target through `fetch → env → draft → [review]
→ condB → row`, resumably (`work/<name>/state.json`, `--force` to redo a
stage), with pyre bounded by `pyre_timeout` (1200 s) and `cond_A` reused
between the draft and the lowering run (`REUSE_COND_A=1`). The manifest's
per-target `pyre_timeout` knob raises that bound where a target needs more than
the 1200 s default: `_ablation_env` overrides the `PYRE_TIMEOUT` env var with
`t.spec.get("pyre_timeout", 1200)`, so a manifest row can request e.g. 3000 s
(quivr's cond_B needs `pyre_timeout: 3000` to finish, then lands `delta0`).
`--stage draft`
stops at the review bundle; `--stage condB` refuses an unreviewed plan unless
`--accept-draft`; `aggregate` writes `summary.{jsonl,csv,md}` (one row per
manifest entry — a target never started shows as `pending` instead of being
dropped — with the derived rows in their own table and their own outcome line;
`walls_accepted` = walls the plan let through at lowering time and
`walls_lowered` = walls that got at least one lowered link in `cond_B/links.json`
are separate columns (review M6); `residual_net` is followed by
`residual_confirmed` / `residual_unlowerable`, the split of the net residual
(blank for rows made before the split); per-framework catalogue / anchor /
confirmed-proposed-accepted counts, outcome histogram); `--stage ablate` produces the leave-one-out table
(`--disable S1 / S2 / S3 / anchoring`, draft level; `--ablate-pyre` adds the
cond_B delta per axis).

```bash
python3 taintp2x_extension/run_benchmark.py --stage draft                      # all 26 rows (23 targets + 3 derived), unattended up to the review
python3 taintp2x_extension/run_benchmark.py --stage all --accept-draft --only OpenManus vanna-0.6.2
python3 taintp2x_extension/run_benchmark.py --stage ablate --only AutoGPT-autogpt-platform-beta-v0.5.0
python3 taintp2x_extension/run_benchmark.py --stage aggregate                  # benchmark_out/summary.md
```

`PYRE_SEARCH_VENV=0` keeps the active venv's `site-packages` out of Pysa's
`search_path` (the default adds it when `VIRTUAL_ENV` is set): for a target
whose dependencies are vendored or irrelevant this is 10–100x faster (AutoGPT:
a 44 KB instead of a 156 MB call graph) and is how the committed AutoGPT
verification was produced.

Each run also writes `$WORK/row.json` (one target = one row: environment
state, pyre seconds, unresolved reasons, walls by engine status / origin,
`review_edits` vs the read-only `plan.draft.json` (`draft_source` says which
file was diffed — a row built from a bundle without `plan.draft.json` reports
0 flips as *not observable*, not as "no edits"; the committed benchmark_out is
now re-drafted at one tool version so every row carries `plan.draft.json` and
`review_edits` is observable — and reads 0 by design, since every row was lowered
unattended with `--accept-draft`, so the diff has nothing to record
(re-measured 2026-08-31, version 8092345c)), link statistics (`links.walls_lowered`
= distinct walls with a lowered link), `accepted_by_tier`, issues and sink pairs
A/B under the `(sink kind, issue callable)` key — with the pairs **new** in
cond_B and the pairs **lost** (both are reported; under the old first-hop key
"lost" pairs were the same issue set re-keyed when a call site's `resolves_to`
shrank — cause unconfirmed) plus the legacy `first_hops` diagnostic —, residual
walls (`residual.raw / net / lowered_walls / generated_excluded / remapped /
legacy_links / confirmed / unlowerable`, and `residual_rows[]` with `confidence` /
`s2_reason` / `engine_status` per wall), `tool_version` / `plan_tool_version` /
`versions_match`, and
`outcome` ∈ {`env_failed`, `no_sources`, `no_surface`, `catalog_stale`,
`no_walls` (the draft accepted 0), `no_candidates` (accepted > 0 but
`links_lowered` 0; `outcome_reason` ∈ no_links / phantom_majority /
unreasonable_majority / filtered_*_majority / no_args_majority / mixed),
`drafted` (no cond_B yet), `delta_pos` (new > 0, lost == 0), `delta_mixed`
(new > 0, lost > 0), `delta_neg` (new == 0, lost > 0), `delta0`}. A cond_B pyre
timeout is an `env_failed` row, never "cond_B issues = 0". `run_benchmark._table_outcome`
gives an environment verdict (`no_sources` / `no_surface` / `catalog_stale`)
precedence over a vacuous `0 → 0` delta0: when cond_B runs but produces the same
empty result the draft's environment verdict predicted, the table keeps that
verdict rather than reporting `delta0` (AutoGPT's whole tree: cond_B measured
`0 → 0`, table stays `no_sources`). The committed `benchmark_out` is now re-run
at one tool version under the current 11-value vocabulary and the (sink kind,
issue callable) key (re-measured 2026-08-31, version 8092345c)).
The plan keys are ordinary spec keys, so a hand-written spec may use them too:
`wall_positions` (`path:line[:col]` or `{"at", "callee", "end", "accept", "match_level", …}`),
`reject_walls`, `wall_files`, `exclude_paths`. Both position keys always name
cond_A lines, also in an analyst-pinned second `stages` entry or a later group on
a file an earlier group already rewrote: the pipeline remaps them through the
earlier insertions, and a line that no longer is an original line is reported
`unmatched_position` (review M3; `test_pipeline.py` (e)/(e2)). In `links.json`
(`WallRecord.file`, `DispatchLink.file`) and in a hand-written links file
(`--links-in` / `LINKS_IN`, `links.manual.json`), `file` is the wall file's path
relative to `--src-root` (POSIX) or an absolute path — a bare basename no
longer matches anything (`prompts/base.py` and `chains/base.py` used to be one
key; review C1 / K1); an omitted `file` means every wall file.
`dump_links(extra=)` adds top-level keys (`tool_version`).

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
(sink kind, first hop) pairs (`SINK_FIRST_HOPS`, the legacy key `EXPECT_SINKS_B`
gates) = 2 distinct (sink kind, issue callable) pairs (`SINK_PAIRS`, the
`row.json` key) (re-measured 2026-08-31, version 8092345c: `EXPECT_SINKS_B=5`
still passes, and the row's current-key sink pairs are 2, new 2, lost 0). The
only difference is the lowering insertion in
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
  scope. It still keys registries by bare name (not by module), so a name bound
  in two modules is untrusted even when the definitions agree (the index cannot
  tell which object a wall reads; precision lost, never recall). `index_registries`
  de-duplicates files by realpath and content hash **only** (no relative-path
  skip): an identical copy of a file seen through two scan roots counts once, so
  the wall tree itself can be `CAND_DIR` without losing narrowing (review C4 /
  K6), but a file that *differs* at the same relative path under two directory
  roots (tree a: `REGISTRY = {x}`, tree b: `REGISTRY = {x, y}`) is two bindings
  and untrusts the name — the same verdict as when the twin is given as a file
  root (review C4 caveat, decided 2026-08-30; a relative-path skip would have
  silently kept the first tree's literal). When any condition fails the
  candidate set is kept whole.
- **The `unreasonable` filter assumes the wall calls the target with the
  target's own signature.** That holds for a direct dispatch; it does not hold
  through a framework's dispatch method (`tool.run(x, verbose=…)` reaching
  `_run`) or a decorator that returns a wrapper (`@tool` → `StructuredTool`), so
  the signature check is skipped for those and the link is kept. A second,
  name-level check does survive the dispatch method: an `x.m(...)` wall keeps
  a *class-method* candidate only if it is named `m` or an impl method the
  catalogue says `m` forwards to (`dispatch_impl_map`: `run → _run`,
  `invoke → _run`, `execute → execute`); function candidates, anchor members
  and explicit records are exempt. The map a draft writes is built from the
  catalogue rows of the *active* frameworks — the ones the tree imports plus the
  explicit `--preset` and the detected top preset — and is written even when
  empty (`LoweringSpec.impl_map_source = "spec"`); `DEFAULT_IMPL_MAP` survives
  only for a hand-written spec without the key (`impl_map_source = "default"`),
  and no code path unions every framework's rows any more (review M10). An
  accidental import brings that framework's rows in (langchain-0.0.131 imports
  llama_index in 4 files → `call / acall / __call__` rows) and the reviewer may
  prune the key; the committed `benchmark_out` plans still carry the merged map. It removes the `BaseTool._run` fan-out
  from `self._validate_tools()`-style walls but cannot tell two tools' `_run`
  apart — that remains the registry's / anchor's job.
- **Only argument-carried taint crosses the wall.** A class target is called on
  `Cls.__new__(Cls)`, so taint that would reach the sink through constructor
  state (`self.cmd` set at registration) is not modelled.
- **The lowered tree does not run.** `__ctaudit_unreachable__` is undefined, so
  evaluating a lowered wall raises `NameError`. `cond_B` is an analysis-only copy.

Every dropped wall or link is recorded with its reason in `links.json`, and each
reason has its own counter in `stats.json` (`filtered_registry`,
`filtered_level`, `unreasonable`, `no_args`, `phantom`), so a coverage claim can
be checked against the numbers rather than assumed.
