# Generic wall-resolution ablation

`run_ablation.sh` measures the issue DELTA that dispatch wall resolution adds to
the host analyzer (TaintP2X/Pysa):
- **cond_A** = host alone (baseline)
- **cond_B** = host + wall resolution (`dispatch_lowering` applied to `WALL_FILES`)

Only the lowering insertion differs between conditions.

## Files
- `run_ablation.sh` — the harness (config-driven via env vars).
- `ablation_helpers.py` — pyre config / lowering / issue-count / statistics table.
- `../taintp2x_extension/{dispatch_lowering.py,links.py,pipeline.py}` — the pass, the
  link IR and the driver the `lower` step imports (located via `EXT`, default
  `$ROOT/dispatch-taint/taintp2x_extension`).
- `spec.autogpt.json` — legacy spec (original detection/candidate rules; for validation).
- `spec.general.example.json` — template spec for new (non-agent) targets.
- `target.example.pysa` — template source/sink declaration.

## Source/sink kinds
Host source kinds: `LLMControlled`, `FromUrlLLMControlled`.
Host sink kinds: `RemoteCodeExecution`, `ExecArgSink`, `ExecImportSink`,
`ExecDeserializationSink`, `FileContentDeserializationSink`, `ExecEnvSink`,
`SQL`, `SSRFSink`, `FileSystem_ReadWrite`, `FileSystem_Other`, `EmailSend`,
`XSS`, `FormatString`, `Logging`, `ReturnedToUser`.
For non-agent targets, reuse `LLMControlled` as the attacker-controlled source label.

## Run
Set the REQUIRED env vars (see top of `run_ablation.sh`) and run it.
Optional `EXPECT_A` / `EXPECT_B` assert exact counts (regression).

Optional:
- `EMIT=inline|redirector` — generated-code form. `redirector` writes one
  `redirector_N` per link into `cond_B/src/__ctaudit_redirect.py` and calls it
  from the wall (IccTA `IpcSC.redirectorN` analogue).
- `LINKS_IN=links.json` — use hand-written / previously saved links instead of
  automatic resolution (IccTA config-file provider analogue). Useful to check
  that the *emitter* alone reproduces a result, isolating the resolver.

Outputs (besides `cond_{A,B}/r/taint-output.json`):
- `cond_B/links.json` — every detected wall and every wall→target link with its
  decision (`lowered` / `filtered_registry` / `unreasonable` / `phantom`), the
  forwarded arguments and the line of the inserted call.
- `cond_B/stats.json` — `LoweringStats`; step 7 prints it as a table next to
  the A/B issue counts (evaluation row).

Regression (AutoGPT, both emission forms). `EXPECT_SINKS_B` asserts the number of
distinct (sink kind, sink callee) pairs — a coarser measure than the raw issue
count, which is per tainted-argument flow (`execute_python_file` contributes two
issues per kind, for `filename` and `args`):
```bash
export TYPESHED=<repo>/.venv/lib/pyre_check/typeshed      # pyre-check's bundled typeshed
TARGET_SRC=$PWD/cond_A/src WALL_FILES=agent.py PYSA_MODELS=$PWD/cond_A/source/autogpt_v05.pysa \
SPEC_JSON=$PWD/spec.autogpt.json EXPECT_A=0 EXPECT_B=7 EXPECT_SINKS_B=5 EMIT=inline     ./run_ablation.sh
SPEC_JSON=$PWD/spec.autogpt.json EXPECT_A=0 EXPECT_B=7 EXPECT_SINKS_B=5 EMIT=redirector ./run_ablation.sh   # (same env)
```
