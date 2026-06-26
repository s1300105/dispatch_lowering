# Generic wall-resolution ablation

`run_ablation.sh` measures the issue DELTA that dispatch wall resolution adds to
the host analyzer (TaintP2X/Pysa):
- **cond_A** = host alone (baseline)
- **cond_B** = host + wall resolution (`dispatch_lowering` applied to `WALL_FILES`)

Only the lowering insertion differs between conditions.

## Files
- `run_ablation.sh` — the harness (config-driven via env vars).
- `ablation_helpers.py` — pyre config / lowering / issue-count (no heredocs).
- `dispatch_lowering.py` — generalized wall-resolution pass (drop-in for the original).
- `spec.autogpt.json` — legacy spec (reproduces AutoGPT exactly; for validation).
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
