# 方向C — Intra-Tool Argument Reachability (precision, recall-safe)

The precision counterpart to the earlier recall work. It addresses the
over-approximation that has been the system's main precision bottleneck: a tool is
flagged as a sink whenever its body contains a dangerous call (`subprocess.run`,
`exec`, …), **regardless of whether the dispatched argument can actually reach that
call**. A tool that uses its argument only to look up a fixed, validated value was
flagged at the same severity as one that passes its argument straight to a shell.

## What it does

For each tool body that contains a dangerous call, an intra-function taint check
classifies the dangerous argument:

- **`reaches`** — a parameter provably flows into the dangerous argument (directly,
  or through simple `y = <tainted expr>` assignments, f-strings, string
  concatenation, or container literals). This is the precise true positive.
- **`not`** — no parameter reaches the dangerous argument, and every argument is
  built only from constants or non-parameter-derived values (e.g. the parameter is
  used solely as a dictionary key, and the looked-up value reaches the sink). This
  is the over-approximation case.
- **`unknown`** — flow could not be decided (the value passes through a call,
  attribute access, comprehension, or an unresolved name). Kept conservatively.

## Recall-safety (the key design constraint)

The verdict **never drops a sink**. A `not` verdict only **downgrades severity**
(high → low); the finding is still reported. Everything that is not provably clean
is `unknown` and keeps its category severity. So an imperfect or incomplete flow
analysis can, at worst, leave a true positive at full severity — it can never turn a
real flow into a missed one. This is consistent with the project's recall-first
discipline and with the decision not to claim soundness lightly.

Concretely, the three-valued lattice is conservative:
- assignment from a call result (`cmd = transform(arg)`) makes the target
  `unknown`, not clean — so a value laundered through a helper is never silently
  treated as safe;
- a subscript using a parameter as a key (`ALLOWED[name]`) yields a clean result
  *with respect to the parameter's value* (the value stored in `ALLOWED` reaches the
  sink, not `name`), which is exactly the distinction that separates a genuine
  validation pattern from a dangerous pass-through.

## Demonstration

`fixtures/reachability_demo.py` registers two tools with one framework agent, both
containing `subprocess.run`:

| tool | how the argument is used | verdict | severity |
|---|---|---|---|
| `run_cmd` | `subprocess.run(command, shell=True)` | `reaches` | high |
| `lookup` | `safe = _ALLOWED[key]; subprocess.run([..., safe])` | `not` | **low** |

End-to-end (`python3 hybrid.py fixtures/reachability_demo.py`) both are reported as
CWE-1426 dispatch resolutions, but `lookup` is downgraded to low while `run_cmd`
stays high. A body-only scan would have reported both at high severity.

## Scope and limits

- This is a **lightweight, conservative** intra-procedural check, not a full
  dataflow analysis. It deliberately answers `unknown` for anything it cannot decide
  cheaply (inter-procedural flow, aliasing through containers, attribute writes).
- It runs only on **user-code tool bodies**. A known dangerous *library* tool
  (resolved by 方向B, e.g. `PythonAstREPLTool`) has no analysable body here, so its
  reachability is `None` (unanalysed) and it keeps full severity.
- It refines **severity / confidence**, not the detection set. Precision in the
  strict TP/FP sense (per the project's evaluation notes) is improved by making the
  obviously-non-reaching cases distinguishable and downgradable, without sacrificing
  recall.
