# TaintP2X M2-level Verification — Reproduction Guide

This directory reproduces, on the **real AutoGPT** repository, the effect of adding
this work's **dynamic-dispatch lowering** pass to **TaintP2X**'s static taint
propagation (its M2 module):

```
condition A  (TaintP2X M2, no lowering)   →  Found 0 issues
condition B  (TaintP2X M2, + lowering)    →  Found 7 issues
```

The only difference between A and B is a lowering insertion into AutoGPT's `agent.py`
(proved by `diff`). TaintP2X itself is used **unmodified**; the lowering is a
preprocessing step applied to the cloned target source.

Since 2026-08-29 the inserted block carries the current emission form — the
`wall=<file>:<line>` header tag, a constructed receiver
(`CodeExecutorComponent.__new__(...)`) so each target runs as a bound method, and
a `# <link id>` comment per call that matches `cond_B/links.json`. The issue count
and the reached sinks are unchanged; only the shape of the inserted code differs
from the `if False:` form described in older revisions of this guide.

See `VERIFICATION_M2.md` in this directory for the full write-up (positioning,
results, honest scope limits). This README is the operational guide: how to install
the two external dependencies and run the reproduction.

---

## Why two external repositories are required

This verification analyzes a real target with a real base analyzer. Neither is part
of this project (they are large third-party projects with their
own licenses), so they are **not** pushed to git and must be obtained locally:

1. **AutoGPT** — the analysis *target*. We use the TaintP2X-benchmark version
   (`autogpt-platform-beta-v0.5.0`, commit `9210d44`), the same version whose
   CVE-2024-1881 appears in TaintP2X's ground-truth table.
2. **TaintP2X** — the *base analyzer*. We use its taint definitions
   (`Taint_Propagation/taint`), stubs, and the same `pyre analyze --no-verify`
   invocation. TaintP2X is the unmodified baseline.

The lowering pass itself (`taintp2x_extension/dispatch_lowering.py`) and the
verification scaffolding (this directory) **are** in the repo.

---

## Expected directory layout

The reproduction script assumes the following layout. `dispatch-taint/` is this
project; `TaintP2X/` and `autogpt/` are the two external repos placed as siblings
of it under a common root (`dispatch-taint-system/` here, but any name works):

```
<ROOT>/                              # dispatch-taint-system
├── dispatch-taint/                  # THIS project
│   ├── taintp2x_extension/
│   │   ├── dispatch_lowering.py     # the lowering pass (this work)
│   │   ├── links.py                 # the DispatchLink IR + precision filters
│   │   └── pipeline.py              # the driver used by run_ablation.sh
│   ├── taintp2x_m2_verification/    # this directory
│   │   ├── reproduce_m2.sh
│   │   ├── run_ablation.sh
│   │   ├── README.md                # this file
│   │   └── VERIFICATION_M2.md
│   └── ...
├── .venv/                           # venv with pyre-check (see below)
├── TaintP2X/                        # external: base analyzer
│   └── Taint_Propagation/{taint,stubs}
└── autogpt/                         # external: analysis target (v0.5.0)
```

If your layout differs, every path is overridable by environment variable
(see "Overriding paths" below); you do not have to match this exactly.

---

## Step 0 — Prerequisites

- Python >= 3.10 (verified on 3.12.3)
- git
- A virtual environment with **pyre-check** installed (provides `pyre` and the
  bundled typeshed). Install it explicitly:

```bash
cd <ROOT>
python3 -m venv .venv
source .venv/bin/activate
pip install pyre-check
pyre --version          # sanity check
```

Locate the bundled typeshed (the script's default expects it under the venv):

```bash
python3 -c "import os,glob; print(next(iter(glob.glob(os.path.expanduser('<ROOT>/.venv/**/typeshed'), recursive=True)), 'NOT FOUND'))"
```

Typically `<ROOT>/.venv/lib/pyre_check/typeshed`.

---

## Step 1 — Install AutoGPT (analysis target)

Clone AutoGPT as a sibling of `dispatch-taint/` and check out the benchmark version.

```bash
cd <ROOT>
git clone https://github.com/Significant-Gravitas/AutoGPT.git autogpt
cd autogpt
git checkout autogpt-platform-beta-v0.5.0      # detached HEAD is expected
git rev-parse --short HEAD                       # should print 9210d44
```

Confirm the two paths the lowering pass reads:

```bash
cd <ROOT>
ls -d autogpt/classic/forge/forge/components/code_executor          # @command source
ls    autogpt/classic/original_autogpt/autogpt/agents/agent.py      # the wall (agent.py)
```

You do **not** need to install AutoGPT's dependencies or run it — only its source is
read for static analysis.

---

## Step 2 — Install TaintP2X (base analyzer)

Clone TaintP2X as a sibling of `dispatch-taint/`.

```bash
cd <ROOT>
git clone https://github.com/security-pride/TaintP2X.git TaintP2X
```

Confirm the taint definitions and stubs the script uses:

```bash
cd <ROOT>
ls -d TaintP2X/Taint_Propagation/taint            # taint.config + source/sink defs
ls -d TaintP2X/Taint_Propagation/stubs            # stubs the analysis searches
```

We use TaintP2X's M2 taint definitions only; the LLM-assisted modules (M1/M3/M4,
which need a DeepSeek API key) are **not** required for this M2-level verification.
TaintP2X's main driver (`run_download_and_check.py`) is **not** invoked or modified.

---

## Step 3 — Run the reproduction

```bash
cd <ROOT>/dispatch-taint/taintp2x_m2_verification
source ../.venv/bin/activate      # if not already active
./reproduce_m2.sh
```

The script performs, in order:

1. Prerequisite check (pyre, TaintP2X taint defs, typeshed, dispatch_lowering, AutoGPT).
2. Build `cond_A/` from pristine AutoGPT (`agent.py` + `code_executor.py` + source spec).
3. Analyze `cond_A/` with TaintP2X M2 → expect **Found 0 issues**.
4. Copy to `cond_B/` and apply `dispatch_lowering` to its `agent.py`.
5. `diff` cond_A vs cond_B → only the lowering insertion differs.
6. Analyze `cond_B/` with the same settings → expect **Found 7 issues**.
7. Print the per-code breakdown (5005 ExecArgSink ×4, 5001 RemoteCodeExecution ×3).

If any stage misses its expected value, the script stops with an error. Reaching the
end means `0 → 7` held.

Expected tail of the output:

```
=== 完了 ===
条件A（lowering 無し）:  Found 0 issues
条件B（lowering 有り）:  Found 7 issues
差分は agent.py への lowering 挿入のみ。0 → 7 を動的に再現しました。
```

---

## Overriding paths

If your layout differs from the assumed one, set any of these before running. The
script derives them from `<ROOT>` by default (`ROOT = <this dir>/../..`).

```bash
TP2X=/path/to/TaintP2X/Taint_Propagation \
TYPESHED=/path/to/.venv/lib/pyre_check/typeshed \
EXT=/path/to/dispatch-taint/taintp2x_extension \
AUTOGPT=/path/to/autogpt \
  ./reproduce_m2.sh
```

| Variable | Default | Meaning |
|---|---|---|
| `TP2X` | `$ROOT/TaintP2X/Taint_Propagation` | TaintP2X taint defs + stubs |
| `TYPESHED` | `$ROOT/dispatch-taint/.venv/lib/pyre_check/typeshed` | pyre's typeshed |
| `EXT` | `$ROOT/dispatch-taint/taintp2x_extension` | folder with `dispatch_lowering.py`, `links.py`, `pipeline.py` |
| `AUTOGPT` | `$ROOT/autogpt` | AutoGPT clone (v0.5.0) |

---

## What the 7 detections are

All seven are taint paths in `agent.Agent._execute_tool` (LLM-controlled
`tool_call.arguments` → a code-execution sink), made reachable by lowering the
`command(**tool_call.arguments)` wall to the four resolved `@command` methods:

| # | rule (code) | lowered method | sink leaf |
|---|---|---|---|
| 1 | ExecArgSink (5005) | `execute_shell_popen` | `subprocess.Popen.__init__` |
| 2 | ExecArgSink (5005) | `execute_shell` | `subprocess.run` |
| 3 | ExecArgSink (5005) | `execute_python_file` | `subprocess.run` (`filename`) |
| 4 | ExecArgSink (5005) | `execute_python_file` | `subprocess.run` (`args`) |
| 5 | RemoteCodeExecution (5001) | `execute_shell` | `subprocess.run` |
| 6 | RemoteCodeExecution (5001) | `execute_python_file` | `subprocess.run` (`filename`) |
| 7 | RemoteCodeExecution (5001) | `execute_python_file` | `subprocess.run` (`args`) |

Pysa reports one issue per tainted *argument* flow, so `execute_python_file`
contributes two per rule — its `filename` and its `args` parameter both carry
taint into `subprocess.run(["python", str(file_path)] + args)`. The distinct
(sink kind, sink method) coverage is therefore **5 pairs**, which
`ablation_helpers.py count` prints as `SINK_PAIRS` and `EXPECT_SINKS_B` asserts.

Paths 1, 2, 5 reach the shell-execution methods (`execute_shell`,
`execute_shell_popen`) — the location of AutoGPT v0.5.0's **CVE-2024-1881**
(OS command injection via a shell-command validator that only checks the first word).
Paths 3, 4, 6, 7 reach the Python-file execution method, a separate code-execution
route also severed by the same dynamic dispatch.

To inspect the paths yourself after a run:

```bash
python3 - <<'PY'
import json
LINE={279:'execute_python_code',280:'execute_python_file',281:'execute_shell',282:'execute_shell_popen'}
for ln in open('results/cond_B_taint-output.json'):
    ln=ln.strip().rstrip(',')
    if not ln or ln in('[',']'): continue
    try: o=json.loads(ln)
    except: continue
    if o.get('kind')!='issue': continue
    d=o['data']; leaf=None
    for t in d.get('traces',[]):
        if t['name']=='backward':
            for r in t['roots']:
                for k in r['kinds']:
                    for lf in k.get('leaves',[]): leaf=(lf['name'],k['kind'])
    print(d['code'], LINE.get(d['line'],d['line']), leaf)
PY
```

---

## Scope (honest limits)

This verification shows **reachability**: that LLM-controlled data reaches a
code-execution sink once the dynamic-dispatch wall is lowered. It does **not** detect
the sanitizer flaw that defines CVE-2024-1881 (validating only the first word of a
shell command); that is outside taint-reachability analysis and is not claimed.
TaintP2X misses this CVE not because it fails to see the sanitizer flaw, but because
its M2 cannot establish reachability across the dynamic dispatch at all (condition A
= 0). The contribution is restoring that reachability — a necessary precondition for
any downstream vulnerability judgement — soundly and with TaintP2X left unmodified.

The result is one target (AutoGPT) at M2 level. Multi-framework ablation is future
work.

---

## Files in this directory

```
taintp2x_m2_verification/
├── reproduce_m2.sh                # dynamic reproduction (this guide drives it)
├── README.md                      # this file
├── VERIFICATION_M2.md             # full write-up
├── cond_A/                        # rebuilt by the script (no lowering)
├── cond_B/                        # generated by the script (+ lowering)
└── results/
    ├── cond_A_taint-output.json   # 0 issues
    └── cond_B_taint-output.json   # 7 issues
```
