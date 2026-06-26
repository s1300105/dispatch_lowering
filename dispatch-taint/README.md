# ctaudit — Static Auditing of Cross-Tool Implicit Flows in LLM Agents

`ctaudit` is a static analysis system for detecting **CWE-1426 (Improper Validation
of Generative AI Output)** cross-tool implicit flows in LLM agents: paths where
attacker-influenced tool output reaches the LLM, the LLM's choice drives a dynamic
tool dispatch, and that dispatch lands on a dangerous sink — *control dependence*
that data-flow taint analysis alone does not follow.

The novelty is **sound resolution of LLM-controlled dynamic dispatch**. Where a tool
is selected at runtime (e.g. `REGISTRY[llm_choice]`, a linear `_get_command(name)`
scan, or a framework's internal dispatch table), the call edge does not exist in the
static call graph, so taint propagation stops at the wall. `ctaudit` resolves that
wall to the concrete reachable tools, soundly (it only prunes a candidate when the
code provably cannot select it), so the flow from source to sink can be recovered.

---

## What this repository contains

```
cross_tool_audit/
├── ctaudit/                     # the analyzer package (stdlib-only core)
├── hybrid.py                    # hybrid driver
├── fixtures/                    # self-contained example agents (positive & negative)
├── benchmark/                   # flow_bench, framework dispatch bench, AgentDojo coverage
├── tests/                       # pytest suite
├── pysa/                        # Pysa integration (models, postprocess, demo project)
├── taintp2x_extension/          # TaintP2X extension: dynamic-dispatch lowering (this work)
├── taintp2x_m2_verification/    # M2-level verification on real AutoGPT (see its README)
├── corpus/ realworld/           # corpora and real-repo check material
└── *.md                         # research notes (RESEARCH_IDEA, BENCHMARK_RESULTS, ...)
```

The core analyzer uses only Python's `ast`, so the analyzer and the full test suite
run **offline with no third-party packages**. LLM backends are optional and only
needed for tool-model discovery and LLM-assisted triage on real repositories.

---

## Install

Requires **Python >= 3.10**.

```bash
git clone <this-repo-url> cross_tool_audit
cd cross_tool_audit

# editable install of the core analyzer (no third-party deps)
python -m pip install -e .

# optional: test runner
python -m pip install -e ".[dev]"

# optional: LLM backends for tool-model discovery and LLM triage
python -m pip install -e ".[triage]"
```

LLM API keys are only needed for the LLM-backed paths:

```bash
export DEEPSEEK_API_KEY=...     # --classifier deepseek
export OPENAI_API_KEY=...       # --classifier openai
export ANTHROPIC_API_KEY=...    # --classifier anthropic / --triage anthropic
```

---

## Quick start

```bash
# audit a single file or a directory (offline; no API key needed)
ctaudit path/to/agent.py
ctaudit path/to/agent_project/

# machine-readable output, non-zero exit if anything is found (handy in CI)
ctaudit path/to/agent_project/ --json --fail-on-finding
```

Bundled fixtures (each is self-contained):

```bash
ctaudit fixtures/dynamic_dispatch_agent.py   # dispatch resolved to run_cmd + fetch_url
ctaudit fixtures/phase_gated_agent.py        # phase gate soundly drops run_cmd
ctaudit fixtures/langchain_2tool_vuln.py     # cross-tool implicit flow
ctaudit fixtures/langchain_2tool_safe.py     # negative: nothing emitted
```

---

## Command-line tools

Installed as console scripts by `pip install -e .`.

| Command | Purpose |
|---|---|
| `ctaudit <path>` | Audit a file/directory and print findings (main entry point). |
| `ctaudit-toolmodel <repo>` | Build the shared tool model for a repo and emit it / the Pysa model / the enumeration. |
| `ctaudit-flowbench` | Run the controlled flow benchmark (by-construction ground truth). |
| `ctaudit-eval` | Run the evaluation harness (per-component / pruning ablation scaffolding). |
| `ctaudit-annotate` | Annotation helper for building/auditing labeled benchmarks. |

---

## Tests

```bash
python -m pip install -e ".[dev]"
python -m pytest -q          # full suite (offline)
```

---

## TaintP2X M2-level verification (real AutoGPT)

`taintp2x_extension/` implements this work's contribution as an external
**dynamic-dispatch lowering** pass for **TaintP2X** (ICSE 2026, a Pysa-based static
taint analyzer). TaintP2X's static taint propagation (its M2 module) cannot carry
taint across AutoGPT's runtime tool dispatch, so it misses the code-execution paths
behind that wall — including the path where AutoGPT v0.5.0's CVE-2024-1881 lives,
which TaintP2X's own paper reports as a miss (Table 2, TaintP2X = N). The lowering
pass resolves the wall as a *preprocessing* step (TaintP2X itself stays unmodified),
restoring reachability so TaintP2X's own taint rules fire.

`taintp2x_m2_verification/` reproduces this end to end on the real AutoGPT repo:

```
TaintP2X M2 (no lowering)  →  Found 0 issues
TaintP2X M2 (+ lowering)   →  Found 7 issues
```

with the only difference being the lowering insertion in `agent.py` (verified by
`diff`). Three of the seven paths reach the shell-execution methods
(`execute_shell`, `execute_shell_popen`) where CVE-2024-1881 resides.

This verification depends on two repositories that are **not** part of this repo and
must be obtained separately: **AutoGPT** (the analysis target) and **TaintP2X** (the
unmodified base analyzer). Full step-by-step instructions, including how to install
both, are in:

> **[`taintp2x_m2_verification/README.md`](taintp2x_m2_verification/README.md)**

Quick version, once both are in place:

```bash
cd taintp2x_m2_verification
./reproduce_m2.sh
```

---

## Scope and honest limits

`ctaudit` and the lowering pass detect **reachability** — that attacker-influenced
LLM output can reach a dangerous sink. They do not, by themselves, detect logical
flaws in a sanitizer along the path (for CVE-2024-1881 that is the "only the first
word is validated" flaw in AutoGPT's command check, which is outside taint
reachability). The contribution is restoring the reachability that dynamic dispatch
otherwise severs — a necessary precondition for any downstream vulnerability
judgement — not reasoning about sanitizer correctness.
