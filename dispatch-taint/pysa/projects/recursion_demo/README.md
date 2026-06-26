# (C) Pysa actually executed — closing the inter-procedural + recursion gap

These dependency-free targets reproduce the exact shapes that DEFEATED the
standalone AST engine (method split + shared mutable history + recursion), and
show that **Pysa (pyre-check, actually run here)** detects the cross-tool
implicit flow (CWE-1426) the standalone engine missed.

Pyre version used: 0.9.25 (`pip install pyre-check`).
Run:  `pyre analyze --no-verify --save-results-to ./res`

| target (src/agent.py variant) | shape | raw Pysa | with §4.3 bridge model |
|---|---|---|---|
| value_threaded.py  | inter-proc + RECURSION, history threaded by return value | **1 (✓)** | — |
| shared_list_direct.py | SHARED MUTABLE history + RECURSION, append modeled in the loop | (0) | **1 (✓)** |
| shared_list_wrapped.py | same but append buried under an extra user wrapper fn | (0) | (0 — needs each layer modeled) |

## What this establishes
1. **Pysa leg is no longer "designed, not executed."** The bundled `pysa/example`
   yields 1 implicit finding whose taint crosses the UNMODELED helpers
   `summarize`/`build_request` — general inter-procedural flow, for free.
2. **(C-i)** Value-threaded inter-procedural + **recursion** is detected
   automatically — the capability the intra-procedural, textual-loop-fixpoint
   standalone engine lacked.
3. **(C-ii)** The shared-mutable-history shape (real shell_gpt structure) is
   detected once the history-append primitive is modeled as a propagator
   (`TaintInTaintOut[Updates[history]]`) — exactly the proposal's §4.3 bridge.
   Division of labor confirmed: Pysa = engine; ctaudit = the wiring/bridge models.

## Honest boundary
In-place mutation taint does NOT auto-propagate back through *intermediate user
wrapper functions*: if the modeled append sits two call-layers below the
orchestration loop, each layer must be modeled (or Pysa must infer the Updates,
which it did not here). The common real shape (append primitive called directly
in the loop) works; deep user wrappers need per-layer models.
