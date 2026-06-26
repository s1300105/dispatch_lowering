# Hybrid audit (b): Pysa data-flow + standalone dispatch enumeration, one report

A framework-factored real repo needs BOTH static legs at once. This directory
shows a single target where **each leg catches a flow the other cannot**, so the
hybrid is strictly better than either alone.

Reproduce:
```
cd pysa/projects/hybrid_demo && pyre analyze --save-results-to ./res
cd <repo root> && python hybrid.py pysa/projects/hybrid_demo/src \
      --pysa-results pysa/projects/hybrid_demo/res
```

## The two flows in one repo
* `src/app/resolvable.py` — cross-method (`get_completion` → `handle_function_call`)
  + **recursion**, registry dispatch via an if/return **free function** (Pyre
  resolves it). The model-chosen shell command is the sink.
* `src/app/dispatchy.py` — single-function loop, registry dispatch via a **dict
  lookup of a `@classmethod`** (`REGISTRY[name](...)`) — the form Pyre's
  higher-order call graph does NOT resolve.

## Result
| leg | resolvable.py | dispatchy.py |
|---|---|---|
| Pysa data-flow (inter-proc + recursion) | **finds** (CWE-1426 implicit) | misses (dispatch unresolvable) |
| standalone enumerate (§4.2 join@LLM + part-B dispatch) | misses (intra-proc only) | **finds** (LLM-controlled dispatch) |
| **hybrid** | ✓ | ✓ |

```
hybrid audit — 2 finding(s)
[1] LLM-controlled tool dispatch (CWE-1426)  [ctaudit-enumerate]   dispatchy.py
[2] CROSS-TOOL IMPLICIT FLOW (CWE-1426)       [pysa-dataflow]      resolvable.py
```

Pysa alone = 1, standalone alone = 1, **hybrid = 2** — the proposal's dual
(a Pysa data-flow + b enumeration) design realized as one pipeline: Pysa supplies
sound inter-procedural + recursion value flow; the enumeration leg covers the
model-chosen dynamic registry dispatch (dict / `@classmethod`) that pure
data-flow cannot resolve in either engine.

## Supporting fix
`_schema_incompatible` (§4.5(2) channel-capacity prune) now exempts `dispatch`
findings: a dispatch is a control-routing channel (which tool the model selects),
not a data-into-arg channel, so the "source string narrower than object arg"
capacity test must not prune it.
