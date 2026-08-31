# Target-specific Pysa models for the benchmark (manual, by design)

One `.pysa` per target that needs a source or sink TaintP2X's own catalogue
(`Taint_Propagation/taint/*.pysa`, LLM-SDK calls as sources) does not cover.
Referenced from `benchmark.json` (`pysa_models`); targets without an entry run
with TaintP2X's models only. Declaring "which data is LLM-controlled" is the
analyst's job, not the system's — see docs/SCALE_OUT_DESIGN.md.
