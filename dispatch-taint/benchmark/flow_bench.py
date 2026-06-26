"""Flow-level benchmark (controlled, by-construction ground truth).

The tool-model benchmark (``benchmark/run_benchmark.py``) measures whether the *tool
model* is recovered. This benchmark measures the headline claim one level up: given a
(gold) tool model, does ctaudit's flow machinery — the dataflow leg, §4.5 pruning, and
dispatch resolution with narrowing — emit the **cross-tool implicit flows** that, by
construction of each fixture, are actually present?

Each fixture has a known set of expected flows (a fixture either *contains* a
source->LLM->sink flow or is a negative: safe/guarded/pruned/unreachable). We compare the
emitted flows to that set and report flow **recall** and **precision** (detection) plus
**guard-classification accuracy** (did we get guarded/unguarded right on matched flows).
Dispatch fixtures are given their gold tool model so that *flow detection* is isolated
from *tool-model recovery* (which RQ1 measures separately). This is a controlled
benchmark with exact ground truth; it complements — does not replace — a flow-level gold
on real repositories (future work).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from ctaudit import analyze_path
from ctaudit.analysis import resolve_dispatch
from ctaudit.toolmodel.schema import RepoToolModel, SinkSpec, ToolSpec

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# the engine emits "exec" for code execution; the resolved-dispatch path uses the model's
# "code_execution". Normalise to one vocabulary so the two paths are comparable.
_CAT = {"exec": "code_execution"}


def _norm_cat(c: str) -> str:
    return _CAT.get(c, c)


@dataclass(frozen=True)
class Flow:
    kind: str          # "implicit" (cross-tool, via LLM) | "explicit" (data-layer verbatim)
    sink: str          # emitted sink name (a call like subprocess.run, or a resolved tool)
    category: str      # normalised: code_execution | file_write | sql | network | deserialize
    guarded: bool

    def key(self):     # detection identity (guard handled separately)
        return (self.kind, self.sink, self.category)


def _sink_model(repo: str, *sinks) -> RepoToolModel:
    return RepoToolModel(repo=repo, src_root=repo,
                         tools=[ToolSpec(name=n, roles=["sink"], sink=SinkSpec(category=c, arg=a))
                                for (n, c, a) in sinks])


# ---- gold tool models for the dispatch fixtures (isolates flow detection from RQ1) ---- #
def _gold_models() -> Dict[str, RepoToolModel]:
    dyn = str(FIXTURES / "dynamic_dispatch_agent.py")
    pha = str(FIXTURES / "phase_gated_agent.py")
    return {
        "dynamic_dispatch_agent.py": _sink_model(dyn, ("run_cmd", "code_execution", "cmd"),
                                                  ("fetch_url", "network", "url")),
        # write_file + run_cmd are both registered; the phase gate must drop run_cmd.
        "phase_gated_agent.py": _sink_model(pha, ("write_file", "file_write", "content"),
                                            ("run_cmd", "code_execution", "cmd")),
    }


# ---- by-construction expected flows per fixture --------------------------------------- #
def _expected() -> Dict[str, List[Flow]]:
    F = Flow
    return {
        # data-layer verbatim (TITO) — explicit, not a cross-tool implicit flow
        "data_layer_verbatim.py":     [F("explicit", "subprocess.run", "code_execution", False)],
        # cross-tool implicit flows (source -> LLM -> sink), unguarded
        "langchain_2tool_vuln.py":    [F("implicit", "subprocess.run", "code_execution", False)],
        "langgraph_multinode_app.py": [F("implicit", "subprocess.run", "code_execution", False)],
        "langgraph_state_app.py":     [F("implicit", "requests.get", "network", False)],
        "mcp_sdk_app.py":             [F("implicit", "cursor.execute", "sql", False)],
        "openai_agents_app.py":       [F("implicit", "os.system", "code_execution", False)],
        # guarded cross-tool implicit flow — present but mitigated (guard classification)
        "guarded_agent_app.py":       [F("implicit", "os.system", "code_execution", True)],
        # LLM-controlled dispatch -> resolved concrete sinks (fusion #4)
        "dynamic_dispatch_agent.py":  [F("implicit", "run_cmd", "code_execution", False),
                                       F("implicit", "fetch_url", "network", False)],
        # dispatch + phase gate: run_cmd is registered but never phase-allowed -> dropped
        "phase_gated_agent.py":       [F("implicit", "write_file", "file_write", False)],
        # negatives (must yield no flow)
        "langchain_2tool_safe.py":    [],   # dangerous arg is a constrained channel
        "schema_pruned_app.py":       [],   # §4.5 prune: constrained-channel argument
        "unreachable_sink_app.py":    [],   # sink is control-flow unreachable
    }


def run_fixture(name: str, model: RepoToolModel | None = None) -> List[Flow]:
    """Emit the flows ctaudit reports for one fixture (dataflow leg + §4.5 + resolution)."""
    path = str(FIXTURES / name)
    findings = [f for f in analyze_path(path).findings if not getattr(f, "pruned", False)]
    mdl = model or _gold_models().get(name) or RepoToolModel(repo=path, src_root=path, tools=[])
    flows: List[Flow] = []
    for f in resolve_dispatch(findings, mdl, repo=path):
        if f.kind == "dispatch":          # an unresolved wall is not a concrete flow
            continue
        flows.append(Flow(f.kind, f.sink_name, _norm_cat(f.sink_category), f.guard is not None))
    return flows


def evaluate(expected: Dict[str, List[Flow]] | None = None) -> dict:
    expected = expected or _expected()
    tp = fp = fn = 0
    guard_matched = guard_ok = 0
    per_fixture = {}
    imp_tp = imp_fp = imp_fn = 0
    for name, exp in expected.items():
        act = run_fixture(name)
        exp_by = {f.key(): f for f in exp}
        act_by = {f.key(): f for f in act}
        ek, ak = set(exp_by), set(act_by)
        ftp, ffp, ffn = len(ek & ak), len(ak - ek), len(ek - ak)
        tp += ftp; fp += ffp; fn += ffn
        for k in (ek & ak):                       # implicit-only slice
            if k[0] == "implicit":
                imp_tp += 1
        imp_fp += len({k for k in (ak - ek) if k[0] == "implicit"})
        imp_fn += len({k for k in (ek - ak) if k[0] == "implicit"})
        g_ok = g_n = 0
        for k in (ek & ak):
            g_n += 1
            if exp_by[k].guarded == act_by[k].guarded:
                g_ok += 1
        guard_matched += g_n; guard_ok += g_ok
        per_fixture[name] = {"tp": ftp, "fp": ffp, "fn": ffn,
                             "guard_ok": g_ok, "guard_n": g_n,
                             "expected": sorted(f"{f.kind}:{f.sink}:{f.category}:{'G' if f.guarded else 'U'}" for f in exp),
                             "actual": sorted(f"{f.kind}:{f.sink}:{f.category}:{'G' if f.guarded else 'U'}" for f in act)}

    def _rp(t, f_p, f_n):
        rec = t / (t + f_n) if (t + f_n) else 1.0
        pre = t / (t + f_p) if (t + f_p) else 1.0
        return rec, pre

    rec, pre = _rp(tp, fp, fn)
    irec, ipre = _rp(imp_tp, imp_fp, imp_fn)
    return {
        "per_fixture": per_fixture,
        "overall": {"tp": tp, "fp": fp, "fn": fn, "recall": rec, "precision": pre},
        "implicit_only": {"tp": imp_tp, "fp": imp_fp, "fn": imp_fn, "recall": irec, "precision": ipre},
        "guard_accuracy": (guard_ok / guard_matched if guard_matched else 1.0),
        "guard_matched": guard_matched,
    }


def main(argv=None) -> int:
    r = evaluate()
    print("flow-level benchmark (controlled, by-construction ground truth)\n")
    print(f"{'fixture':30} {'TP':>3} {'FP':>3} {'FN':>3}  guard  detail")
    for name, d in r["per_fixture"].items():
        gd = f"{d['guard_ok']}/{d['guard_n']}" if d["guard_n"] else "-"
        ok = "ok" if (d["fp"] == 0 and d["fn"] == 0 and d["guard_ok"] == d["guard_n"]) else "DIFF"
        print(f"{name:30} {d['tp']:>3} {d['fp']:>3} {d['fn']:>3}  {gd:>5}  {ok}")
        if ok == "DIFF":
            print(f"    expected: {d['expected']}")
            print(f"    actual  : {d['actual']}")
    o, i = r["overall"], r["implicit_only"]
    print(f"\nALL flows      : recall={o['recall']:.3f} precision={o['precision']:.3f} "
          f"(TP={o['tp']} FP={o['fp']} FN={o['fn']})")
    print(f"implicit only  : recall={i['recall']:.3f} precision={i['precision']:.3f} "
          f"(TP={i['tp']} FP={i['fp']} FN={i['fn']})")
    print(f"guard accuracy : {r['guard_accuracy']:.3f} over {r['guard_matched']} matched flow(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
