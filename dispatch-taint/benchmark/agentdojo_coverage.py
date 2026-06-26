"""AgentDojo coverage benchmark (static, no LLM execution, fully reproducible).

This measures the (C) quantity established in the design discussion: the relationship
between ctaudit's *static* dangerous-sink set and AgentDojo's *defined* attack-success
sink set, on the banking suite.

Definitions (both read statically — NO model is run):
  * **S_dyn**  — the set of sink tools that AgentDojo's injection-task ``ground_truth``
                 methods actually call.  AgentDojo's ``ground_truth`` is the benchmark's
                 OWN definition of "this injection succeeded == these FunctionCalls were
                 emitted", so S_dyn is the *defined* attack-success sink set.  It is read
                 by AST-parsing ``injection_tasks.py`` (no execution, no API key).
  * **S_static** — the set of dangerous sinks ctaudit resolves the AgentDojo dispatch
                 wall to, on the banking suite (``--agentdojo`` mode).

Reported:
  * **coverage / soundness**: does ``S_static ⊇ S_dyn`` hold?  i.e. does the static
    analysis miss any sink that a defined attack actually uses?  (R ⊇ R*, empirically.)
  * **over-approximation rate** = ``|S_static \\ S_dyn| / |S_static|`` — the cost of
    keeping soundness: sinks ctaudit flags that no defined attack uses.  This is NOT a
    defect; it quantifies the price of the (sound) over-approximation that follows from
    an LLM being able to route any source to any sink.

This is *not* "flow recall/precision on the 629 cases" (a dynamic attack-success GT — a
category mismatch) and *not* attack-success-rate (which needs a model).  It is the
empirical soundness check + its over-approximation cost, on a standard public benchmark.

Requires ``agentdojo`` to be importable (``pip install agentdojo``); otherwise it skips.
"""
from __future__ import annotations

import ast
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ctaudit.models.agentdojo import AGENTDOJO_DOMAIN_SINKS


def _agentdojo_root() -> Optional[Path]:
    try:
        import agentdojo  # noqa: F401
        return Path(os.path.dirname(agentdojo.__file__))
    except Exception:
        return None


def _ground_truth_sinks(injection_tasks_py: Path) -> Dict[str, List[str]]:
    """Map each InjectionTask class -> the function names its ground_truth calls.

    Reads statically (AST); does not execute the suite or any model.
    """
    tree = ast.parse(injection_tasks_py.read_text(encoding="utf-8"))
    out: Dict[str, List[str]] = {}
    for cls in [n for n in ast.walk(tree)
                if isinstance(n, ast.ClassDef) and n.name.startswith("InjectionTask")]:
        gt = next((m for m in cls.body
                   if isinstance(m, ast.FunctionDef) and m.name == "ground_truth"), None)
        funcs: List[str] = []
        if gt is not None:
            for n in ast.walk(gt):
                if isinstance(n, ast.Call):
                    fin = (n.func.attr if isinstance(n.func, ast.Attribute)
                           else getattr(n.func, "id", None))
                    if fin == "FunctionCall":
                        for kw in n.keywords:
                            if kw.arg == "function":
                                v = kw.value
                                if isinstance(v, ast.Constant):
                                    funcs.append(v.value)
        out[cls.name] = funcs
    return out


def _s_dyn(gt: Dict[str, List[str]]) -> Set[str]:
    """S_dyn = union of ground_truth-called functions that are domain sinks."""
    s: Set[str] = set()
    for funcs in gt.values():
        for f in funcs:
            if f in AGENTDOJO_DOMAIN_SINKS:
                s.add(f)
    return s


def _s_static(banking_files: List[Path]) -> Set[str]:
    """S_static = sinks ctaudit resolves the AgentDojo wall to on the banking suite."""
    import shutil
    import tempfile

    # hybrid.py lives at the repo root (one level above benchmark/).
    _root = str(Path(__file__).resolve().parent.parent)
    if _root not in sys.path:
        sys.path.insert(0, _root)
    import hybrid

    tmp = Path(tempfile.mkdtemp(prefix="ad_cov_"))
    try:
        for fp in banking_files:
            if fp.exists():
                shutil.copy(fp, tmp / fp.name)
        findings = hybrid.run(str(tmp), None, "mock", agentdojo=True)
        return {f.sink_name for f in findings if getattr(f, "via_dispatch", None)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run() -> Tuple[Set[str], Set[str], Dict[str, List[str]]]:
    root = _agentdojo_root()
    if root is None:
        print("agentdojo not installed — skipping AgentDojo coverage benchmark.")
        print("(install with: pip install agentdojo --break-system-packages)")
        return set(), set(), {}

    banking = root / "default_suites" / "v1" / "banking"
    tools = root / "default_suites" / "v1" / "tools"
    inj = banking / "injection_tasks.py"
    banking_files = [
        root / "agent_pipeline" / "tool_execution.py",
        root / "functions_runtime.py",
        banking / "task_suite.py",
        tools / "banking_client.py",
        tools / "file_reader.py",
        tools / "user_account.py",
    ]

    gt = _ground_truth_sinks(inj)
    S_dyn = _s_dyn(gt)
    S_static = _s_static(banking_files)

    print("=" * 70)
    print("AgentDojo coverage benchmark — banking suite (static, no model run)")
    print("=" * 70)
    print(f"\ninjection tasks read: {len(gt)}")
    for name in sorted(gt):
        sinks = [f for f in gt[name] if f in AGENTDOJO_DOMAIN_SINKS]
        print(f"  {name:18s} ground_truth sinks: {sinks}")

    print(f"\nS_dyn   (defined attack-success sinks) [{len(S_dyn)}]: {sorted(S_dyn)}")
    print(f"S_static(ctaudit-flagged sinks)        [{len(S_static)}]: {sorted(S_static)}")

    missed = S_dyn - S_static                 # sinks an attack uses but ctaudit misses
    over = S_static - S_dyn                    # sinks ctaudit flags but no attack uses

    print("\n--- soundness (coverage) ---")
    print(f"  S_static ⊇ S_dyn ? {S_dyn <= S_static}"
          f"   (missed attack sinks: {sorted(missed) or 'NONE'})")
    print("\n--- over-approximation cost ---")
    rate = (len(over) / len(S_static)) if S_static else 0.0
    print(f"  over-flagged (S_static \\ S_dyn): {sorted(over)}")
    print(f"  over-approximation rate = |S_static \\ S_dyn| / |S_static| "
          f"= {len(over)}/{len(S_static)} = {rate:.2f}")

    print("\n--- interpretation ---")
    if not S_dyn:
        print("  S_dyn empty — cannot interpret (no domain-sink ground truth parsed).")
    elif S_dyn <= S_static and S_dyn != S_static:
        print("  Sound (no missed attack sink) AND non-trivial (S_dyn ⊊ S_static):")
        print("  ctaudit covers every defined-attack sink while flagging "
              f"{len(over)} extra — the (sound) over-approximation cost, NOT a miss.")
    elif S_dyn == S_static:
        print("  S_dyn == S_static: coverage is trivial here (both are the full set).")
    else:
        print("  WARNING: S_static does NOT cover S_dyn — a missed attack sink "
              "(would contradict the soundness claim; investigate).")

    return S_dyn, S_static, gt


if __name__ == "__main__":
    S_dyn, S_static, _ = run()
    # non-zero exit only if a defined-attack sink is missed (soundness violation)
    sys.exit(1 if (S_dyn and not (S_dyn <= S_static)) else 0)
