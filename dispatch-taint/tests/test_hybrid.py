"""Fusion #4 wired into the hybrid driver: a dynamic-dispatch wall in the enumeration
leg is resolved to concrete, registry-narrowed sinks from the shared #5 tool model.

Leg-1-only (``pysa_results=None``) so the test needs no pyre; the shared model is
injected (``model=``) so it needs no live LLM. The fixture's ``TOOL_MAP`` is parsed
from the file itself for narrowing.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "pysa"))

import hybrid  # noqa: E402
from ctaudit.toolmodel.schema import RepoToolModel, ToolSpec, SinkSpec  # noqa: E402

_FIX = str(_ROOT / "fixtures" / "dynamic_dispatch_agent.py")


def _model(tools):
    return RepoToolModel(repo=_FIX, src_root=str(_ROOT / "fixtures"), tools=tools)


def _shared_model():
    # what the #5 classifier would yield: TOOL_MAP's two dangerous tools
    return _model([
        ToolSpec(name="run_cmd",   roles=["sink"], sink=SinkSpec(category="code_execution", arg="cmd")),
        ToolSpec(name="fetch_url", roles=["sink"], sink=SinkSpec(category="network",        arg="url")),
    ])


def _resolved(findings):
    return sorted(f.sink_name for f in findings if getattr(f, "via_dispatch", None))


def test_hybrid_resolves_dispatch_with_shared_model():
    out = hybrid.run(_FIX, None, "mock", resolve=True, model=_shared_model())
    # the wall became concrete sinks; no raw dispatch finding remains
    assert _resolved(out) == ["fetch_url", "run_cmd"]
    assert all(f.kind != "dispatch" for f in out)
    # resolved findings carry the fusion#4 provenance, path context, and a triage verdict
    res = [f for f in out if getattr(f, "via_dispatch", None)]
    assert res and all("fusion#4-resolved" in getattr(f, "_provenance", []) for f in res)
    assert all(f.triage_verdict for f in res)
    assert all(f.exit_sites for f in res)            # LLM node on the path preserved
    assert all(f.via_dispatch == 'TOOL_MAP[call["name"]]' for f in res)


def test_hybrid_no_resolve_keeps_the_wall():
    out = hybrid.run(_FIX, None, "mock", resolve=False)
    assert any(f.kind == "dispatch" for f in out)    # wall kept
    assert _resolved(out) == []


def test_hybrid_recall_safe_when_model_has_no_sink():
    # heuristic-style miss (no sink discovered for this idiom) -> wall kept, no false sinks
    out = hybrid.run(_FIX, None, "mock", resolve=True, model=_model([]))
    assert any(f.kind == "dispatch" for f in out)
    assert _resolved(out) == []


def test_hybrid_narrows_to_registry_members():
    # a sink NOT registered in TOOL_MAP must not be attached to this dispatch
    mdl = _model([
        ToolSpec(name="run_cmd",  roles=["sink"], sink=SinkSpec(category="code_execution", arg="cmd")),
        ToolSpec(name="db_query", roles=["sink"], sink=SinkSpec(category="sql",            arg="q")),
    ])
    out = hybrid.run(_FIX, None, "mock", resolve=True, model=mdl)
    assert _resolved(out) == ["run_cmd"]             # db_query dropped (not in TOOL_MAP)
