"""Tests for the shared tool model + classifier (proposal §6 fusion #5).

Covers: schema round-trip; both emitters; the deterministic classifier on a
synthetic repo (portable, no external deps); and skip-if-present checks against
the real shell_gpt / termwise trees that reproduce the hand-written enumerations.
"""
import os
import sys
import textwrap
from pathlib import Path

import pytest

from ctaudit.toolmodel import (
    RepoToolModel, ToolSpec, SinkSpec, SourceSpec, LLMCallSpec,
    to_pysa, to_enumeration, get_classifier,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "corpus" / "agentdojo"))
from _common import _flows  # noqa: E402


def _shellgpt_model() -> RepoToolModel:
    return RepoToolModel(repo="shell_gpt", tools=[
        ToolSpec(name="execute_shell_command",
                 callable="sgpt.llm_functions.common.execute_shell.Function.execute",
                 recv="cls", roles=["source", "sink"],
                 sink=SinkSpec(category="code_execution", arg="shell_command"),
                 source=SourceSpec(capacity="string", attacker=True)),
        ToolSpec(name="execute_apple_script",
                 callable="sgpt.llm_functions.mac.apple_script.Function.execute",
                 recv="cls", roles=["source", "sink"],
                 sink=SinkSpec(category="code_execution", arg="apple_script"),
                 source=SourceSpec(capacity="string", attacker=True)),
    ], llm_call=LLMCallSpec("openai._Completions.create", "messages"))


def test_schema_roundtrip():
    m = _shellgpt_model()
    m2 = RepoToolModel.from_json(m.to_json())
    assert [t.name for t in m2.tools] == [t.name for t in m.tools]
    assert m2.tools[0].sink.category == "code_execution"
    assert m2.tools[0].source.attacker is True
    assert m2.llm_call.callable == "openai._Completions.create"


def test_emit_enumeration_pairs():
    SOURCES, SINKS = to_enumeration(_shellgpt_model())
    assert set(SOURCES) == {"execute_shell_command:out", "execute_apple_script:out"}
    assert set(SINKS) == {"execute_shell_command", "execute_apple_script"}
    assert len(_flows(SOURCES, SINKS)) == 4


def test_emit_pysa_signatures():
    text = to_pysa(_shellgpt_model())
    assert "TaintInTaintOut[Via[llm_node]]" in text
    assert "openai._Completions.create" in text
    # the dangerous arg is modelled as a sink and the return as a tool-output source
    assert "shell_command: TaintSink[CodeExecution]" in text
    assert "TaintSource[ToolOutput" in text


SYNTHETIC = {
    "agent/__init__.py": "",
    "agent/handler.py": textwrap.dedent("""
        import openai
        client = openai.OpenAI()
        completion = client.chat.completions.create   # aliased LLM call
        def run(msgs):
            return completion(model="x", messages=msgs)
    """),
    "agent/tools/__init__.py": "",
    "agent/tools/shell_tool.py": textwrap.dedent('''
        import subprocess
        class ShellTool:
            @property
            def name(self): return "run_shell"
            def _check_safety(self, command): return command
            def execute(self, **kwargs):
                command = kwargs.get("command", "")
                self._check_safety(command)
                p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
                out, _ = p.communicate()
                return out.decode()
            def openai_schema(self): return {"name": "run_shell"}
    '''),
    "agent/tools/writer_tool.py": textwrap.dedent('''
        class WriterTool:
            @property
            def name(self): return "write_file"
            def execute(self, **kwargs):
                path = kwargs.get("path", "")
                content = kwargs.get("content", "")
                mode = kwargs.get("mode", "write")
                wm = "a" if mode == "append" else "w"
                with open(path, wm) as f:
                    f.write(content)
                return "ok"
    '''),
}


def _write_repo(tmp_path) -> Path:
    for rel, body in SYNTHETIC.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return tmp_path


def test_heuristic_on_synthetic_repo(tmp_path):
    repo = _write_repo(tmp_path)
    model = get_classifier("heuristic").classify(str(repo), src_root=str(repo))
    names = {t.name for t in model.tools}
    assert names == {"run_shell", "write_file"}

    by = {t.name: t for t in model.tools}
    assert by["run_shell"].sink.category == "code_execution"
    assert by["run_shell"].sink.guard == "_check_safety"      # guard detected
    assert "source" in by["run_shell"].roles                  # subprocess output returned
    assert by["write_file"].sink.category == "file_write"     # open(var-mode)+.write
    assert by["write_file"].sink.guard is None

    # aliased `completion = client.chat.completions.create` is recognised as the LLM call
    assert model.llm_call and model.llm_call.callable == "openai._Completions.create"

    SOURCES, SINKS = to_enumeration(model)
    flows = _flows(SOURCES, SINKS)
    # run_shell is source+sink, write_file is sink-only -> 1 source x 2 sinks = 2 pairs
    assert len(flows) == 2
    cats = {(s, k) for (s, k) in flows}
    assert ("run_shell:out", "write_file") in cats


def test_anthropic_classifier_falls_back_to_heuristic(tmp_path, monkeypatch):
    # with no API key, the LLM backend must degrade to the heuristic verdict
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    repo = _write_repo(tmp_path)
    model = get_classifier("anthropic").classify(str(repo), src_root=str(repo))
    assert {t.name for t in model.tools} == {"run_shell", "write_file"}
    assert all("heuristic" in t.classifier for t in model.tools)


# ---- skip-if-present checks on the real corpus repos ---------------------- #
_CAND = Path(os.environ.get("CTAUDIT_CORPUS_BASE", "/home/claude/cand"))


@pytest.mark.skipif(not (_CAND / "shellgpt").exists(), reason="shell_gpt not present")
def test_real_shellgpt_reproduces_four_pairs():
    repo = str(_CAND / "shellgpt")
    model = get_classifier("heuristic").classify(repo, src_root=repo)
    assert {t.name for t in model.tools} == {"execute_shell_command", "execute_apple_script"}
    SOURCES, SINKS = to_enumeration(model)
    assert len(_flows(SOURCES, SINKS)) == 4


@pytest.mark.skipif(not (_CAND / "termwise").exists(), reason="termwise not present")
def test_real_termwise_reproduces_six_pairs_with_guard_split():
    repo = str(_CAND / "termwise")
    model = get_classifier("heuristic").classify(repo, src_root=repo)
    by = {t.name: t for t in model.tools}
    assert {"shell", "write_file", "read_file", "search"} <= set(by)
    assert by["shell"].sink.guard == "_check_safety"
    assert by["write_file"].sink.guard is None
    SOURCES, SINKS = to_enumeration(model)
    flows = _flows(SOURCES, SINKS)
    assert len(flows) == 6


def test_capacity_out_of_vocabulary_is_normalized_and_enumeration_survives():
    """Regression: an LLM may emit a free-form capacity (e.g. 'filesystem_read').
    It must be clamped to the lattice (-> 'string', widest/recall-safe) so the §4.5
    enumeration does not KeyError."""
    import sys
    from pathlib import Path
    from ctaudit.toolmodel.schema import RepoToolModel, SinkSpec, SourceSpec, ToolSpec
    from ctaudit.toolmodel.emit import to_enumeration

    assert SourceSpec(capacity="filesystem_read").capacity == "string"
    assert SinkSpec(category="file_write", capacity="weird").capacity == "string"
    # round-trips through JSON too
    assert RepoToolModel.from_json(
        '{"tools":[{"name":"r","roles":["source"],'
        '"source":{"capacity":"filesystem_read","attacker":true}}]}'
    ).tools[0].source.capacity == "string"

    model = RepoToolModel(repo="x", src_root="x", tools=[
        ToolSpec(name="read_file", roles=["source"],
                 source=SourceSpec(capacity="filesystem_read", attacker=True)),
        ToolSpec(name="write_file", roles=["sink"],
                 sink=SinkSpec(category="file_write", arg="content", guard="confirm_action")),
    ])
    SOURCES, SINKS = to_enumeration(model)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "corpus" / "agentdojo"))
    from _common import _flows
    assert _flows(SOURCES, SINKS) == [("read_file:out", "write_file")]   # no KeyError, flow kept
