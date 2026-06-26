"""Tests for the bounded discovery improvements (scale ranking + broadened conventions).

These pin the two fixes that let discovery behave on large class/registry-style repos:
  (1) `_candidate_files` RANKS by tool relevance so a tool-dense file survives the budget
      even when buried under hundreds of noise files (the AutoGPT/MetaGPT scale failure), and
  (2) the heuristic recognizes a PARAMETERIZED tool decorator `@register_tool('name', ...)`,
      while NOT misfiring on Click's ubiquitous `@group.command(...)` (a false-positive guard).
"""
import tempfile
from pathlib import Path

from ctaudit.toolmodel.classify import HeuristicClassifier, LLMToolClassifier


def _tree_with_buried_tool(n_noise: int = 60) -> Path:
    d = Path(tempfile.mkdtemp())
    for i in range(n_noise):
        sub = d / f"pkg{i}"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "noise.py").write_text("VALUE = 1\n\ndef helper():\n    return VALUE\n")
    cmd = d / "agent" / "abilities"
    cmd.mkdir(parents=True, exist_ok=True)
    (cmd / "shell_ability.py").write_text(
        "import subprocess\n\n"
        "@register_tool('execute_shell', 'run a shell command', {})\n"
        "def execute_shell(command_line: str) -> str:\n"
        "    return subprocess.run(command_line, shell=True, capture_output=True).stdout.decode()\n"
    )
    return d


def test_ranking_surfaces_buried_tool_file_in_large_tree():
    d = _tree_with_buried_tool(60)
    files = LLMToolClassifier(complete=None)._candidate_files(d)
    names = [p.name for p in files]
    # the one tool-dense file must survive the bounded budget despite 60 noise packages.
    assert "shell_ability.py" in names
    assert files[0].name == "shell_ability.py"            # ranked first by relevance


def test_parameterized_tool_decorator_is_recognized():
    d = _tree_with_buried_tool(0)
    model = HeuristicClassifier().classify(str(d))
    by = {t.name: t for t in model.tools}
    assert "execute_shell" in by
    assert by["execute_shell"].sink is not None
    assert by["execute_shell"].sink.category == "code_execution"


def test_click_command_decorator_is_not_a_false_positive():
    # @group.command(...) (Click) must NOT be treated as a tool — bare "command" was dropped
    # from the decorator set precisely to avoid this collision.
    d = Path(tempfile.mkdtemp())
    (d / "cli.py").write_text(
        "import click\n\n"
        "@click.group()\n"
        "def cli():\n    pass\n\n"
        "@cli.command()\n"
        "def config_cmd(get_key, set_value):\n    return None\n"
    )
    model = HeuristicClassifier().classify(str(d))
    assert {t.name for t in model.tools} == set()          # no spurious 'config'/'config_cmd' tool
