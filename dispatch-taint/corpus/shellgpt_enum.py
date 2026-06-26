#!/usr/bin/env python3
"""Enumeration leg (b) on shell_gpt's REAL tool registry.

Literal shell_gpt defeats every static *data-flow* leg: `get_function(name)(...)`
loads the tool module via `importlib` (sgpt/function.py), so neither Pysa nor the
standalone engine can resolve which tool runs — and that one dispatch gates BOTH
ends of the loop (tool output -> history, and model response -> tool execution).
Pysa therefore reports 0 on the literal repo.

This is exactly the case the proposal's enumeration leg (b, §6.1) is for: when the
dispatch is dynamic, enumerate the *registry* and reason over (source x sink)
pairs that the model can route between, instead of following code paths. Here the
"registry" is the set of `Function` tools discoverable under sgpt/llm_functions/.

We reuse the SAME §4.5 enumeration/pruning as the AgentDojo leg.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from corpus.agentdojo._common import _flows, render_flows_by_guard  # noqa: E402

# shell_gpt's loadable tools (scanned from sgpt/llm_functions/), classified per
# §4.5.1. Each shell/AppleScript tool is BOTH a sink (it executes a model-chosen
# command) and a source (its *output* — e.g. the text a command prints — is
# attacker-influenceable and flows back into the history).
SOURCES = {
    # the tool OUTPUT is attacker-influenceable free text (command stdout).
    "execute_shell_command:out": dict(reachable=True, capacity="string", attacker=True,
                                       sensitive=False, hidden=False),
    "execute_apple_script:out":  dict(reachable=True, capacity="string", attacker=True,
                                       sensitive=False, hidden=False),
}
SINKS = {
    # the tool COMMAND is a code-execution sink (subprocess.Popen / osascript),
    # run directly with NO in-function guard.
    "execute_shell_command":  dict(reachable=True, sensitive=True, capacity="string",
                                   category="code_execution", guard=None),
    "execute_apple_script":   dict(reachable=True, sensitive=True, capacity="string",
                                   category="code_execution", guard=None),
}

if __name__ == "__main__":
    flows = _flows(SOURCES, SINKS)
    print(render_flows_by_guard(flows, SINKS, title="shell_gpt registry enumeration (leg b)"))
    print("\nNote: shell_gpt's execute_shell/apple_script run the model-chosen "
          "command with NO in-function guard (subprocess.Popen(shell=True) / "
          "osascript directly). Any mitigation lives at the CLI/confirmation "
          "layer, not the tool.")
