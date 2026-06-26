#!/usr/bin/env python3
"""Enumeration leg (b) on termwise's REAL tool registry — guard-aware.

termwise abstracts the LLM behind an HTTP provider (`self._client.post(
"/chat/completions", …)`, not the SDK) and dispatches tools through a dict
registry of `Tool` subclasses (`self.tools[name].execute`). As with shell_gpt,
the dict-of-subclasses dispatch defeats static data-flow to the concrete
dangerous tool, so we enumerate the registry (leg b).

NEW here: termwise's shell sink runs `subprocess.run(shell=True)` only AFTER an
in-function `_check_safety(command)` guard, while its `file_writer` sink has no
such guard. So this enumeration is **guard-aware**: it still reports every flow
(the guard does not remove it), but separates UNGUARDED sinks (high priority —
the "unintended/unguarded" instances the sharpened RQ1 targets) from GUARDED ones
(noted, lower priority). That guard signal is the audit's real value.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from corpus.agentdojo._common import _flows, render_flows_by_guard  # noqa: E402

# termwise tools (scanned from termwise/tools/), classified per §4.5.1.
SOURCES = {
    # tool OUTPUTS that carry attacker-influenceable bytes (file content / names,
    # command stdout) back into the history.
    "read_file:out": dict(reachable=True, capacity="string", attacker=True,
                           sensitive=False, hidden=False),
    "search:out":    dict(reachable=True, capacity="string", attacker=True,
                          sensitive=False, hidden=False),
    "shell:out":     dict(reachable=True, capacity="string", attacker=True,
                          sensitive=False, hidden=False),
}
SINKS = {
    # shell command -> subprocess.run(shell=True), GUARDED by _check_safety().
    "shell":       dict(reachable=True, sensitive=True, capacity="string",
                        category="code_execution", guard="_check_safety"),
    # file write -> open(path,'w').write(content), NO guard.
    "write_file":  dict(reachable=True, sensitive=True, capacity="string",
                        category="file_write", guard=None),
}

if __name__ == "__main__":
    flows = _flows(SOURCES, SINKS)
    print(render_flows_by_guard(flows, SINKS,
                                title="termwise registry enumeration (leg b, guard-aware)"))
    print("\nNote: the guard does not remove the static flow (a weak/incomplete "
          "_check_safety can still be bypassed), so it is recorded as a "
          "mitigating factor, not a prune. shell_gpt, by contrast, has NO "
          "in-function guard on its code-exec tools.")
