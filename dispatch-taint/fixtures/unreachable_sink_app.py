"""Reachability fixture (§4.5(1)).

The cross-tool wiring is genuinely present: a tool output (``read_ticket``) is
wrapped in a ToolMessage, appended to the history, and the model's tool-call
routing out of ``llm.invoke`` would drive ``subprocess.run``. The engine's
over-approximation therefore raises an implicit candidate at the sink.

But the sink sits *after an unconditional ``return``* in the same block, so it
can never execute. §4.5(1) reachability prunes the candidate. Turning the
reachability prune off (ablation) brings the candidate back, demonstrating that
it is the prune — not the detector — that removes it.
"""

import subprocess

from langchain_core.messages import ToolMessage
from langchain_core.tools import tool


@tool
def read_ticket() -> str:
    """Attacker-influenceable: reads an external ticket body."""
    with open("/tmp/ticket.txt") as fh:
        return fh.read()


def handle(llm):
    messages = [{"role": "user", "content": "triage this ticket"}]
    messages.append(ToolMessage(content=read_ticket(), tool_call_id="t1"))

    response = llm.invoke(messages)
    for call in response.tool_calls:
        command = call["args"]["command"]
        return command                       # unconditional return
        subprocess.run(command, shell=True)  # DEAD CODE: never executes
