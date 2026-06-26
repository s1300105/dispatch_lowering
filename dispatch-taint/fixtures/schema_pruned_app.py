"""SCHEMA-PRUNED — a narrow-channel source (§4.5(2) / §4.6 channel capacity).

``is_safe_url`` is a tool declared to return ``bool``: a one-bit channel.  Its
output is routed through the model to a ``subprocess.run`` whose dangerous
parameter is a free-form string.  The engine first raises the candidate (the
control edge exists), then the schema pruner removes it: a 1-bit source cannot
carry an arbitrary command into a string sink (bool ⊑ enum ⊑ string).

Run with ``--show-pruned`` to see it listed with its prune reason.  This prune is
ablatable; the proposal is explicit that it rarely fires because most real tool
outputs are strings.

Analysis target only; never executed.
"""

import subprocess
from typing import Literal

from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI


@tool
def is_safe_url(url: str) -> bool:
    """Return whether a URL is allowlisted (one-bit, narrow channel)."""
    return url.startswith("https://trusted.example")


@tool
def pick_region(name: str) -> Literal["us", "eu", "ap"]:
    """Return a region code (enum, also narrow)."""
    return "us"


def run_agent(goal: str) -> None:
    llm = ChatOpenAI(model="gpt-4o").bind_tools([is_safe_url, pick_region])
    messages = [HumanMessage(content=goal)]

    for _ in range(5):
        response = llm.invoke(messages)
        for call in response.tool_calls:
            if call["name"] == "is_safe_url":
                verdict = is_safe_url.invoke(call["args"])
                messages.append(ToolMessage(content=verdict, tool_call_id=call["id"]))
            elif call["name"] == "run_shell":
                # candidate, but the only attacker-influenced source is 1-bit.
                subprocess.run(call["args"]["command"], shell=True)
