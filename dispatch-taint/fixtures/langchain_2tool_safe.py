"""SAFE — same wiring as the vulnerable app, but the untrusted tool output is
*selectively hidden* (§4.5(4), FIDES HIDE): it is stored by reference and never
expanded into the prompt text the model reasons over.  The control edge is cut,
so no cross-tool implicit flow should be reported (the join at the LLM node drops
hidden marks; the selective-hiding prune is the explicit backstop).

Analysis target only; never executed.
"""

import subprocess

from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI


def hide(value):
    """Quarantine an untrusted value behind a reference handle (FIDES HIDE).

    The handle, not the content, is placed in the prompt, so the model never
    reads the attacker-influenceable bytes and cannot be steered by them.
    """
    return {"$ref": _store(value)}


_QUARANTINE = {}


def _store(value) -> str:
    key = f"ref-{len(_QUARANTINE)}"
    _QUARANTINE[key] = value
    return key


@tool
def read_webpage(url: str) -> str:
    """Fetch a web page (UNTRUSTED)."""
    import requests
    return requests.get(url).text


def run_agent(user_goal: str) -> None:
    llm = ChatOpenAI(model="gpt-4o").bind_tools([read_webpage])
    messages = [HumanMessage(content=user_goal)]

    for _ in range(10):
        response = llm.invoke(messages)
        messages.append(response)
        if not response.tool_calls:
            break
        for call in response.tool_calls:
            if call["name"] == "read_webpage":
                page = read_webpage.invoke(call["args"])
                # hidden: only the reference handle reaches the prompt.
                messages.append(ToolMessage(content=hide(page), tool_call_id=call["id"]))

    # A sink exists in the file, but it is driven by a constant, not by any
    # tool output routed through the model.
    subprocess.run("echo done", shell=True)
