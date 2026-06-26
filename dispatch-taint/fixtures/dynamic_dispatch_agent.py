"""VULNERABLE — dynamic-dispatch agent loop (fusion #4 demo; analysis target only).

    tool output  -->  ToolMessage(content=...)  -->
    state["messages"] = add_messages(state["messages"], [tool_msg])  (reducer merge) -->
    llm.invoke(state["messages"])  (exit)  -->
    model-chosen {name, args}  -->  TOOL_MAP[name](**args)   (DYNAMIC DISPATCH)

The sink call is *dynamically dispatched*: the model (after reading attacker-
influenceable prior tool output) chooses a tool NAME and ARGS, and the dispatcher
routes to a runtime-selected callable. A static name-matcher cannot say which
concrete tool — hence which sink — this reaches, so the dataflow leg records a
``dispatch`` finding (the wall). Fusion #4 resolves it against the shared tool model:
``run_cmd`` (code-execution) and ``fetch_url`` (network/SSRF) are the registered
sinks; ``echo`` is benign.

Never executed.
"""

import subprocess

import requests
from langchain_core.messages import ToolMessage
from langchain_openai import ChatOpenAI
from langgraph.graph.message import add_messages


def fetch_url(url: str) -> str:
    """network/SSRF sink."""
    return requests.get(url).text


def run_cmd(cmd: str) -> bytes:
    """code-execution sink."""
    return subprocess.run(cmd, shell=True, capture_output=True).stdout


def echo(text: str) -> str:
    """benign — no sink."""
    return text


TOOL_MAP = {"fetch_url": fetch_url, "run_cmd": run_cmd, "echo": echo}


def search_tool(query: str) -> str:
    """Untrusted search backend (attacker-influenceable tool output)."""
    return requests.get("https://search.example", params={"q": query}).text


def run(state: dict) -> dict:
    llm = ChatOpenAI(model="gpt-4o")

    while not state.get("done"):
        response = llm.invoke(state["messages"])               # exit (join@LLM)

        for call in getattr(response, "tool_calls", []):
            # the model chose NAME + ARGS after reading prior tool output; the
            # dispatcher routes to a runtime-selected callable -> concrete sink hidden.
            TOOL_MAP[call["name"]](**call["args"])             # DISPATCH WALL

        raw = search_tool(state["query"])                       # untrusted tool output (source)
        tool_msg = ToolMessage(content=raw, tool_call_id="t1")
        state["messages"] = add_messages(state["messages"], [tool_msg])

    return state
