"""VULNERABLE — LangGraph multi-node agent (cross-node add_messages reducer).

This is the proposal's 「実装上の最難関」 in its hardest, fully inter-procedural
form. The tool node, the model node, and the dangerous action node are three
SEPARATE functions wired declaratively by ``add_node`` / ``add_edge``. No
function calls another directly; the ``add_messages`` reducer threads
``state["messages"]`` between them. The cross-tool implicit flow exists ONLY
across node boundaries:

    tools_node :  raw = fetch_url(...)                          # attacker-influenceable
                  return {"messages": [ToolMessage(content=raw)]}   # -> merged into state
    model_node :  resp = llm.invoke(state["messages"])          # reads merged history -> CTL
                  return {"messages": [resp]}                    # CTL -> merged into state
    action_node:  cmd = state["messages"][-1].tool_calls[0]["args"]["command"]
                  subprocess.run(cmd, shell=True)                # SINK, driven by routing

Analysed by threading a shared "state channel" between the node functions and
running it to a fixpoint.  Analysis target only; never executed.
"""

import subprocess
from typing import Annotated, TypedDict

import requests
from langchain_core.messages import ToolMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph
from langgraph.graph.message import add_messages


class State(TypedDict):
    messages: Annotated[list, add_messages]
    query: str


@tool
def fetch_url(q: str) -> str:
    """Untrusted: returns the body of an attacker-influenceable page."""
    return requests.get("https://api.example", params={"q": q}).text


def tools_node(state: State) -> dict:
    raw = fetch_url(state["query"])
    return {"messages": [ToolMessage(content=raw, tool_call_id="t1")]}


def model_node(state: State) -> dict:
    llm = ChatOpenAI(model="gpt-4o")
    response = llm.invoke(state["messages"])      # reads the cross-node history
    return {"messages": [response]}


def action_node(state: State) -> dict:
    last = state["messages"][-1]
    command = last.tool_calls[0]["args"]["command"]   # model-chosen, attacker-influenced
    subprocess.run(command, shell=True)               # SINK
    return state


def build():
    g = StateGraph(State)
    g.add_node("tools", tools_node)
    g.add_node("model", model_node)
    g.add_node("act", action_node)
    g.add_edge("tools", "model")
    g.add_edge("model", "act")
    g.add_edge("act", "tools")
    return g.compile()
