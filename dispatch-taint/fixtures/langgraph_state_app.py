"""VULNERABLE — LangGraph state agent using the add_messages reducer (§4.3 rule 3).

    tool output  -->  ToolMessage(content=...)  -->
    state["messages"] = add_messages(state["messages"], [tool_msg])  (reducer merge) -->
    llm.invoke(state["messages"])  (exit)  -->
    model-chosen args  -->  requests.get   (SINK, SSRF via routing)

The reducer is the proposal's "実装上の最難関": ``add_messages`` is modelled as a
step that joins the new-message labels with the existing-history labels.  Here it
is written in the explicit ``state[key] = add_messages(state[key], [...])`` form
that the prototype handles intra-procedurally.

Analysis target only; never executed.
"""

import requests
from langchain_core.messages import ToolMessage
from langgraph.graph.message import add_messages
from langchain_openai import ChatOpenAI


def search_tool(query: str) -> str:
    """Untrusted search backend."""
    return requests.get("https://search.example", params={"q": query}).text


def run(state: dict) -> dict:
    llm = ChatOpenAI(model="gpt-4o")

    while not state.get("done"):
        response = llm.invoke(state["messages"])

        for call in getattr(response, "tool_calls", []):
            if call["name"] == "fetch":
                # SINK: URL chosen by the model after reading prior tool output.
                requests.get(call["args"]["url"])

        raw = search_tool(state["query"])
        tool_msg = ToolMessage(content=raw, tool_call_id="t1")
        # declarative reducer merge into the state's message channel.
        state["messages"] = add_messages(state["messages"], [tool_msg])

    return state
