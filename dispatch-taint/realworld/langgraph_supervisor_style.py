"""REAL-REPO analysis target B — create_react_agent with UNDECORATED tools.

Source: pattern from github.com/langchain-ai/langgraph-supervisor-py README
(public).  Transcribed for STATIC ANALYSIS ONLY (never executed).  LangGraph
accepts plain Python functions as tools (no ``@tool`` decorator required); this
target uses that style and adds one function whose body performs a dangerous
operation in USER code.

Pattern exercised (different again):
  * tools are PLAIN functions (NO ``@tool`` decorator).
  * passed as a LITERAL list directly to ``create_react_agent``.
  * launched via ``.invoke({"messages": ...})``.

This stresses tool capture: the dispatch wall should still be detected (the
registered tool list is right there in the factory call), but whether the sink is
grounded depends on the classifier recognising an undecorated function as a tool.
"""

import os

from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI


def web_search(query: str) -> str:
    """Search the web for information (untrusted source)."""
    import requests
    return requests.get("https://example.com/s", params={"q": query}).text


def run_command(cmd: str) -> str:
    """Run a system command (DANGEROUS — code execution in user code)."""
    return os.popen(cmd).read()


model = ChatOpenAI(model="gpt-4o")
graph = create_react_agent(model, tools=[web_search, run_command])


def main(question: str):
    return graph.invoke({"messages": [("user", question)]})
