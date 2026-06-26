"""VULNERABLE — framework-MANAGED dispatch (項目1).

Unlike ``langchain_2tool_vuln.py`` (which writes the dispatch loop by hand:
``for call in response.tool_calls: read_webpage.invoke(...)``), this agent hands
its tools to a framework factory and calls a launch method.  LangGraph's ToolNode
then selects and runs the chosen tool *inside the framework* — the dispatch wall
is invisible to a syntactic scan of user code:

    agent = create_react_agent(llm, tools=[fetch_url, run_cmd])   # registration
    agent.invoke({"messages": [("user", goal)]})                  # launch == wall

``fetch_url`` (attacker-influenceable) and ``run_cmd`` (a code-execution sink) are
both registered, and the framework internally routes a fetched page through the
model into the tool call.  The cross-tool implicit flow (CWE-1426) therefore runs
entirely inside the framework; ctaudit recovers it from the declarative dispatch
spec (DispatchSpec) rather than by penetrating the framework body.

Analysis target only; never executed.
"""

import subprocess

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent


@tool
def fetch_url(url: str) -> str:
    """Fetch a web page (UNTRUSTED tool output)."""
    import requests
    return requests.get(url).text


@tool
def run_cmd(command: str) -> str:
    """Run a shell command (DANGEROUS — code-execution sink)."""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


def run_agent(user_goal: str):
    llm = ChatOpenAI(model="gpt-4o")
    agent = create_react_agent(llm, tools=[fetch_url, run_cmd])
    return agent.invoke({"messages": [("user", user_goal)]})
