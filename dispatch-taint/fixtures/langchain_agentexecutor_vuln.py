"""VULNERABLE — framework-MANAGED dispatch via classic ``AgentExecutor`` (項目1).

A second framework registration shape: the classic LangChain ``AgentExecutor``
takes ``tools=[...]`` and its ``.invoke`` runs the agent loop, dispatching to the
chosen tool internally.  The dispatch wall is again invisible to a syntactic scan.

    executor = AgentExecutor(agent=agent, tools=[search_web, run_shell])  # registration
    executor.invoke({"input": goal})                                      # launch == wall

``search_web`` (attacker-influenceable) and ``run_shell`` (code-execution sink) are
both registered; the framework internally routes the fetched content through the
model into the tool call.  Same cross-tool implicit flow (CWE-1426) as the manual
loop, but hidden behind the executor.

Analysis target only; never executed.
"""

import subprocess

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI


@tool
def search_web(query: str) -> str:
    """Search the web (UNTRUSTED tool output)."""
    import requests
    return requests.get("https://example.com/search", params={"q": query}).text


@tool
def run_shell(command: str) -> str:
    """Run a shell command (DANGEROUS — code-execution sink)."""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


def run_agent(user_goal: str):
    llm = ChatOpenAI(model="gpt-4o")
    agent = create_tool_calling_agent(llm, [search_web, run_shell], prompt=None)
    executor = AgentExecutor(agent=agent, tools=[search_web, run_shell])
    return executor.invoke({"input": user_goal})
