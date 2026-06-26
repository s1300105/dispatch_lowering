"""VULNERABLE — framework-MANAGED dispatch via ``create_agent`` + ``.stream`` (項目1).

A third shape: the new ``langchain.create_agent`` factory, launched with
``.stream`` instead of ``.invoke``.  The streaming launch still drives the
framework's internal tool dispatch (the wall).

    agent = create_agent(model=llm, tools=[read_doc, exec_python])  # registration
    for chunk in agent.stream({"messages": [...]}):                 # launch == wall
        ...

``read_doc`` (attacker-influenceable) and ``exec_python`` (code-execution sink)
are both registered.  Same cross-tool implicit flow (CWE-1426), via a streaming
launch.

Analysis target only; never executed.
"""

from langchain.agents import create_agent
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI


@tool
def read_doc(path: str) -> str:
    """Read a document from a URL (UNTRUSTED tool output)."""
    import requests
    return requests.get(path).text


@tool
def exec_python(code: str) -> str:
    """Execute Python code (DANGEROUS — code-execution sink)."""
    return str(eval(code))


def run_agent(user_goal: str):
    llm = ChatOpenAI(model="gpt-4o")
    agent = create_agent(model=llm, tools=[read_doc, exec_python])
    out = []
    for chunk in agent.stream({"messages": [("user", user_goal)]}):
        out.append(chunk)
    return out
