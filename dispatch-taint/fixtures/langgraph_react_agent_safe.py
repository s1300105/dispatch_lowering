"""SAFE — framework-MANAGED agent with NO dangerous tool registered (項目1 negative).

Same framework wiring as ``langgraph_react_agent.py`` (create_react_agent + .invoke),
but the registered tool set contains only benign tools: a web fetch (a source) and
an ``echo`` formatter that performs no dangerous operation.  There is no sink tool
for the dispatch to reach, so the framework wall resolves to nothing and ctaudit
must report no cross-tool implicit flow.

This is the negative that checks 項目1 does not over-report: detecting the wall is
not enough — a flow is only emitted when a *dangerous* tool is reachable.

    agent = create_react_agent(llm, tools=[fetch_url, echo])   # registration (no sink)
    agent.invoke({"messages": [...]})                          # launch == wall

Analysis target only; never executed.
"""

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent


@tool
def fetch_url(url: str) -> str:
    """Fetch a web page (UNTRUSTED tool output, but only fed to a benign tool)."""
    import requests
    return requests.get(url).text


@tool
def echo(text: str) -> str:
    """Return the text unchanged (benign — no dangerous operation)."""
    return text


def run_agent(user_goal: str):
    llm = ChatOpenAI(model="gpt-4o")
    agent = create_react_agent(llm, tools=[fetch_url, echo])
    return agent.invoke({"messages": [("user", user_goal)]})
