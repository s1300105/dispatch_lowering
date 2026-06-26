"""VULNERABLE — framework agent whose dispatch is split across METHODS (1-hop).

Many real agents wrap a framework agent in a class and split the work across
methods: one method launches the agent (the LLM call / wall), and a *helper*
method actually invokes the chosen tool.  With purely intra-procedural analysis
the control taint born at the launch in one method never reaches the dispatch in
the other method, so the wall is missed.

    class Bot:
        def __init__(self):
            self.agent = create_react_agent(llm, tools=[fetch_url, run_cmd])
        def handle(self, goal):
            result = self.agent.invoke({"messages": [("user", goal)]})  # launch == wall
            return self._dispatch(result)            # 1-hop call carrying the result
        def _dispatch(self, result):
            ...                                       # uses the framework result

Here the launch IS the wall (framework-managed), so this fixture specifically
exercises that a launch recorded in ``handle`` is still attributed correctly even
though the surrounding orchestration is split into ``_dispatch``.  The companion
manual-dispatch split is in ``method_split_manual.py``.

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


class Bot:
    def __init__(self):
        llm = ChatOpenAI(model="gpt-4o")
        self.agent = create_react_agent(llm, tools=[fetch_url, run_cmd])

    def handle(self, goal: str):
        result = self.agent.invoke({"messages": [("user", goal)]})
        return self._postprocess(result)

    def _postprocess(self, result):
        return str(result)
