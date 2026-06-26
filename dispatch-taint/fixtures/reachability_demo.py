"""方向C demonstration — intra-tool argument reachability.

Two tools are registered with the same framework agent:

  * ``run_cmd`` passes its argument straight into ``subprocess.run`` — the
    dispatched value DRIVES the dangerous call (arg reaches → stays high).
  * ``lookup`` uses its argument only as a dictionary KEY; what reaches
    ``subprocess.run`` is a fixed, validated value, never the parameter — the
    dispatched value cannot drive the dangerous call (arg provably does NOT
    reach → kept but downgraded to low).

Both have ``subprocess.run`` in their body, so a body-only scan flags both as
high-severity sinks.  方向C's intra-tool reachability separates them: it keeps
both (recall-first) but lowers the severity of the one whose argument cannot
reach the dangerous operation.

Analysis target only; never executed.
"""

import subprocess

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

_ALLOWED = {"status": "systemctl status", "uptime": "uptime"}


@tool
def run_cmd(command: str) -> str:
    """Run a shell command (argument REACHES the sink)."""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


@tool
def lookup(key: str) -> str:
    """Run a FIXED command chosen by key (argument does NOT reach the sink)."""
    safe = _ALLOWED[key]                 # key used only as a lookup key
    return subprocess.run(["/bin/sh", "-c", safe], shell=False).stdout.decode()


def run_agent(user_goal: str):
    llm = ChatOpenAI(model="gpt-4o")
    agent = create_react_agent(llm, tools=[run_cmd, lookup])
    return agent.invoke({"messages": [("user", user_goal)]})
