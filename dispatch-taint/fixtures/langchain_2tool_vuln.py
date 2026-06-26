"""VULNERABLE — canonical Stage-1 LangChain two-tool agent (§7 stage 1).

Cross-tool implicit flow (CWE-1426):

    read_webpage()  --(tool output, attacker-influenceable)-->
    ToolMessage(content=...)  --append-->  messages  --llm.invoke-->
    response.tool_calls[i].args["command"]  -->  subprocess.run   (SINK)

No byte of the web page is copied into the command; the fetched text *selects*
which command the model emits.  This is the implicit/control-dependency flow the
data layer (TITO) cannot see, and the one the engine should report.

This module is an analysis target only; it is never executed.
"""

import subprocess

from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI


@tool
def read_webpage(url: str) -> str:
    """Fetch a web page and return its text (UNTRUSTED, attacker-influenceable)."""
    import requests
    return requests.get(url).text


@tool
def run_shell(command: str) -> str:
    """Run a shell command (the dangerous tool)."""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


def run_agent(user_goal: str) -> None:
    llm = ChatOpenAI(model="gpt-4o").bind_tools([read_webpage, run_shell])
    messages = [HumanMessage(content=user_goal)]

    for _ in range(10):
        response = llm.invoke(messages)
        messages.append(response)
        if not response.tool_calls:
            break
        for call in response.tool_calls:
            if call["name"] == "read_webpage":
                page = read_webpage.invoke(call["args"])
                # tool output enters the history here -> taints messages[*]
                messages.append(ToolMessage(content=page, tool_call_id=call["id"]))
            elif call["name"] == "run_shell":
                # SINK: command is chosen by the model after reading the page.
                subprocess.run(call["args"]["command"], shell=True)
