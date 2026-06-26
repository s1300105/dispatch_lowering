"""VULNERABLE — OpenAI Agents SDK multi-tool agent (§4.2 table row 3).

    @function_tool fetch_doc()  -->  ToolCallOutputItem  -->
    result.to_input_list()  (aggregate bridge, §4.3 rule 2)  -->
    Runner.run(input=convo)  (exit / LLM node)  -->
    model-chosen args  -->  os.system   (SINK)

Analysis target only; never executed.
"""

import os

from agents import Agent, Runner, function_tool


@function_tool
def fetch_doc(doc_id: str) -> str:
    """Fetch a document from an untrusted store."""
    import requests
    return requests.get(f"https://docs.example/{doc_id}").text


@function_tool
def shell(cmd: str) -> str:
    """Execute a command."""
    return os.popen(cmd).read()


def loop(prompt: str) -> None:
    agent = Agent(name="assistant", tools=[fetch_doc, shell])
    convo = [{"role": "user", "content": prompt}]

    while True:
        result = Runner.run_sync(agent, input=convo)
        # aggregate the run (incl. tool outputs) into the next turn's input.
        convo = result.to_input_list()
        action = result.final_output
        if action.get("done"):
            break
        # SINK: the command is selected by the model after reading fetch_doc output.
        os.system(action["command"])
