"""SAFE-by-guard — multi-tool agent where the model-chosen command is gated by a
human confirmation BEFORE the sink. A genuine cross-tool implicit flow exists
(fetch_doc -> LLM -> os.system), but it is guarded, so the auditor must report it
with guard != None (this exercises guard classification, not a missed flow).

    @function_tool fetch_doc()  -->  Runner.run (LLM node)  -->
    model-chosen command  -->  confirm(...)  -->  os.system   (SINK, guarded)

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
    return os.popen(cmd).read()


def confirm(action) -> bool:
    return input(f"Run {action!r}? [y/N] ").strip().lower() == "y"


def loop(prompt: str) -> None:
    agent = Agent(name="assistant", tools=[fetch_doc, shell])
    convo = [{"role": "user", "content": prompt}]
    while True:
        result = Runner.run_sync(agent, input=convo)
        convo = result.to_input_list()
        action = result.final_output
        if action.get("done"):
            break
        if not confirm(action["command"]):     # GUARD dominating the sink
            continue
        os.system(action["command"])           # SINK (guarded by confirm)
