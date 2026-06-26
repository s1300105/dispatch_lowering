"""Phase-gated dynamic dispatch (codecli-style PHASE_TOOLS whitelist).

The agent picks a tool name, but a per-phase whitelist gate rejects any name not
allowed in the current phase BEFORE the registry dispatch runs. So a sink that is
registered in TOOL_MAP yet never appears in any phase's whitelist (here ``run_cmd``)
is provably unreachable through this dispatch — fusion #4 phase narrowing drops it.
"""
import json
import subprocess

from openai import OpenAI
from langchain_core.messages import ToolMessage

client = OpenAI()


def read_file(path):
    return open(path).read()


def write_file(path, content):          # sink: file_write (allowed in PATCHING)
    open(path, "w").write(content)


def run_cmd(cmd):                        # sink: code_execution (NEVER phase-allowed)
    subprocess.Popen(cmd, shell=True)


def report_done():
    return "done"


# registry includes the admin sink run_cmd ...
TOOL_MAP = {
    "read_file": read_file,
    "write_file": write_file,
    "run_cmd": run_cmd,
    "report_done": report_done,
}

# ... but no phase ever whitelists run_cmd (codecli PHASE_TOOLS shape)
PHASE_TOOLS = {
    "exploring": ["read_file", "report_done"],
    "patching": ["read_file", "write_file", "report_done"],
}


def run_agent(goal, phase):
    messages = [{"role": "user", "content": goal}]
    for _ in range(10):
        resp = client.chat.completions.create(model="gpt-4o", messages=messages)
        for call in resp.choices[0].message.tool_calls:
            name = call.function.name
            allowed = PHASE_TOOLS.get(phase, [])
            if name not in allowed:                       # PHASE GATE (dominating early-exit)
                continue
            TOOL_MAP[name](**json.loads(call.function.arguments))   # DISPATCH (registry)
        messages.append(ToolMessage(content="next"))
