"""VULNERABLE — MANUAL dict-dispatch split across methods (1-hop control taint).

This is the shape the 5th real target (maxscheijen_dict_registry) exposed, reduced
to the essence and kept framework-free.  The LLM call is in one method; the manual
dispatch wall ``tool_map[name](...)`` is in a *helper* method that receives the
LLM-derived tool-call object as an argument:

    def run(self, query):
        resp = client.chat.completions.create(...)   # LLM call (control born)
        for call in resp.choices[0].message.tool_calls:
            self._dispatch(call)                     # 1-hop: pass control-tainted arg
    def _dispatch(self, call):
        return self.tool_map[call.name](call.args)   # manual wall, in another method

Intra-procedural analysis records the wall only when its argument carries the LLM
control mark; because the wall is in ``_dispatch`` and the LLM call is in ``run``,
that mark never arrives.  A conservative 1-hop propagation of control taint from a
call site into the called method's parameter lets the wall be recorded.

Analysis target only; never executed.
"""

import json
import subprocess

from openai import OpenAI

TOOL_MAP = {}


def run_cmd(command: str) -> str:
    """Run a shell command (DANGEROUS — code-execution sink)."""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


TOOL_MAP["run_cmd"] = run_cmd


class Agent:
    def __init__(self):
        self.tool_map = TOOL_MAP

    def run(self, query: str):
        client = OpenAI()
        resp = client.chat.completions.create(
            messages=[{"role": "user", "content": query}], model="gpt-4o")
        for call in resp.choices[0].message.tool_calls:
            self._dispatch(call)

    def _dispatch(self, call):
        return self.tool_map[call.function.name](**json.loads(call.function.arguments))
