"""REAL-REPO analysis target — dict-registry (``tool_mapping[name]()``) dispatch.

Source: maxscheijen.github.io "Basic LLM Agent with Tool Calling" (public blog).
Transcribed for STATIC ANALYSIS ONLY (never executed).  This is a hand-written
(no-framework) agent built directly on the OpenAI SDK, and it is the
dict-registry / syntactic-wall shape:

    self.tool_mapping = {tool.__name__: tool for tool in self.tools}   # registry
    ...
    self.tool_mapping[tool.function.name](**json.loads(tool.function.arguments))  # wall

This differs from the four framework targets: the dispatch is a dictionary indexed
by the LLM-chosen name, written in user code, and the LLM call is the raw OpenAI
``client.chat.completions.create(...)`` rather than a LangChain agent launch.  It
exercises the ORIGINAL syntactic-wall path (not DispatchSpec).

The published example registers only ``get_weather`` (a network source).  To make
the cross-tool flow concrete, this transcription also registers ``run_shell`` — a
shell-command tool of the same hand-written style — as the dangerous sink.  This
added tool is clearly an analysis aid; the agent *structure* (registry + loop +
dict dispatch + OpenAI call) is faithful to the source.

Judgement criterion: flow reachability (source -> LLM -> dangerous tool in code),
not exploitability.
"""

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable

import requests
from openai import OpenAI


def get_weather(latitude: float, longitude: float) -> dict | str:
    """Get the weather for a latitude/longitude (untrusted web source)."""
    with requests.Session() as session:
        response = session.get(
            f"https://api.open-meteo.com/v1/forecast?latitude={latitude}"
            f"&longitude={longitude}&current=temperature_2m"
        )
        if response.status_code == 200:
            return response.json()
        return "Error: Unable to fetch data"


def run_shell(command: str) -> str:
    """Run a shell command (DANGEROUS — code-execution sink, user code)."""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


@dataclass
class Agent:
    system_prompt: str = ""
    model: str = "gpt-4o-mini"
    tools: list[Callable] = field(default_factory=list)

    def __post_init__(self):
        self.messages: list[dict[str, Any]] = []
        self.tool_mapping = {tool.__name__: tool for tool in self.tools}
        if self.system_prompt:
            self.messages.append({"role": "system", "content": self.system_prompt})

    def run(self, query: str, max_iterations: int = 5) -> str:
        client = OpenAI()
        self.messages.append({"role": "user", "content": query})
        for _ in range(max_iterations):
            response = client.chat.completions.create(
                messages=self.messages,
                model=self.model,
                temperature=0,
            )
            if tool_calls := response.choices[0].message.tool_calls:
                for tool in tool_calls:
                    self.call_tool(tool)
            else:
                break
        return self.messages[-1]["content"]

    def call_tool(self, tool) -> Any:
        return self.tool_mapping[tool.function.name](
            **json.loads(tool.function.arguments)
        )


def main(query: str):
    agent = Agent(system_prompt="You are a helpful assistant.",
                  tools=[get_weather, run_shell])
    return agent.run(query)
