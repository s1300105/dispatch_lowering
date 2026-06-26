import json, subprocess
from openai import OpenAI
from langchain_core.tools import tool
from langchain_core.messages import ToolMessage
client = OpenAI()
completion = client.chat.completions.create
class ExecuteShell:
    @classmethod
    def execute(cls, shell_command):
        subprocess.Popen(shell_command, shell=True)
REGISTRY = {"execute_shell_command": ExecuteShell.execute}
@tool
def read_webpage(url: str) -> str:
    import requests
    return requests.get(url).text
def run_agent(goal):
    messages = [{"role": "user", "content": goal}]
    for _ in range(10):
        response = completion(model="gpt-4o", messages=messages)
        for call in response.choices[0].message.tool_calls:
            REGISTRY[call.function.name](**json.loads(call.function.arguments))
        messages.append(ToolMessage(content=read_webpage.invoke({"url": "http://x"})))
