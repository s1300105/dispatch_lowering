"""HTTP-provider agent loop (no SDK): the LLM call is a raw httpx POST inside a
provider abstraction — termwise's shape. Dispatch kept resolvable here so the
flow lights end-to-end once the HTTP exit is modeled."""
import subprocess
import httpx


class OpenAIProvider:
    def __init__(self):
        self._client = httpx.Client(base_url="https://api.openai.com")
    def complete_with_tools(self, messages):
        payload = {"model": "gpt-4o", "messages": messages}
        response = self._client.post("/chat/completions", json=payload)   # HTTP exit (llm_node)
        return response.json()

def shell_exec(cmd):
    return subprocess.run(cmd, shell=True)

def read_page(url):                                  # tool: OUTPUT is a source
    return httpx.Client().get(url).text if False else "untrusted page text"

def run_tool(name, args):                            # resolvable dispatch
    if name == "shell":
        return shell_exec(args["cmd"])                   # sink (user wrapper)
    return read_page(args["url"])

def agent(goal):
    provider = OpenAIProvider()
    messages = [{"role": "user", "content": goal}]
    for _ in range(8):
        data = provider.complete_with_tools(messages)         # via provider abstraction
        for call in data["tool_calls"]:
            run_tool(call["name"], call["arguments"])         # model-chosen routing -> sink
        messages = messages + [{"role": "tool", "content": read_page("http://x")}]  # source -> history
