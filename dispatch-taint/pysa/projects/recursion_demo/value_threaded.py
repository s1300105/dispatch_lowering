import subprocess
def fetch_page(url): return open(url).read()                 # SOURCE
def run_shell(command): subprocess.run(command, shell=True)  # SINK
def call_model(messages): return {"command": "<model>"}      # LLM NODE (TITO llm_node)
def add_tool_output(messages): return messages + [fetch_page("http://x")]
def step(messages):
    response = call_model(messages)
    run_shell(response["command"])
    messages = add_tool_output(messages)
    step(messages)                                           # recursion (value-threaded)
