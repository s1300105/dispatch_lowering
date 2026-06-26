import subprocess
def fetch_page(url): return open(url).read()
def run_shell(command): subprocess.run(command, shell=True)
def call_model(messages): return {"command": "<model>"}
def append_message(history, msg): history.append(msg)        # §4.3 bridge (modeled)
def step(messages):
    response = call_model(messages)
    run_shell(response["command"])
    append_message(messages, fetch_page("http://x"))         # shared mutable history
    step(messages)                                           # recursion
