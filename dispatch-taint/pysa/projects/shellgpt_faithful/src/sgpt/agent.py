"""shell_gpt structure, lit END-TO-END with Pysa:
  aliased LLM call (exit, llm_node) + registry dispatch (if/return, Pyre-resolved)
  + tool output -> shared history via §4.3 bridge (value-threaded) + RECURSION
  + sink = the model-chosen shell command.
(The tool is a free function: shell_gpt's @classmethod tool would need explicit
 dispatch modeling, since Pyre's higher-order resolution does not follow it.)"""
from openai import OpenAI
client = OpenAI()
completion = client.chat.completions.create        # alias resolved by type

def execute_shell(shell_command):                  # SINK (shell_command) + SOURCE (return)
    import subprocess
    return subprocess.Popen(shell_command, shell=True, stdout=subprocess.PIPE).communicate()[0].decode()

def get_function(name):                            # registry dispatch (Pyre resolves if/return)
    if name == "execute_shell_command":
        return execute_shell
    raise KeyError(name)

class Handler:
    def handle_function_call(self, name, arguments):
        import json
        return get_function(name)(**json.loads(arguments))     # dispatch -> execute_shell

    def get_completion(self, model, messages, functions):
        response = completion(model=model, messages=messages, tools=functions)   # exit (llm_node)
        tc = response.choices[0].message.tool_calls[0]
        result = self.handle_function_call(tc.function.name, tc.function.arguments)
        messages = messages + [{"role": "tool", "content": result}]              # §4.3 bridge
        self.get_completion(model, messages, functions)                          # RECURSION
