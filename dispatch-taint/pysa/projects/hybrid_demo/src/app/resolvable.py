from openai import OpenAI
client = OpenAI()
completion = client.chat.completions.create
def execute_shell(shell_command):                 # SINK + SOURCE
    import subprocess
    return subprocess.Popen(shell_command, shell=True, stdout=subprocess.PIPE).communicate()[0].decode()
def get_function(name):
    if name == "execute_shell_command":
        return execute_shell
    raise KeyError(name)
class Handler:
    def handle_function_call(self, name, arguments):
        import json
        return get_function(name)(**json.loads(arguments))
    def get_completion(self, model, messages, functions):
        response = completion(model=model, messages=messages, tools=functions)
        tc = response.choices[0].message.tool_calls[0]
        result = self.handle_function_call(tc.function.name, tc.function.arguments)
        messages = messages + [{"role": "tool", "content": result}]
        self.get_completion(model, messages, functions)
