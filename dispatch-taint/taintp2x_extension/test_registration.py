"""Self-contained test for dispatch_lowering.py (general tool-registration recovery).

Run from any directory that can import dispatch_lowering.py (e.g. drop this file
next to dispatch_lowering.py and run `python3 test_registration.py`).
Fixtures are generated into a temp dir at runtime — no external files needed.
"""
import ast, json, os, sys, tempfile, shutil
import dispatch_lowering as d

# --- fixtures written to a temp dir ---------------------------------------- #
FIX = {
    "autogpt/code_executor.py": '''\
class CodeExecutorComponent:
    @command(names=["execute_python_code"])
    def execute_python_code(self, code: str) -> str: ...
    @command(names=["execute_python_file"])
    def execute_python_file(self, filename: str, args=None) -> str: ...
    @command(names=["execute_shell"])
    def execute_shell(self, command_line: str) -> list: ...
    @command(names=["execute_shell_popen"])
    def execute_shell_popen(self, command_line: str) -> str: ...
''',
    "autogpt/agent.py": '''\
class Agent:
    def _execute_tool(self, tool_call):
        name = tool_call.name
        args = tool_call.arguments
        command = self._get_command(name)
        return command(**args)
''',
    "general/tools.py": '''\
@tool
def deco_a(x): ...
@mcp.tool()
def deco_b(y): ...
def reg_call_fn(a): ...
def list_fn1(b): ...
def list_fn2(c): ...
def dict_fn(e): ...
def wrapped_via_register(f): ...
def never_registered(g): ...
''',
    "general/wiring.py": '''\
from .tools import (reg_call_fn, list_fn1, list_fn2, dict_fn, wrapped_via_register)
runtime.register(reg_call_fn)
mcp.add_tool(func=reg_call_fn)
mcp.add_tool(StructuredTool.from_function(wrapped_via_register))
agent = Agent(tools=[list_fn1, Tool(func=list_fn2)])
TOOLS = [list_fn1]
REGISTRY = {"k1": dict_fn}
runtime.register(external_only_name)   # unresolved on purpose -> gap in R
''',
}

root = tempfile.mkdtemp(prefix="dl_test_")
for rel, txt in FIX.items():
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(txt)
AUTOGPT, GENERAL = os.path.join(root, "autogpt"), os.path.join(root, "general")

ok = True
def check(label, cond):
    global ok
    print(("PASS" if cond else "FAIL"), "-", label)
    ok = ok and cond

try:
    # (A) backward-compat: AutoGPT legacy spec (byte-identical to original)
    legacy = {"tool_decorator": "command", "dispatch_resolver_hint": "command"}
    cands = d.collect_commands(AUTOGPT, legacy)
    names = sorted(n for _c, n, _p in cands)
    check("legacy: 4 @command methods recovered", len(cands) == 4)
    check("legacy: exact method names", names == [
        "execute_python_code", "execute_python_file", "execute_shell", "execute_shell_popen"])
    check("legacy: all are class methods", all(c is not None for c, _n, _p in cands))
    lowered = d.lower_wall_file(open(os.path.join(AUTOGPT, "agent.py")).read(), cands, legacy)
    check("legacy: if-False block inserted (4 targets)",
          "if False:  # [ctaudit] resolved dynamic dispatch -> 4 targets" in lowered)
    check("legacy: tainted **args threaded into targets",
          lowered.count("(code=args)") == 1 and "command_line=args" in lowered)
    check("legacy: targets qualified Class.method", "CodeExecutorComponent.execute_shell(" in lowered)
    check("legacy: lowered source parses", ast.parse(lowered) is not None)

    # (B) general registration recovery
    gen = {
        "tool_decorators": ["tool"],
        "register_methods": ["register", "add_tool"],
        "tool_list_names": ["tools", "TOOLS"],
        "tool_wrappers": ["Tool", "StructuredTool", "FunctionTool"],
        "registry_vars": ["REGISTRY"],
    }
    gnames = sorted(n for _c, n, _p in d.collect_candidates(GENERAL, gen))
    expected = sorted(["deco_a", "deco_b", "reg_call_fn", "wrapped_via_register",
                       "list_fn1", "list_fn2", "dict_fn"])
    print("  collected:", gnames)
    check("general: exactly the registered tools recovered", gnames == expected)
    check("general: never_registered NOT collected", "never_registered" not in gnames)

    desc = d.describe_candidates(GENERAL, gen)
    print("  describe:", json.dumps(desc))
    check("general: unresolved ref reported (gap in R)", "external_only_name" in desc["unresolved_refs"])
    check("general: no spurious ambiguity", desc["ambiguous_refs"] == [])

    # (C) AutoGPT under general spec still gives the 4 (decorator path)
    ga = sorted(n for _c, n, _p in d.collect_candidates(AUTOGPT, {"tool_decorators": ["command"]}))
    check("general-mode AutoGPT: 4 @command methods", ga == [
        "execute_python_code", "execute_python_file", "execute_shell", "execute_shell_popen"])
finally:
    shutil.rmtree(root, ignore_errors=True)

print("\nALL PASS" if ok else "\nSOME FAILED")
sys.exit(0 if ok else 1)