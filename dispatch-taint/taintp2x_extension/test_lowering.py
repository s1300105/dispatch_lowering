"""Verify the generalized dispatch_lowering against the original.

(1) Backward-compat: on an AutoGPT-shaped wall + @command candidates, the NEW
    module with the legacy spec must produce byte-identical collect_commands and
    lower_wall_file output as the ORIGINAL module.
(2) Generalization: each new idiom (subscript / getattr / higher-order) is
    detected and lowered in general mode.
"""
import importlib.util
import os
import sys
import tempfile

REPO = "/home/claude/ctaudit_extract/cross_tool_audit2/cross_tool_audit"
ORIG = os.path.join(REPO, "taintp2x_extension", "dispatch_lowering.py")
NEW = "/home/claude/work/dispatch_lowering.py"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod          # needed for dataclass type resolution under importlib
    spec.loader.exec_module(mod)
    return mod


orig = load(ORIG, "orig_dl")
new = load(NEW, "new_dl")

# --- AutoGPT-shaped fixtures ------------------------------------------------- #
CMD_SRC = '''\
class CodeExecutorComponent:
    @command
    def execute_python_code(self, code):
        subprocess.run(code)
    @command
    def execute_python_file(self, filename, args):
        subprocess.run([filename, args])
    @command
    def execute_shell(self, command_line):
        subprocess.run(command_line)
    @command
    def execute_shell_popen(self, command_line):
        subprocess.Popen(command_line)
'''

AGENT_SRC = '''\
class Agent:
    def _execute_tool(self, tool_call):
        command = self._get_command(tool_call.name)
        result = command(**tool_call.arguments)
        return result
'''

LEGACY_SPEC = {"tool_decorator": "command", "dispatch_resolver_hint": "command"}

print("=" * 70)
print("TEST 1 — backward compatibility (legacy AutoGPT spec)")
print("=" * 70)

with tempfile.TemporaryDirectory() as d:
    cmd_dir = os.path.join(d, "code_executor")
    os.makedirs(cmd_dir)
    with open(os.path.join(cmd_dir, "code_executor.py"), "w") as f:
        f.write(CMD_SRC)

    cmds_orig = orig.collect_commands(cmd_dir, LEGACY_SPEC)
    cmds_new = new.collect_commands(cmd_dir, LEGACY_SPEC)
    print(f"collect_commands  original={len(cmds_orig)}  new={len(cmds_new)}  "
          f"identical={cmds_orig == cmds_new}")

    out_orig = orig.lower_wall_file(AGENT_SRC, cmds_orig, LEGACY_SPEC)
    out_new = new.lower_wall_file(AGENT_SRC, cmds_new, LEGACY_SPEC)
    print(f"lower_wall_file   byte-identical={out_orig == out_new}")
    if out_orig != out_new:
        import difflib
        for line in difflib.unified_diff(out_orig.splitlines(), out_new.splitlines(),
                                         "original", "new", lineterm=""):
            print(line)
    print("\n--- lowered agent.py (new, legacy spec) ---")
    print(out_new)

assert cmds_orig == cmds_new, "collect_commands diverged"
assert out_orig == out_new, "lower_wall_file diverged"

print("=" * 70)
print("TEST 2 — generalization (general spec, new module)")
print("=" * 70)

GENERAL_FIXTURE = '''\
HANDLERS = {}

def route_subscript_direct(event, payload):
    HANDLERS[event.type](payload)            # (S) direct subscript dispatch

def route_subscript_indirect(event, payload):
    fn = HANDLERS[event.type]                # (S) indirected
    fn(payload)

def route_getattr(obj, name, data):
    getattr(obj, name)(data)                 # (G) getattr dispatch

def route_higher_order(name, data):
    f = resolve_plugin(name)                 # (H) callee from a resolver call
    f(data)

def not_a_wall(x):
    return helper(x)                         # ordinary direct call — must NOT fire
'''

GEN_CANDIDATES = [
    (None, "plugin_a", ["payload"]),
    (None, "plugin_b", ["payload"]),
]

gen_spec = new.LoweringSpec(
    tool_decorators=(),
    detect_subscript=True,
    detect_getattr=True,
    detect_higher_order=True,
    resolver_hints=(),       # maximally over-approximate (H)
)

walls = new.describe_walls(GENERAL_FIXTURE, gen_spec)
print("detected walls (lineno, idiom, callee):")
for w in walls:
    print(f"  L{w[0]:<3} {w[1]:<22} {w[2]}")

# 'not_a_wall' (helper(x), a direct Name call to an unbound name) must not appear
flagged_lines = {w[0] for w in walls}
not_a_wall_line = GENERAL_FIXTURE.splitlines().index("    return helper(x)                         # ordinary direct call — must NOT fire") + 1
print(f"\nordinary call at L{not_a_wall_line} flagged? "
      f"{not_a_wall_line in flagged_lines}  (expected False)")
assert not_a_wall_line not in flagged_lines, "false wall on ordinary direct call"
assert len(walls) == 4, f"expected 4 walls, got {len(walls)}"

print("\n--- lowered general fixture (new) ---")
print(new.lower_wall_file(GENERAL_FIXTURE, GEN_CANDIDATES, gen_spec))

print("=" * 70)
print("ALL CHECKS PASSED")
print("=" * 70)
