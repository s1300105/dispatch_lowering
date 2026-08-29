"""Micro-benchmark fixtures — one per wall idiom / precision mechanism.

IccTA validated each ICC kind with a dedicated test app (``TestApps`` /
DroidBench ICC suite); this is the same idea for the Python idioms the
lowering pass claims to handle. Each fixture is a tiny source tree plus a
spec and the expected link-level outcome. ``run_bench.py`` materialises them
in a temp dir, runs the pipeline in both emission modes and checks:

  * ``walls``               number of walls detected
  * ``lowered``             links emitted as code
  * ``filtered_registry``   links dropped by registry / BoolOp membership
  * ``filtered_level``      links dropped by the ``match_level`` cap
  * ``unreasonable``        links dropped by argument-compatibility
  * ``phantom``             links whose target could not be imported
  * ``contains`` / ``not_contains``  substrings of the lowered wall file
                            (``not_contains`` also checks the redirect module)
  * ``redirect_contains``   substrings of the generated redirect module
  * ``before_return`` / ``before_wall`` / ``chain_intact`` / ``block_count``
                            structural placement checks on the lowered file
  * ``expect_per_emit``     overrides for one emission mode
  * ``reaches``             (``--pyre`` only) sink callees Pysa must report as
                            reached on cond_B (fully qualified, e.g.
                            ``tools.run_shell``); the same tree WITHOUT lowering is
                            analysed first and must report 0 issues, so a fixture
                            only counts when its wall really blocks Pysa. Raw issue
                            counts are not asserted: the host rule set tags
                            ``subprocess.run`` with two kinds (5001 + 5005), so one
                            flow is two issues

Every fixture declares the same source/sink pair so the Pysa check needs no
per-fixture rules: ``app.llm_decide`` returns ``LLMControlled`` data and
``subprocess.run`` is the ``RemoteCodeExecution`` sink (TaintP2X rule 5001).
"""

MODELS = """\
def app.llm_decide(prompt) -> TaintSource[LLMControlled]: ...
def subprocess.run(args: TaintSink[RemoteCodeExecution], **kwargs): ...
"""

TOOLS_BASIC = '''\
import subprocess


def run_shell(cmd):
    subprocess.run(cmd, shell=True)


def echo(msg):
    return msg
'''

FIXTURES = {
    # (S) REG[k](...) with a trusted static registry -> both members lowered (match level 1)
    "subscript": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nREGISTRY = {"shell": run_shell, "echo": echo}\n',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    REGISTRY[name](args)
''',
        },
        "spec": {"registry_vars": ["REGISTRY"], "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 2, "filtered_registry": 0, "unreasonable": 0,
                   "contains": ["run_shell(args)", "echo(args)", "wall=app.py:"],
                   "reaches": ["tools.run_shell"]},
    },
    # registry narrowing: the wall reads SAFE, so the dangerous tool registered in
    # another registry must NOT be linked (precision), and vice versa
    "registry_narrowing": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nSAFE = {"echo": echo}\nDANGER = {"shell": run_shell}\n',
            "app.py": '''\
from tools import SAFE, DANGER


def llm_decide(prompt):
    return prompt, prompt


def safe_agent(prompt):
    name, args = llm_decide(prompt)
    SAFE[name](args)


def danger_agent(prompt):
    name, args = llm_decide(prompt)
    DANGER[name](args)
''',
        },
        "spec": {"registry_vars": ["SAFE", "DANGER"], "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        "expect": {"walls": 2, "lowered": 2, "filtered_registry": 2, "unreasonable": 0,
                   "reaches": ["tools.run_shell"], "not_reaches": ["tools.echo"]},
    },
    # a registry mutated later is NOT trusted -> no narrowing, recall-first (both linked)
    "registry_untrusted": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nREGISTRY = {"echo": echo}\nREGISTRY["shell"] = run_shell\n',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    REGISTRY[name](args)
''',
        },
        "spec": {"registry_vars": ["REGISTRY"], "tool_decorators": [], "scan_all_callables": True,
                 "detect_subscript": True, "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        # scan_all picks up llm_decide/agent too; only run_shell/echo matter for the check
        "expect": {"walls": 1, "filtered_registry": 0,
                   "contains": ["run_shell(args)", "echo(args)"], "reaches": ["tools.run_shell"]},
    },
    # (G) getattr(obj, name)(...) on decorated class methods
    "getattr": {
        "files": {
            "tools.py": '''\
import subprocess


def tool(fn):
    return fn


class Tools:
    @tool
    def shell(self, cmd):
        subprocess.run(cmd, shell=True)

    @tool
    def echo(self, msg):
        return msg
''',
            "app.py": '''\
from tools import Tools


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    tools = Tools()
    name, args = llm_decide(prompt)
    getattr(tools, name)(args)
''',
        },
        "spec": {"tool_decorators": ["tool"], "detect_subscript": False,
                 "detect_getattr": True, "detect_higher_order": False},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 2, "unreasonable": 0,
                   "contains": ["__ctaudit_obj = Tools.__new__(Tools)", "__ctaudit_obj.shell(args)",
                                "__ctaudit_obj.echo(args)"],
                   "redirect_contains": ["__ctaudit_obj = Tools.__new__(Tools)", "return __ctaudit_obj.shell(args)"],
                   "reaches": ["tools.Tools.shell"]},
    },
    # (H) f = resolve(name); f(...) with a resolver hint
    "higher_order": {
        "files": {
            "tools.py": '''\
import subprocess


def tool(fn):
    return fn


@tool
def run_shell(cmd):
    subprocess.run(cmd, shell=True)


@tool
def echo(msg):
    return msg


def resolve_tool(name):
    return {"shell": run_shell, "echo": echo}[name]
''',
            "app.py": '''\
from tools import resolve_tool


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    fn = resolve_tool(name)
    fn(args)
''',
        },
        "spec": {"tool_decorators": ["tool"], "resolver_hints": ["resolve"],
                 "detect_subscript": False, "detect_getattr": False, "detect_higher_order": True},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 2, "contains": ["run_shell(args)"], "reaches": ["tools.run_shell"]},
    },
    # (B) f = custom or default; f(...) -> narrowed to the named alternatives
    "boolop": {
        "files": {
            "tools.py": '''\
import subprocess


def tool(fn):
    return fn


@tool
def default_handler(cmd):
    subprocess.run(cmd, shell=True)


@tool
def other_tool(msg):
    return msg
''',
            "app.py": '''\
from tools import default_handler, other_tool

PRIMARY = default_handler


def llm_decide(prompt):
    return prompt


def agent(prompt):
    args = llm_decide(prompt)
    fn = PRIMARY or default_handler
    fn(args)
''',
        },
        "spec": {"tool_decorators": ["tool"], "detect_subscript": False,
                 "detect_getattr": False, "detect_higher_order": False, "detect_boolop": True},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 1, "filtered_registry": 1,
                   "contains": ["default_handler(args)"], "not_contains": ["other_tool(args)"],
                   "reaches": ["tools.default_handler"]},
    },
    # a BoolOp alternative that is a PARAMETER is an open set — the caller picks
    # its value — so narrowing must be skipped or the real callee is dropped
    "boolop_open_param": {
        "files": {
            "tools.py": '''\
import subprocess


def tool(fn):
    return fn


@tool
def default_handler(cmd):
    return cmd


@tool
def run_shell(cmd):
    subprocess.run(cmd, shell=True)
''',
            "app.py": '''\
from tools import default_handler, run_shell


def llm_decide(prompt):
    return prompt


def agent(prompt, handler=None):
    args = llm_decide(prompt)
    fn = handler or default_handler
    fn(args)


def main(prompt):
    return agent(prompt, handler=run_shell)
''',
        },
        "spec": {"tool_decorators": ["tool"], "detect_subscript": False,
                 "detect_getattr": False, "detect_higher_order": False, "detect_boolop": True},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 2, "filtered_registry": 0,
                   "contains": ["run_shell(args)", "default_handler(args)"], "reaches": ["tools.run_shell"]},
    },
    # method wall: tool = self.tools[name]; tool.run(x) on class-based tools
    "method_wall": {
        "files": {
            "tools.py": '''\
import subprocess


class BaseTool:
    name = ""

    def run(self, x):
        raise NotImplementedError


class ShellTool(BaseTool):
    name = "shell"

    def run(self, cmd):
        subprocess.run(cmd, shell=True)


class EchoTool(BaseTool):
    name = "echo"

    def run(self, msg):
        return msg
''',
            "app.py": '''\
from tools import ShellTool, EchoTool


def llm_decide(prompt):
    return prompt, prompt


class Agent:
    def __init__(self, tools):
        # registered at runtime from whatever the caller passes: Pysa cannot
        # type the dict's values, so `tool.run` below is a real wall
        self.tools = {}
        for t in tools:
            self.tools[t.name] = t

    def step(self, prompt):
        name, args = llm_decide(prompt)
        tool = self.tools[name]
        observation = tool.run(args)
        return observation


def main(prompt):
    return Agent([ShellTool(), EchoTool()]).step(prompt)
''',
        },
        "spec": {"tool_base_classes": ["BaseTool"], "tool_impl_methods": ["run"],
                 "wall_method_names": ["run"], "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 2, "unreasonable": 0,
                   "contains": ["__ctaudit_obj = ShellTool.__new__(ShellTool)", "__ctaudit_obj.run(args)",
                                "observation = __ctaudit_ret"],
                   "redirect_contains": ["__ctaudit_obj = ShellTool.__new__(ShellTool)",
                                         "return __ctaudit_obj.run(args)"],
                   "reaches": ["tools.ShellTool.run"]},
    },
    # argument compatibility: keyword not accepted / too many positionals -> unreasonable.
    # Undecorated defs, so the recorded signature IS the one the wall would call.
    "unreasonable": {
        "files": {
            "tools.py": '''\
import subprocess


def run_shell(cmd, verbose=False):
    subprocess.run(cmd, shell=True)


def echo(msg):
    return msg


def two_args(a, b):
    return a + b
''',
            "app.py": '''\
from tools import run_shell, echo, two_args

REGISTRY = {"shell": run_shell, "echo": echo, "two": two_args}


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    REGISTRY[name](args, verbose=True)


def agent3(prompt):
    name, args = llm_decide(prompt)
    REGISTRY[name](args, args, args)
''',
        },
        "spec": {"registry_vars": ["REGISTRY"], "narrow": False, "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        # wall 1: run_shell ok, echo (no 'verbose'), two_args (no 'verbose') -> 2 unreasonable
        # wall 2: 3 positionals: run_shell(2) echo(1) two_args(2) -> 3 unreasonable
        "expect": {"walls": 2, "lowered": 1, "unreasonable": 5,
                   "contains": ["run_shell(args, verbose=True)"], "not_contains": ["echo(args"],
                   "reaches": ["tools.run_shell"]},
    },
    # the same filter must NOT fire on a decorated def: the runtime callee is the
    # decorator's return value, so the recorded signature says nothing (LangChain
    # @tool -> StructuredTool). Recall-first: keep the link.
    "decorated_not_filtered": {
        "files": {
            "tools.py": '''\
import subprocess


def tool(fn):
    return fn


@tool
def run_shell(cmd):
    subprocess.run(cmd, shell=True)


@tool
def echo(msg):
    return msg
''',
            "app.py": '''\
from tools import run_shell, echo

REGISTRY = {"shell": run_shell, "echo": echo}


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    REGISTRY[name](args, verbose=True, color="green")
''',
        },
        "spec": {"tool_decorators": ["tool"], "narrow": False, "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        # the wall's keywords are forwarded verbatim (the signature is unknowable,
        # so nothing may be dropped); the block is analysed, never executed
        "expect": {"walls": 1, "lowered": 2, "unreasonable": 0,
                   "contains": ["run_shell(args, verbose=True, color='green')"], "reaches": ["tools.run_shell"]},
    },
    # return form: `return REG[k](x)` -> block must be placed BEFORE the return
    "return_form": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nREGISTRY = {"shell": run_shell, "echo": echo}\n',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    return REGISTRY[name](args)
''',
        },
        "spec": {"registry_vars": ["REGISTRY"], "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 2, "before_return": True, "reaches": ["tools.run_shell"]},
    },
    # multi-line call: block must land after the closing paren, not inside the args
    "multiline_call": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nREGISTRY = {"shell": run_shell, "echo": echo}\n',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    result = REGISTRY[name](
        args,
    )
    return result
''',
        },
        "spec": {"registry_vars": ["REGISTRY"], "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 2, "contains": ["result = __ctaudit_ret"], "reaches": ["tools.run_shell"]},
    },
    # async wall + coroutine target -> await emitted, async redirector generated
    "async_wall": {
        "files": {
            "tools.py": '''\
import subprocess


async def run_shell(cmd):
    subprocess.run(cmd, shell=True)


async def echo(msg):
    return msg


REGISTRY = {"shell": run_shell, "echo": echo}
''',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


async def agent(prompt):
    name, args = llm_decide(prompt)
    result = await REGISTRY[name](args)
    return result
''',
        },
        "spec": {"registry_vars": ["REGISTRY"], "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 2,
                   "contains": ["await run_shell(args)", "result = __ctaudit_ret"],
                   "redirect_contains": ["async def redirector_0", "return await run_shell("],
                   "reaches": ["tools.run_shell"]},
    },
    # narrowing must use the wall's OWN scope: two functions reusing a local name
    # (`fn = SAFE[k]` / `fn = DANGER[k]`) must not share a binding
    "narrowing_scoped_locals": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nSAFE = {"echo": echo}\nDANGER = {"shell": run_shell}\n',
            "app.py": '''\
from tools import SAFE, DANGER


def llm_decide(prompt):
    return prompt, prompt


def safe_agent(prompt):
    name, args = llm_decide(prompt)
    fn = SAFE[name]
    fn(args)


def danger_agent(prompt):
    name, args = llm_decide(prompt)
    fn = DANGER[name]
    fn(args)
''',
        },
        "spec": {"registry_vars": ["SAFE", "DANGER"], "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": True},
        "walls": ["app.py"],
        # one wall per function; each must narrow to the registry ITS OWN local reads
        "expect": {"walls": 2, "lowered": 2, "filtered_registry": 2,
                   "contains": ["echo(args)", "run_shell(args)"], "reaches": ["tools.run_shell"]},
    },
    # a registry built with `**other` or mutated with `|=` is not trustworthy:
    # narrowing must be skipped entirely (recall-first), not applied partially
    "registry_splat": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nPLUGINS = {"shell": run_shell}\nREGISTRY = {"echo": echo, **PLUGINS}\n',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    REGISTRY[name](args)
''',
        },
        "spec": {"registry_vars": ["REGISTRY"], "scan_all_callables": True,
                 "detect_subscript": True, "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        "expect": {"walls": 1, "filtered_registry": 0,
                   "contains": ["run_shell(args)", "echo(args)"], "reaches": ["tools.run_shell"]},
    },
    # `f = get() or default`: one alternative is not statically known, so the
    # candidate set must stay open — narrowing to `default` would drop the truth
    "boolop_open_member": {
        "files": {
            "tools.py": '''\
import subprocess


def tool(fn):
    return fn


@tool
def default_handler(cmd):
    return cmd


@tool
def run_shell(cmd):
    subprocess.run(cmd, shell=True)


def get_custom():
    return run_shell
''',
            "app.py": '''\
from tools import default_handler, get_custom


def llm_decide(prompt):
    return prompt


def agent(prompt):
    args = llm_decide(prompt)
    fn = get_custom() or default_handler
    fn(args)
''',
        },
        "spec": {"tool_decorators": ["tool"], "detect_subscript": False,
                 "detect_getattr": False, "detect_higher_order": False, "detect_boolop": True},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 2, "filtered_registry": 0,
                   "contains": ["run_shell(args)"], "reaches": ["tools.run_shell"]},
    },
    # match_level caps how speculative a LINK may be; narrowing promotes a
    # registry member to level 1, so `match_level: 1` must keep exactly those
    "match_level_cap": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nREGISTRY = {"shell": run_shell, "echo": echo}\n',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    REGISTRY[name](args)
''',
        },
        "spec": {"registry_vars": ["REGISTRY"], "scan_all_callables": True, "match_level": 1,
                 "detect_subscript": True, "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        # scan_all also sees llm_decide/agent: narrowing drops them as non-members,
        # and the two registry members are promoted to level 1 so they survive the cap
        "expect": {"walls": 1, "lowered": 2, "filtered_registry": 2, "filtered_level": 0,
                   "contains": ["run_shell(args)", "echo(args)"], "reaches": ["tools.run_shell"]},
    },
    # multi-line call whose closing paren sits on the argument line: the block's
    # indentation must come from the statement's FIRST line
    "multiline_call_paren": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nREGISTRY = {"shell": run_shell, "echo": echo}\n',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    result = REGISTRY[name](
        args)
    return result
''',
        },
        "spec": {"registry_vars": ["REGISTRY"], "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 2, "contains": ["result = __ctaudit_ret"], "reaches": ["tools.run_shell"]},
    },
    # a wall in an `elif` header: the block must go before the whole if-chain,
    # or the chain is re-parented to the inserted `if`
    "elif_header": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nREGISTRY = {"shell": run_shell, "echo": echo}\n',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt, flag):
    name, args = llm_decide(prompt)
    if flag:
        return 0
    elif REGISTRY[name](args):
        return 1
    else:
        return 2
''',
        },
        "spec": {"registry_vars": ["REGISTRY"], "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 2, "chain_intact": True, "reaches": ["tools.run_shell"]},
    },
    # an explicit candidate written without `params` means "signature unknown",
    # not "takes no arguments"
    "explicit_candidates_minimal": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nREGISTRY = {"shell": run_shell}\n',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    REGISTRY[name](args)
''',
        },
        "spec": {"detect_subscript": True, "detect_getattr": False, "detect_higher_order": False,
                 "narrow": False,
                 "candidates": [{"cls": None, "name": "run_shell", "module": "tools"}]},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 1, "unreasonable": 0,
                   "contains": ["run_shell(args)"], "reaches": ["tools.run_shell"]},
    },
    # running the same spec twice must not re-detect and re-lower generated code
    "stages_idempotent": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nREGISTRY = {"shell": run_shell, "echo": echo}\n',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    result = REGISTRY[name](args)
    return result
''',
        },
        "spec": {"stages": [
            {"registry_vars": ["REGISTRY"], "detect_subscript": True,
             "detect_getattr": False, "detect_higher_order": True},
            {"registry_vars": ["REGISTRY"], "detect_subscript": True,
             "detect_getattr": False, "detect_higher_order": True},
        ]},
        "walls": ["app.py"],
        # stage 2 must find the same single wall again, not the generated calls
        "expect": {"walls": 2, "lowered": 4, "block_count": 2, "reaches": ["tools.run_shell"]},
    },
    # `insert_before` (what the Semantic Kernel spec relies on): the block must
    # precede the wall statement, and the writeback must still be visible
    "insert_before_assign": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nREGISTRY = {"shell": run_shell, "echo": echo}\n',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    result = REGISTRY[name](args)
    return result
''',
        },
        "spec": {"registry_vars": ["REGISTRY"], "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": False, "insert_before": True},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 2, "before_wall": "REGISTRY[name](args)",
                   "contains": ["result = __ctaudit_ret"], "reaches": ["tools.run_shell"]},
    },
    # the wall is a call to a callable *parameter* (`wall_param_names`) — the
    # shape the MCP server specs use — and to a callable attribute
    # (`wall_attr_names`), with the target imported into the block
    "param_and_attr_walls": {
        "files": {
            "tools.py": TOOLS_BASIC,
            "app.py": '''\
import tools


def llm_decide(prompt):
    return prompt


class Runner:
    def __init__(self, fn):
        self.fn = fn


def dispatch(fn, prompt):
    args = llm_decide(prompt)
    fn(args)


def dispatch_attr(runner, prompt):
    args = llm_decide(prompt)
    runner.fn(args)
''',
        },
        "spec": {"scan_all_callables": False, "detect_subscript": False, "detect_getattr": False,
                 "detect_higher_order": False, "wall_param_names": ["fn"], "wall_attr_names": ["fn"],
                 "candidates": [{"cls": None, "name": "run_shell", "params": ["cmd"], "module": "tools"}]},
        "walls": ["app.py"],
        "expect": {"walls": 2, "lowered": 2,
                   "contains": ["from tools import run_shell", "run_shell(args)"], "reaches": ["tools.run_shell"]},
    },
    # a redirector target with no module cannot be imported from the synthetic
    # module: the link must be recorded as `phantom`, not silently dropped
    "phantom_target": {
        "files": {
            "tools.py": TOOLS_BASIC + '\nREGISTRY = {"shell": run_shell}\n',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    REGISTRY[name](args)
''',
        },
        "spec": {"detect_subscript": True, "detect_getattr": False, "detect_higher_order": False,
                 "narrow": False,
                 "candidates": [{"cls": None, "name": "run_shell", "params": ["cmd"]}]},
        "walls": ["app.py"],
        # inline can still name it (the wall file imports nothing, but the call is
        # emitted); redirector cannot import it -> phantom
        "expect_per_emit": {
            "inline": {"walls": 1, "lowered": 1, "phantom": 0},
            "redirector": {"walls": 1, "lowered": 0, "phantom": 1},
        },
        "expect": {"walls": 1},
    },
    # splat forwarding into keyword-only parameters and a `**kwargs` target
    "kwargs_forwarding": {
        "files": {
            "tools.py": '''\
import subprocess


def tool(fn):
    return fn


def run_shell(cmd, *, mode="safe", **extra):
    subprocess.run(cmd, shell=True)


REGISTRY = {"shell": run_shell}
''',
            "app.py": '''\
from tools import REGISTRY


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, payload = llm_decide(prompt)
    REGISTRY[name](**payload)
''',
        },
        "spec": {"registry_vars": ["REGISTRY"], "detect_subscript": True,
                 "detect_getattr": False, "detect_higher_order": False},
        "walls": ["app.py"],
        "expect": {"walls": 1, "lowered": 1,
                   "contains": ["run_shell(cmd=payload, mode=payload, **payload)"],
                   "redirect_contains": ["**"], "reaches": ["tools.run_shell"]},
    },
    # hand-written links (FileLinksProvider): no candidate recovery at all
    "manual_links": {
        "files": {
            "tools.py": TOOLS_BASIC,
            "app.py": '''\
import tools


def llm_decide(prompt):
    return prompt, prompt


def agent(prompt):
    name, args = llm_decide(prompt)
    getattr(tools, name)(args)
''',
            "links.manual.json": '''\
{
  "links": [
    {"file": "app.py", "line": 10,
     "target": {"cls": null, "name": "run_shell", "params": ["cmd"], "module": "tools"}}
  ]
}
''',
        },
        "spec": {"detect_subscript": False, "detect_getattr": True, "detect_higher_order": False,
                 "candidate_import_module": "tools"},
        "walls": ["app.py"],
        "links_in": "links.manual.json",
        "expect": {"walls": 1, "lowered": 1, "contains": ["run_shell(args)"],
                   "not_contains": ["echo(args)"], "reaches": ["tools.run_shell"]},
    },
}
