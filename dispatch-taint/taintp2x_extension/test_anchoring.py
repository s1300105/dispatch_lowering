"""Tests for anchoring.py — synthetic trees, no pyre.

    python3 test_anchoring.py

Anchors are keyed ``module.NAME`` / ``module.Cls.attr`` (review C6); the
negative tests at the end each pin one closed-anchor defect of the review:
same attribute name in unrelated classes, same-named registry in two modules,
setter re-binding / class-body declaration, ``+=`` / ``|=``, alias mutation,
relative import, ``global`` + item assignment, ``.pop`` reads. The C6-R*
tests pin the verifier's remaining defects: a function-local name shadowing
a module registry, a re-exported mutation site seen before the defining
module, a nested class named like a top-level one, and rebinding through
``setattr`` / ``__dict__`` / the class object. ``test_parse_once`` pins the
review minor "find_reads re-parse / describe_call cost": ``anchoring()``
parses each module once, ``find_reads`` describes no call again, and
``engine_walls._binding_of`` walks a scope body once per file.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import anchoring as A      # noqa: E402
import engine_walls as EW  # noqa: E402

FAILS: list = []
N = 0


def check(label, cond, detail=""):
    global N
    N += 1
    print(("PASS " if cond else "FAIL ") + label + ("" if cond or not detail else f": {detail}"))
    if not cond:
        FAILS.append(label)


TREE = {
    "tools.py": '''
import subprocess


def run_shell(cmd):
    subprocess.run(cmd, shell=True)


def echo(msg):
    return msg


class ShellTool:
    name = "shell"

    def run(self, x):
        subprocess.run(x, shell=True)


class EchoTool:
    name = "echo"

    def run(self, x):
        return x


REGISTRY = {"shell": run_shell, "echo": echo}
PROVIDERS = {"openai": "gpt-4", "anthropic": "claude"}     # strings: not an anchor
OPEN = {"shell": run_shell, **REGISTRY}
MUTATED = {"shell": run_shell}
MUTATED["x"] = echo
''',
    "app.py": '''
from tools import REGISTRY, OPEN, MUTATED, ShellTool, EchoTool, run_shell


def llm(prompt):
    return prompt, prompt


def by_subscript(prompt):
    name, args = llm(prompt)
    REGISTRY[name](args)


def by_get(prompt):
    name, args = llm(prompt)
    fn = REGISTRY.get(name)
    fn(args)


def by_open(prompt):
    name, args = llm(prompt)
    OPEN[name](args)


class Agent:
    def __init__(self):
        self.tools = {"shell": ShellTool(), "echo": EchoTool()}
        self.registry = {}
        self.registry["shell"] = run_shell

    def step(self, prompt):
        name, args = llm(prompt)
        tool = self.tools[name]
        return tool.run(args)

    def all(self, args):
        for t in self.tools.values():
            t.run(args)

    def reg(self, prompt):
        name, args = llm(prompt)
        self.registry[name](args)
''',
    "vanna_like.py": '''
class VannaBase:
    def run_sql(self, sql):
        raise Exception("not connected")

    def connect_to_sqlite(self, url):
        def run_sql_sqlite(sql):
            return url + sql
        self.run_sql = run_sql_sqlite

    def connect_to_pg(self, url):
        def run_sql_postgres(sql):
            return sql
        self.run_sql = run_sql_postgres

    def ask(self, question):
        sql = question
        return self.run_sql(sql)
''',
    "loop_like.py": '''
from tools import run_shell, echo

HANDLERS = [run_shell, echo]


def fan(args):
    for h in HANDLERS:
        h(args)
''',
    "mcp_like.py": '''
class Server:
    def __init__(self):
        self.tools = []

    def add_tool(self, fn):
        self.tools.append(fn)

    def call(self, name, args):
        for t in self.tools:
            t(args)


def hello(x):
    return x


server = Server()
server.add_tool(hello)
server.add_tool(lambda x: x)
''',
    # a function-local dict is not a registry (review: test_anchoring:198 pinned nothing)
    "local_dict.py": '''
from tools import run_shell, echo


def build():
    record = {"shell": run_shell}
    record["x"] = echo
    return record
''',
    # C6-1: same attribute name in unrelated classes / subclasses
    "inherit.py": '''
from tools import run_shell, echo


class Base:
    def __init__(self):
        self.handler = run_shell

    def go(self, x):
        return self.handler(x)


class Child(Base):
    def run(self, x):
        return self.handler(x)


class Stranger:
    def __init__(self, handler):
        self.handler = handler

    def run(self, x):
        return self.handler(x)


class Unrelated:
    def run(self, x):
        return self.handler(x)


class Base2:
    def __init__(self):
        self.cb = echo

    def go(self, x):
        return self.cb(x)


class Rebinder(Base2):
    def __init__(self, cb):
        self.cb = cb

    def run(self, x):
        return self.cb(x)
''',
    # C6-2: same-named registry in two modules / same-named class in two modules
    "loaders_a.py": '''
from tools import run_shell

LOADERS = {"shell": run_shell}


def load(kind, cfg):
    return LOADERS[kind](cfg)
''',
    "loaders_b.py": '''
from tools import run_shell, echo

LOADERS = {"shell": run_shell, "echo": echo}


def load(kind, cfg):
    return LOADERS[kind](cfg)
''',
    "agent2.py": '''
from tools import EchoTool


class Agent:
    def __init__(self):
        self.tools = {"echo": EchoTool()}

    def step(self, name, args):
        return self.tools[name].run(args)
''',
    # C6-3: setter re-binding and class-body declaration
    "setter.py": '''
from tools import echo


class Notifier:
    def __init__(self):
        self.callback = echo

    def set_callback(self, cb):
        self.callback = cb

    def fire(self, x):
        return self.callback(x)


class Model:
    formatter = None

    def __init__(self):
        self.formatter = echo

    def render(self, x):
        return self.formatter(x)
''',
    # C6-4: augmented assignment
    "aug.py": '''
from tools import run_shell, echo

HANDLERS2 = [run_shell]
HANDLERS2 += [echo]
MERGED = {"shell": run_shell}
MERGED |= {"echo": echo}


class Box:
    def __init__(self):
        self.tools = {"shell": run_shell}

    def extend(self):
        self.tools |= {"echo": echo}

    def run(self, name, x):
        return self.tools[name](x)
''',
    # C6-5: aliases — module-level alias, ``import X as Y`` and ``from X import N as M``
    "alias.py": '''
from tools import run_shell, echo

TABLE = {"shell": run_shell}
ALIAS = TABLE
ALIAS["echo"] = echo
TABLE2 = {"shell": run_shell}
TABLE3 = {"shell": run_shell}
TABLE4 = {"shell": run_shell}


def call(name, x):
    return TABLE[name](x)


def call2(name, x):
    return TABLE2[name](x)
''',
    "alias_use.py": '''
import alias as al
from alias import TABLE3 as T3
from tools import echo

al.TABLE2["echo"] = echo
T3["echo"] = echo
''',
    # C6-6: relative imports
    "pkg/__init__.py": "",
    "pkg/impl.py": '''
def a(x):
    return x
''',
    "pkg/reg.py": '''
from .impl import a
from ..outside import z

REG = {"a": a, "z": z}


def run(name, x):
    return REG[name](x)
''',
    # C6-4b: ``global`` + assignment / function-scope item assignment (@register idiom)
    "decor.py": '''
from tools import run_shell, echo

REGISTRY3 = {"base": run_shell}
TABLE5 = {"base": run_shell}


def register(fn):
    REGISTRY3[fn.__name__] = fn
    return fn


@register
def d(x):
    return x


def reset():
    global TABLE5
    TABLE5 = {"echo": echo}


def dispatch(name, x):
    return REGISTRY3[name](x)
''',
    # minor: ``fn = REG.pop(k); fn(x)`` is a read (and a mutation)
    "popread.py": '''
from tools import run_shell, echo

POOL = {"shell": run_shell, "echo": echo}


def take(name, x):
    fn = POOL.pop(name)
    return fn(x)
''',
    # C6 repair (1): a function-local / parameter / closure binding shadows the module registry
    "shadow.py": '''
from tools import run_shell, echo

SHADOWED = {"shell": run_shell}


def local_shadow(k, x):
    SHADOWED = {"echo": echo}
    return SHADOWED[k](x)


def param_shadow(SHADOWED, k, x):
    return SHADOWED[k](x)


def closure_shadow(k, x):
    SHADOWED = {"echo": echo}

    def inner():
        return SHADOWED[k](x)
    return inner()


def get_shadow(k, x):
    SHADOWED = {"echo": echo}
    fn = SHADOWED.get(k)
    return fn(x)


def via_global(k, x):
    global SHADOWED
    return SHADOWED[k](x)


def plain(k, x):
    return SHADOWED[k](x)
''',
    # C6 repair (2): a mutation through a package re-export, in a file walked BEFORE the defining module
    "reexp/__init__.py": "from .core import REG as REGX\n",
    "reexp/adder.py": '''
from reexp import REGX
from tools import echo


def add():
    REGX["echo"] = echo
''',
    "reexp/core.py": '''
from tools import run_shell

REG = {"shell": run_shell}


def run(k, x):
    return REG[k](x)
''',
    # C6 repair (3): a nested class with a top-level class's name
    "nested.py": '''
from tools import run_shell, echo


class Outer:
    class Inner:
        def __init__(self):
            self.h = run_shell

        def run(self, x):
            return self.h(x)


class Inner:
    def __init__(self):
        self.h = echo

    def run(self, x):
        return self.h(x)
''',
    # C6 repair (4): rebinding through setattr / __dict__ / the class object
    "setattr_like.py": '''
from tools import run_shell, echo


class SetAttr:
    def __init__(self):
        self.cb = run_shell

    def set(self, fn):
        setattr(self, "cb", fn)

    def run(self, x):
        return self.cb(x)


class DictAttr:
    def __init__(self):
        self.cb = run_shell

    def set(self, fn):
        self.__dict__["cb"] = fn

    def run(self, x):
        return self.cb(x)


class ObjSetAttr:
    def __init__(self):
        self.cb = run_shell

    def set(self, fn):
        object.__setattr__(self, "cb", fn)

    def run(self, x):
        return self.cb(x)


class DynSetAttr:
    def __init__(self, **kw):
        self.cb = run_shell
        for k, v in kw.items():
            setattr(self, k, v)

    def run(self, x):
        return self.cb(x)


class SelfSetAttr:
    def __init__(self):
        self.cb = run_shell

    def set(self, fn):
        self.__setattr__("cb", fn)

    def run(self, x):
        return self.cb(x)


class SetAttrDef:
    def __init__(self):
        self.cb = run_shell

    def set(self):
        setattr(self, "cb", echo)

    def run(self, x):
        return self.cb(x)


class ClassRebound:
    def __init__(self):
        self.cb = run_shell

    def run(self, x):
        return self.cb(x)


def pick():
    return echo


ClassRebound.cb = pick()


class DynBase:
    def __init__(self):
        self.cb = run_shell

    def run(self, x):
        return self.cb(x)


class DynSub(DynBase):
    def __init__(self, **kw):
        super().__init__()
        for k, v in kw.items():
            setattr(self, k, v)

    def run2(self, x):
        return self.cb(x)
''',
}


def js_reads(res):
    return [a["reads"] for a in res.to_dict()["anchors"]]


def materialise() -> str:
    d = tempfile.mkdtemp(prefix="anch_")
    for rel, txt in TREE.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(txt)
    return d


def test_parse_once(d: str) -> None:
    """review minor (anchoring: find_reads re-parse / describe_call cost).
    (1) ``find_anchors`` parses every module exactly once and describes its
    read sites while it holds the tree; ``find_reads`` with that index opens,
    parses and describes nothing — it only joins the sites to the anchors.
    (2) standalone ``find_reads`` (no index) parses each file once, not twice.
    (3) ``engine_walls._binding_of`` is memoised per (tree, scope): the eight
    Name calls of a file walk the def body and the module body once each,
    and the per-call position still selects the latest binding before the
    call."""
    import ast
    import dispatch_lowering as dl
    n_files = sum(1 for _ in A._iter_files(d))
    counts = {"parse": 0, "describe": 0, "walk": 0}
    orig_parse, orig_describe, orig_walk = ast.parse, EW.describe_call, dl._own_stmt_walk

    def parse(*a, **k):
        if k.get("mode") != "eval":            # expression parses (constant keys) are not file parses
            counts["parse"] += 1
        return orig_parse(*a, **k)

    def describe(*a, **k):
        counts["describe"] += 1
        return orig_describe(*a, **k)

    def walk(*a, **k):
        counts["walk"] += 1
        return orig_walk(*a, **k)

    ast.parse, EW.describe_call = parse, describe
    try:
        index = A._TreeIndex(d)
        anchors = A.find_anchors(d, index=index)
        after_anchors = dict(counts)
        A.find_reads(d, [a for a in anchors if not a.rejected], index=index)
        n_reads = sum(len(a.reads) for a in anchors)
        check("parse-once: find_anchors parses each module once and describes its read sites there",
              n_files > 0 and after_anchors["parse"] == n_files and after_anchors["describe"] > 0
              and all(s.read_sites is not None and s.tree is None for s in index.scans.values()),
              str((after_anchors, n_files)))
        check("parse-once: find_reads with the index parses no file and describes no call again (reads still found)",
              counts["parse"] == after_anchors["parse"] and counts["describe"] == after_anchors["describe"] and n_reads >= 6,
              str((counts, after_anchors, n_reads)))
        anchors2 = A.find_anchors(d)
        counts.update(parse=0, describe=0)
        A.find_reads(d, [a for a in anchors2 if not a.rejected])
        check("parse-once: standalone find_reads parses each file once (not once for the index and once for the calls)",
              counts["parse"] == n_files and sum(len(a.reads) for a in anchors2) == n_reads,
              str((counts, n_files, sum(len(a.reads) for a in anchors2), n_reads)))
        # (3) _binding_of memo: one scope walk per (tree, scope), position still per call
        src = """
from tools import REGISTRY, resolve
PRIMARY = resolve("p")

def m(name, args):
    f = REGISTRY[name]
    f(args)                # 7  subscript
    g = REGISTRY.get(name)
    g(args)                # 9  higher_order
    PRIMARY(args)          # 10 higher_order through the module binding
    resolve(args)          # 11 name_call (import)
    h = resolve(name)
    h(args)                # 13 higher_order: the binding before this call
    h = REGISTRY[name]
    h(args)                # 15 subscript: the later binding of the same name
"""
        fx = EW._FileIndex("<mem>", source=src)
        dl._own_stmt_walk = walk
        counts["walk"] = 0
        got = {}
        for (line, _c), calls in sorted(fx.calls.items()):
            for c in calls:
                if isinstance(c.func, ast.Name):
                    got[line] = EW.describe_call(c, fx)
        check("binding memo: the eight Name calls of the file walk the def body once and the module body once (2 walks, not 10)",
              counts["walk"] == 2 and sorted(got) == [3, 7, 9, 10, 11, 12, 13, 15], str((counts["walk"], sorted(got))))
        check("binding memo: results unchanged — the per-call position still selects the latest binding before the call",
              [(got[n]["idiom"], got[n]["receiver_binding"]) for n in (7, 9, 10, 11, 13, 15)]
              == [("subscript", "subscript"), ("higher_order", "resolver_call"), ("higher_order", "resolver_call"),
                  ("name_call", "import"), ("higher_order", "resolver_call"), ("subscript", "subscript")],
              str({n: (got[n]["idiom"], got[n]["receiver_binding"]) for n in sorted(got)}))
        sb = EW._scope_bindings(None, fx.tree)
        check("binding memo: the scope index is cached on the tree and reused",
              sb is EW._scope_bindings(None, fx.tree) and getattr(fx.tree, "_ctaudit_bindings", None) is not None
              and len(fx.tree._ctaudit_bindings) == 2, str(getattr(fx.tree, "_ctaudit_bindings", None)))
    finally:
        ast.parse, EW.describe_call, dl._own_stmt_walk = orig_parse, orig_describe, orig_walk


def main() -> int:
    d = materialise()
    try:
        res = A.anchoring(d)
        by = {a.name: a for a in res.anchors}

        def shorts(s):
            # anchors displayed as ``s`` (old code: name == short)
            return [a for a in res.anchors if getattr(a, "short", a.name) == s]

        def reads(name):
            return {(r.file, r.line): r for r in by[name].reads}

        def reads_of(short):
            return [r for a in shorts(short) for r in a.reads]

        check("anchor: tools.REGISTRY found, closed", "tools.REGISTRY" in by and by["tools.REGISTRY"].closed, str(by.get("tools.REGISTRY")))
        check("anchor: REGISTRY members are defs",
              sorted(m.name for m in by["tools.REGISTRY"].members) == ["echo", "run_shell"]
              and all(m.kind == "def" and m.candidate for m in by["tools.REGISTRY"].members))
        check("anchor: short name / module recorded", by["tools.REGISTRY"].short == "REGISTRY" and by["tools.REGISTRY"].module == "tools")
        check("anchor: PROVIDERS (strings) is not an anchor", not shorts("PROVIDERS"))
        check("anchor: OPEN ({**other}) is open", "tools.OPEN" in by and by["tools.OPEN"].open and not by["tools.OPEN"].closed)
        check("anchor: MUTATED (subscript assign) is open", "tools.MUTATED" in by and by["tools.MUTATED"].open,
              str(by.get("tools.MUTATED") and by["tools.MUTATED"].open_reasons))
        check("anchor: app.Agent.tools (self.attr dict of instances) closed",
              "app.Agent.tools" in by and by["app.Agent.tools"].closed
              and sorted(m.name for m in by["app.Agent.tools"].members) == ["EchoTool", "ShellTool"]
              and all(m.kind == "instance" for m in by["app.Agent.tools"].members))
        check("anchor: app.Agent.registry (subscript assign of a def) has run_shell and is open (item assignment)",
              "app.Agent.registry" in by and any(m.name == "run_shell" and m.kind == "def" for m in by["app.Agent.registry"].members)
              and by["app.Agent.registry"].open)
        check("anchor: VannaBase.run_sql attr_assign with two nested defs",
              "vanna_like.VannaBase.run_sql" in by and by["vanna_like.VannaBase.run_sql"].kind == "attr_assign"
              and sorted(m.name for m in by["vanna_like.VannaBase.run_sql"].members) == ["run_sql_postgres", "run_sql_sqlite"]
              and all(not m.importable for m in by["vanna_like.VannaBase.run_sql"].members) and by["vanna_like.VannaBase.run_sql"].closed)
        # module-level registration through an instance: the anchor is the
        # receiver expression (``server``); linking it to ``Server.tools`` would
        # need to know that add_tool appends to self.tools — a documented limit
        check("anchor: server.add_tool(hello) register_call, open by the lambda",
              "mcp_like.server" in by and by["mcp_like.server"].kind == "register_call"
              and any(m.name == "hello" and m.kind == "def" for m in by["mcp_like.server"].members) and by["mcp_like.server"].open,
              str({k: (v.kind, [m.name for m in v.members], v.open) for k, v in by.items()}))
        check("anchor: Server.tools itself (only runtime appends) is not an anchor", not shorts("Server.tools"))
        check("anchor: function-local dicts are not anchors (local_dict.build.record)",
              not shorts("record") and "local_dict.record" not in by, str(sorted(by)))

        rr = reads("tools.REGISTRY")
        check("read: REGISTRY[name](args) subscript", any(r.idiom == "subscript" and r.key_expr == "name" for r in rr.values()))
        check("read: fn = REGISTRY.get(name); fn(args)", any(r.idiom == "get" for r in rr.values()))
        check("read: candidates of a REGISTRY read are the two defs",
              all(sorted(c["name"] for c in r.candidates) == ["echo", "run_shell"] for r in rr.values()))
        check("read: a read through ``from tools import REGISTRY`` is exact and closed for narrowing",
              rr and all(getattr(r, "binding", "") == "exact" and getattr(r, "anchor_closed", False) for r in rr.values()),
              str([(r.file, getattr(r, "binding", None), getattr(r, "anchor_closed", None)) for r in rr.values()]))
        rt = reads("app.Agent.tools")
        check("read: tool = self.tools[name]; tool.run(args) -> method_call with Cls.run candidates",
              any(r.idiom == "method_call" and r.method == "run"
                  and sorted(c["cls"] for c in r.candidates) == ["EchoTool", "ShellTool"]
                  and all(c["name"] == "run" for c in r.candidates) for r in rt.values()), str([(r.idiom, r.method, r.candidates) for r in rt.values()]))
        check("read: for t in self.tools.values(): t.run(args) -> loop_method",
              any(r.idiom == "loop_method" and r.method == "run" for r in rt.values()))
        rv = reads("vanna_like.VannaBase.run_sql")
        check("read: self.run_sql(sql) attr_call with nested-def candidates",
              any(r.idiom == "attr_call" and sorted(c["name"] for c in r.candidates) == ["run_sql_postgres", "run_sql_sqlite"]
                  and all(c["importable"] is False for c in r.candidates) for r in rv.values()), str([(r.idiom, r.candidates) for r in rv.values()]))
        check("read: for t in self.tools: t(args) has no anchor (Server.tools is not one)",
              not any(r.anchor.endswith("Server.tools") for a in res.anchors for r in a.reads))
        rh = reads("loop_like.HANDLERS")
        check("read: for h in HANDLERS: h(args) -> loop_call with both defs",
              any(r.idiom == "loop_call" and sorted(c["name"] for c in r.candidates) == ["echo", "run_shell"] for r in rh.values()),
              str([(r.idiom, r.candidates) for r in rh.values()]))
        check("no engine: reads are proposed / off", all(not r.accept and r.confidence == "proposed" for a in res.anchors for r in a.reads))

        # ---- review C6 negative tests -------------------------------------- #
        # 1. self.<attr> reads join the reader's own class, or an in-tree
        #    ancestor as an *inherited* (never closed) read — never a stranger
        bh = by.get("inherit.Base.handler")
        rb = reads_of("Base.handler")
        check("C6-1: inherit.Base.handler closed with run_shell",
              bh is not None and bh.closed and [m.name for m in bh.members] == ["run_shell"], str(bh))
        check("C6-1: unrelated classes reading self.handler are NOT joined (Stranger / Unrelated)",
              rb and not any(r.callable.startswith(("Stranger.", "Unrelated.")) for r in rb),
              str([(r.callable, r.anchor) for r in rb]))
        check("C6-1: the read in Base.go is exact and closed",
              any(r.callable == "Base.go" and getattr(r, "binding", "") == "exact" and getattr(r, "anchor_closed", False) for r in rb),
              str([(r.callable, getattr(r, "binding", None)) for r in rb]))
        check("C6-1: the read in Child(Base).run is inherited: candidates attached, never closed",
              any(r.callable == "Child.run" and getattr(r, "binding", "") == "inherited"
                  and not getattr(r, "anchor_closed", True) and [c["name"] for c in r.candidates] == ["run_shell"] for r in rb),
              str([(r.callable, getattr(r, "binding", None), getattr(r, "anchor_closed", None)) for r in rb]))
        b2 = by.get("inherit.Base2.cb")
        check("C6-1: a subclass rebinding the attribute (Rebinder.cb = cb) opens Base2.cb and gets no join",
              b2 is not None and b2.open and any("Rebinder" in w for w in b2.open_reasons)
              and not any(r.callable.startswith("Rebinder.") for r in reads_of("Base2.cb")),
              str((b2 and b2.open_reasons, [(r.callable, r.anchor) for r in reads_of("Base2.cb")])))
        # 2. keys are module-qualified
        la, lb = by.get("loaders_a.LOADERS"), by.get("loaders_b.LOADERS")
        check("C6-2: same-named LOADERS in two modules stay two closed anchors (1 and 2 members)",
              len(shorts("LOADERS")) == 2 and la is not None and lb is not None and la.closed and lb.closed
              and len(la.members) == 1 and len(lb.members) == 2,
              str([(a.name, a.closed, len(a.members), a.open_reasons) for a in shorts("LOADERS")]))
        check("C6-2: each module's read resolves to its own LOADERS",
              la is not None and lb is not None and [r.file for r in la.reads] == ["loaders_a.py"]
              and [r.file for r in lb.reads] == ["loaders_b.py"] and all(len(r.candidates) == 1 for r in la.reads),
              str([(a.name, [(r.file, len(r.candidates)) for r in a.reads]) for a in shorts("LOADERS")]))
        check("C6-2: same-named class Agent in app / agent2 never merges (2 + 1 members)",
              len(shorts("Agent.tools")) == 2 and "agent2.Agent.tools" in by
              and [m.name for m in by["agent2.Agent.tools"].members] == ["EchoTool"]
              and len(by["app.Agent.tools"].members) == 2,
              str([(a.name, [m.name for m in a.members]) for a in shorts("Agent.tools")]))
        # 3. rebinding to a runtime value / class-body declaration
        nc = by.get("setter.Notifier.callback")
        check("C6-3: self.callback = cb (setter parameter) opens Notifier.callback",
              nc is not None and nc.open and any("rebound" in w and "parameter" in w for w in nc.open_reasons),
              str(nc and (nc.closed, nc.open_reasons)))
        mf = by.get("setter.Model.formatter")
        check("C6-3: class-body ``formatter = None`` opens Model.formatter",
              mf is not None and mf.open and any("class body" in w for w in mf.open_reasons), str(mf and (mf.closed, mf.open_reasons)))
        # 4. augmented assignment in the module and in a method
        h2, mg, bx = by.get("aug.HANDLERS2"), by.get("aug.MERGED"), by.get("aug.Box.tools")
        check("C6-4: HANDLERS2 += [...] opens the list anchor",
              h2 is not None and h2.open and any("mutated" in w and "+=" in w for w in h2.open_reasons), str(h2 and (h2.closed, h2.open_reasons)))
        check("C6-4: MERGED |= {...} opens the dict anchor",
              mg is not None and mg.open and any("|=" in w for w in mg.open_reasons), str(mg and (mg.closed, mg.open_reasons)))
        check("C6-4: self.tools |= {...} in a method opens Box.tools",
              bx is not None and bx.open and any("|=" in w for w in bx.open_reasons), str(bx and (bx.closed, bx.open_reasons)))
        # 5. aliases
        t1, t2, t3, t4 = by.get("alias.TABLE"), by.get("alias.TABLE2"), by.get("alias.TABLE3"), by.get("alias.TABLE4")
        check("C6-5: ALIAS = TABLE; ALIAS[k] = fn opens TABLE (aliased / mutated via alias)",
              t1 is not None and t1.open and any("alias" in w for w in t1.open_reasons), str(t1 and (t1.closed, t1.open_reasons)))
        check("C6-5: import alias as al; al.TABLE2[k] = fn opens TABLE2",
              t2 is not None and t2.open and any("alias_use.py" in w for w in t2.open_reasons), str(t2 and (t2.closed, t2.open_reasons)))
        check("C6-5: from alias import TABLE3 as T3; T3[k] = fn opens TABLE3",
              t3 is not None and t3.open and any("alias_use.py" in w for w in t3.open_reasons), str(t3 and (t3.closed, t3.open_reasons)))
        check("C6-5: an untouched sibling (TABLE4) stays closed", t4 is not None and t4.closed, str(t4))
        # 6. relative imports
        rg = by.get("pkg.reg.REG")
        ma = rg and next((m for m in rg.members if m.name == "a"), None)
        mz = rg and next((m for m in rg.members if m.name == "z"), None)
        check("C6-6: from .impl import a -> member module pkg.impl, importable",
              ma is not None and ma.module == "pkg.impl" and ma.importable and ma.candidate and ma.candidate["module"] == "pkg.impl",
              str(ma))
        check("C6-6: from ..outside import z (above src_root) -> importable=False",
              mz is not None and mz.importable is False and mz.candidate and mz.candidate.get("importable") is False, str(mz))
        # 7. function-scope item assignment / global rebinding
        r3, t5 = by.get("decor.REGISTRY3"), by.get("decor.TABLE5")
        check("C6-7: REGISTRY3[fn.__name__] = fn inside register() opens REGISTRY3",
              r3 is not None and r3.open and any("register" in w or "REGISTRY3[" in w for w in r3.open_reasons), str(r3 and (r3.closed, r3.open_reasons)))
        check("C6-7: global TABLE5; TABLE5 = {...} inside reset() opens TABLE5",
              t5 is not None and t5.open and any("global" in w for w in t5.open_reasons), str(t5 and (t5.closed, t5.open_reasons)))
        # minor: .pop reads
        pl = by.get("popread.POOL")
        check("minor: fn = POOL.pop(name); fn(x) is a read (and POOL is open by the .pop())",
              pl is not None and pl.open and any(r.idiom == "get" and r.callable == "take" for r in pl.reads),
              str(pl and (pl.open_reasons, [(r.idiom, r.callable) for r in pl.reads])))

        # ---- review C6 repair: the verifier's remaining defects ------------- #
        # (1) a function-local / parameter / closure binding shadows the module registry
        sh = by.get("shadow.SHADOWED")
        sh_calls = sorted(r.callable for r in (sh.reads if sh else []))
        check("C6-R1: shadow.SHADOWED stays closed with run_shell only",
              sh is not None and sh.closed and [m.name for m in sh.members] == ["run_shell"], str(sh))
        check("C6-R1: reads under a local / parameter / closure / .get binding of SHADOWED join nothing",
              sh is not None and not any(c.startswith(("local_shadow", "param_shadow", "closure_shadow", "get_shadow")) for c in sh_calls),
              str(sh_calls))
        check("C6-R1: the module name read via ``global`` and plainly still joins (exact, closed)",
              sh_calls == ["plain", "via_global"] and all(r.binding == "exact" and r.anchor_closed for r in sh.reads), str(sh_calls))
        # (2) merge: the defining site wins even when a re-exported mutation site was walked first
        rx = by.get("reexp.core.REG")
        check("C6-R2: reexp.core.REG carries its defining site (dict_literal, reexp/core.py:4, short REG, module reexp.core)",
              rx is not None and rx.kind == "dict_literal" and rx.file == "reexp/core.py" and rx.line == 4
              and rx.short == "REG" and rx.module == "reexp.core", str(rx and (rx.kind, rx.file, rx.line, rx.short, rx.module)))
        check("C6-R2: ... open by the mutation through the re-export (REGX[k] = ... in reexp/adder.py), read in core.run only",
              rx is not None and rx.open and any("adder.py" in w for w in rx.open_reasons) and "reexp.REGX" not in by
              and [r.file for r in rx.reads] == ["reexp/core.py"], str(rx and (rx.open_reasons, [r.file for r in rx.reads], sorted(by))))
        res_rx = A.anchoring(d, reject=["REG"])
        check("C6-R2: --reject REG (the defining short name) rejects it",
              next(a for a in res_rx.anchors if a.name == "reexp.core.REG").rejected)
        # (3) a nested class never shares a key with a top-level class of the same name
        ni, no = by.get("nested.Inner.h"), by.get("nested.Outer.Inner.h")
        check("C6-R3: nested.Outer.Inner.h and nested.Inner.h are two closed anchors with one member each",
              ni is not None and no is not None and ni.closed and no.closed
              and [m.name for m in no.members] == ["run_shell"] and [m.name for m in ni.members] == ["echo"],
              str([(a.name, [m.name for m in a.members]) for a in res.anchors if a.name.startswith("nested.")]))
        check("C6-R3: each class's self.h read joins its own anchor with one candidate; short is Outer.Inner.h",
              no is not None and ni is not None and no.short == "Outer.Inner.h"
              and [(r.callable, len(r.candidates)) for r in no.reads] == [("Outer.Inner.run", 1)]
              and [(r.callable, len(r.candidates)) for r in ni.reads] == [("Inner.run", 1)],
              str([(a.name, [(r.callable, len(r.candidates)) for r in a.reads]) for a in res.anchors if a.name.startswith("nested.")]))
        # (4) rebinding through setattr / __dict__ / the class object
        for cname, what in (("SetAttr", "setattr(self, 'cb', fn)"), ("DictAttr", "self.__dict__['cb'] = fn"),
                            ("ObjSetAttr", "object.__setattr__(self, 'cb', fn)"), ("SelfSetAttr", "self.__setattr__('cb', fn)"),
                            ("ClassRebound", "ClassRebound.cb = pick()")):
            an = by.get(f"setattr_like.{cname}.cb")
            check(f"C6-R4: {what} opens {cname}.cb",
                  an is not None and an.open and any("rebound" in w for w in an.open_reasons), str(an and (an.closed, an.open_reasons)))
        dyn = by.get("setattr_like.DynSetAttr.cb")
        check("C6-R4: setattr(self, k, v) with a dynamic name opens every attribute anchor of the class",
              dyn is not None and dyn.open and any("dynamic attribute name" in w for w in dyn.open_reasons),
              str(dyn and (dyn.closed, dyn.open_reasons)))
        sd = by.get("setattr_like.SetAttrDef.cb")
        check("C6-R4: setattr(self, 'cb', echo) with a def is a member, the anchor stays closed",
              sd is not None and sd.closed and sorted(m.name for m in sd.members) == ["echo", "run_shell"],
              str(sd and (sd.closed, [m.name for m in sd.members], sd.open_reasons)))
        db = by.get("setattr_like.DynBase.cb")
        check("C6-R4: a subclass with a dynamic setattr opens the base anchor and gets no inherited join",
              db is not None and db.open and any("DynSub" in w and "dynamic setattr" in w for w in db.open_reasons)
              and not any(r.callable.startswith("DynSub.") for r in db.reads),
              str(db and (db.open_reasons, [r.callable for r in db.reads])))

        # rejection by name (qualified or short)
        res2 = A.anchoring(d, reject=["tools.REGISTRY", "HANDLERS"])
        by2 = {a.name: a for a in res2.anchors}
        check("reject: tools.REGISTRY (qualified) flagged and has no reads", by2["tools.REGISTRY"].rejected and not by2["tools.REGISTRY"].reads)
        check("reject: HANDLERS (short) flagged and has no reads", by2["loop_like.HANDLERS"].rejected and not by2["loop_like.HANDLERS"].reads)

        # join with a fake engine result at the positions the reads were found at
        p_sub = next(r for r in rr.values() if r.idiom == "subscript")
        p_typed = next(r for r in rt.values() if r.idiom == "method_call")
        p_stub = next(r for r in rv.values() if r.idiom == "attr_call")
        p_inh = next((r for r in rb if r.callable == "Child.run"), None)
        sites = {
            "app.py": [{"line": p_sub.line, "col": p_sub.col, "end_line": p_sub.end_line, "end_col": p_sub.end_col,
                        "status": "unresolved:UnknownCallCallee", "targets": [], "callable": "app.by_subscript"},
                       {"line": p_typed.line, "col": p_typed.col, "end_line": p_typed.end_line, "end_col": p_typed.end_col,
                        "status": "resolved", "targets": ["tools.ShellTool.run", "tools.EchoTool.run"], "callable": "app.Agent.step"}],
            "vanna_like.py": [{"line": p_stub.line, "col": p_stub.col, "end_line": p_stub.end_line, "end_col": p_stub.end_col,
                               "status": "resolved_stub", "targets": ["vanna_like.VannaBase.run_sql"], "callable": "vanna_like.VannaBase.ask"}],
        }
        if p_inh is not None:
            sites["inherit.py"] = [{"line": p_inh.line, "col": p_inh.col, "end_line": p_inh.end_line, "end_col": p_inh.end_col,
                                    "status": "unresolved:UnknownCallCallee", "targets": [], "callable": "inherit.Child.run"}]
        fake = EW.ScanResult(walls=[], env={}, counts={}, sites_by_file=sites)
        res3 = A.anchoring(d, engine=fake)
        pos = {k: v for k, v in res3.by_position.items()}
        r_sub = pos.get(("app.py", p_sub.line, p_sub.col))
        check("join: unresolved engine site -> confirmed / accepted", r_sub is not None and r_sub[1].accept and r_sub[1].confidence == "confirmed", str(r_sub))
        r_typed = pos.get(("app.py", p_typed.line, p_typed.col))
        check("join: typed registry read (engine resolved) -> proposed / off",
              r_typed is not None and not r_typed[1].accept and "typed registry" in r_typed[1].note, str(r_typed))
        r_stub = pos.get(("vanna_like.py", p_stub.line, p_stub.col))
        check("join: resolved_stub -> confirmed", r_stub is not None and r_stub[1].accept, str(r_stub))
        r_inh = pos.get(("inherit.py", p_inh.line, p_inh.col)) if p_inh is not None else None
        check("join C6-1: an inherited read at an unresolved site stays proposed / off, anchor_closed False",
              r_inh is not None and not r_inh[1].accept and r_inh[1].confidence == "proposed"
              and not getattr(r_inh[1], "anchor_closed", True) and "inherited" in r_inh[1].note, str(r_inh and r_inh[1]))
        check("join C6-1: by_position hands the consumer an OPEN view of the anchor for an inherited read (never narrows)",
              r_inh is not None and not r_inh[0].closed and r_inh[0].name == "inherit.Base.handler"
              and next(a for a in res3.anchors if a.name == "inherit.Base.handler").closed,
              str(r_inh and (r_inh[0].closed, r_inh[0].open_reasons)))
        check("json: reads carry binding / anchor_closed and anchors carry short",
              all("binding" in r and "anchor_closed" in r for a in js_reads(res3) for r in a) and all("short" in a for a in res3.to_dict()["anchors"]))
        js = res3.to_dict()
        check("json: counts", js["counts"]["anchors"] >= 6 and js["counts"]["reads"] >= 6, str(js["counts"]))

        test_parse_once(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    print(f"\n{N - len(FAILS)}/{N} passed" + ("" if not FAILS else f"; FAILED: {FAILS}"))
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
