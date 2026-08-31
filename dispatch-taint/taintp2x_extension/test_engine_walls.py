"""Tests for engine_walls.py — no pyre needed.

``r_min/`` holds the in-repo excerpts of real Pysa result directories
(``engine_walls.py extract``): AutoGPT v0.5.0 (cond_A and the lowered cond_B),
LangChain (typed and type-erased), Semantic Kernel, and two old-schema
call graphs from the TaintP2X dataset (OpenManus, vanna), plus fixture-sized
trees analysed for one rule each (``two_walls_before_stub``, ``m1_bindings``). Every expectation
below was read off the full result directories first (gate 0 of
docs/SCALE_OUT_DESIGN.md), so this file pins what the engine said, not what
the AST looks like.

Excerpt-relative vs pinned (review minor): the env counts of an excerpt
(``sites_in_repo``, ``unresolved_by_reason``, ``env_gaps``, ``callables_*``)
are counts over the excerpt's files, never the full tree's. Tiers T1 / T2 are
recomputed from the kept models; T3 (reachable from a source-carrying
callable over the call graph) is NOT computable from an excerpt — it keeps
no caller records — and comes from the ``r/engine-tiers.json`` side file
``extract`` records off the full tree (``test_tier_rules``). Every excerpt's
tiers were checked equal to a scan of its full tree (0 differences) when the
side files were generated.

    python3 test_engine_walls.py
"""
from __future__ import annotations

import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import engine_walls as E   # noqa: E402

R = os.path.join(HERE, "r_min")
FAILS: list = []
N = 0


def check(label, cond, detail=""):
    global N
    N += 1
    if cond:
        print(f"PASS {label}")
    else:
        print(f"FAIL {label}" + (f": {detail}" if detail else ""))
        FAILS.append(label)


def wall_at(res, file_suffix, line, col=None):
    for w in res.walls:
        if w.file.endswith(file_suffix) and w.line == line and (col is None or w.col == col):
            return w
    return None


# --------------------------------------------------------------------------- #
# unit: record parsing (old and new schema)
# --------------------------------------------------------------------------- #
def test_sites_of():
    new = {
        "277:21-277:51": {"call": {"unresolved": ["BypassingDecorators", ["UnknownIdentifierCallee"]]}},
        "275:18-275:51": {"call": {"calls": [{"target": "agent.Agent._get_command"}]}},
        "283:15-283:24|artificial-call|try-handler-isinstance": {"call": {"calls": [{"target": "isinstance"}]}},
        "9:12-9:19": {"call": {"new_calls": [{"target": "object.__new__"}], "init_calls": [{"target": "tools.Tools.__init__"}]}},
        "1:0-1:5|identifier|x": {"identifier": {"globals": []}},
    }
    s = {x.key.split("|")[0]: x for x in E._sites_of(new)}
    check("new schema: unresolved reason", s["277:21-277:51"].unresolved == "UnknownIdentifierCallee")
    check("new schema: span", (s["277:21-277:51"].line, s["277:21-277:51"].col, s["277:21-277:51"].end_line,
                               s["277:21-277:51"].end_col) == (277, 21, 277, 51))
    check("new schema: resolved targets", s["275:18-275:51"].targets == ["agent.Agent._get_command"]
          and s["275:18-275:51"].unresolved is None)
    check("new schema: artificial flagged", s["283:15-283:24"].artificial.startswith("artificial-call"))
    check("new schema: constructor flagged", s["9:12-9:19"].constructor)
    check("new schema: identifier entries skipped", "1:0-1:5" not in s)
    old = {
        "518:15-518:54": {"singleton": {"call": {"unresolved": True}}},
        "583:16-583:76": {"singleton": {"call": {"calls": [{"target": "x.y"}]}}},
        "582:17-582:72": {"compound": {"__enter__": {"call": {"calls": [{"target": "T.__enter__"}]}},
                                       "Trace": {"call": {"init_calls": [{"target": "T.__init__"}]}}}},
    }
    o = list(E._sites_of(old))
    check("old schema: unresolved without reason", any(x.unresolved == "n/a" for x in o))
    check("old schema: singleton resolved", any(x.targets == ["x.y"] for x in o))
    check("old schema: compound yields both calls", sum(1 for x in o if x.key == "582:17-582:72") == 2)


def test_helpers():
    fn = ast.parse("def f(x):\n    '''doc'''\n    raise NotImplementedError\n").body[0]
    check("trivial: raise", E._def_body_trivial(fn)[0])
    fn = ast.parse("def f(x):\n    ...\n").body[0]
    check("trivial: ellipsis", E._def_body_trivial(fn)[0])
    fn = ast.parse("from abc import abstractmethod\n@abstractmethod\ndef f(x):\n    return x\n").body[1]
    check("trivial: abstractmethod", E._def_body_trivial(fn)[1] == "abstractmethod")
    fn = ast.parse("def f(x):\n    return x + 1\n").body[0]
    check("not trivial: real body", not E._def_body_trivial(fn)[0])
    check("constant key: literal", E._key_is_constant("'tags'"))
    check("constant key: __name__", E._key_is_constant("__name__"))
    check("constant key: expression is not", not E._key_is_constant("agent_action.tool"))
    check("catalog: suffix match", E.catalog_match("langchain_core.tools.base.BaseTool.run", E.load_catalog())["api"] == "BaseTool.run")
    check("catalog: framework-specific rows do not collide",
          E.catalog_match("app.tool.base.BaseTool.__call__", E.load_catalog())["framework"] == "openmanus"
          and E.catalog_match("llama_index.tools.types.BaseTool.__call__", E.load_catalog())["framework"] == "llama_index"
          and E.catalog_match("somefw.BaseTool.__call__", E.load_catalog()) is None)
    check("catalog: Overrides{} stripped", E.catalog_match("Overrides{langchain.tools.base.BaseTool.arun}", E.load_catalog())["api"] == "BaseTool.arun")
    check("catalog: no match", E.catalog_match("os.path.join", E.load_catalog()) is None)
    # review K7: the rows ARE the presets' dispatch rows (catalog.py vocabulary), not a built-in list
    import catalog as CAT
    check("catalog: load_catalog == catalog.dispatch_rows(spec.presets.json)",
          sorted(r["api"] for r in E.load_catalog()) == sorted(r["api"] for r in CAT.dispatch_rows(CAT.load()))
          and len(E.load_catalog()) >= 17)
    check("catalog: fallback rows only when the presets file is missing",
          [r["api"] for r in E.load_catalog(os.path.join(HERE, "no_such_presets.json"))] == ["BaseTool.run", "BaseTool.arun"]
          and not hasattr(E, "DEFAULT_DISPATCH"))
    # generated-code index and the cond_B -> cond_A line map (review C1 (b)/(c))
    cond_b_src = '''\
from tools import REGISTRY, BaseParser


def step(name, args, parser):
    if __ctaudit_unreachable__:  # [ctaudit] resolved dynamic dispatch -> 2 targets | wall=pkg/app.py:5
        from tools import echo, run_shell
        run_shell(args)  # L0
        echo(args)  # L1
    result = REGISTRY[name](args)
    parser.parse(args)
    return result
'''
    fx = E._FileIndex("<mem>", source=cond_b_src)
    check("generated: guard block indexed with its wall tag",
          len(fx.generated) == 1 and (fx.generated[0].start, fx.generated[0].end, fx.generated[0].wall_file,
                                      fx.generated[0].wall_line, fx.generated[0].targets) == (5, 8, "pkg/app.py", 5, 2))
    check("generated: calls inside the block are not indexed, the wall below is",
          not any(ln in fx.by_line for ln in (7, 8)) and 9 in fx.by_line and fx.in_generated(6) and not fx.in_generated(9))
    check("generated: cond_B line 9 maps to cond_A line 5 (block inserted before), 10 -> 6, inside -> None",
          (fx.cond_a_line(9), fx.cond_a_line(10), fx.cond_a_line(6), fx.cond_a_line(4)) == (5, 6, None, 4))
    check("generated: pure line map with two spans",
          [E.cond_a_line(n, [(3, 4), (8, 10)]) for n in (2, 3, 5, 7, 9, 11)] == [2, None, 3, 5, None, 6])
    red = E._FileIndex("<mem>", source='"""[ctaudit] generated redirectors — one per resolved dispatch link.\n"""\nfrom tools import run_shell\n\ndef redirector_0(cmd):\n    return run_shell(cmd)\n')
    check("generated: a redirector module is generated whole", red.generated_module and red.in_generated(6))
    tc_src = ("import os\nfrom typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from tools import ShellTool\n\n"
              "def step(t, args):\n    if __ctaudit_unreachable__:  # [ctaudit] resolved dynamic dispatch -> 1 targets | wall=app.py:5\n"
              "        __ctaudit_obj = ShellTool.__new__(ShellTool)\n        __ctaudit_obj.run(args)  # L0\n    t.run(args)\n")
    tfx = E._FileIndex("<mem>", source=tc_src)
    check("generated: the injected TYPE_CHECKING import block (inline mode) counts as generated lines",
          tfx.generated_extra == [(2, 4)] and tfx.cond_a_line(10) == 4 and tfx.in_generated(3), str(tfx.generated_ranges()))
    # BoolOp-receiver rule (engine_walls._suggest): an OPEN BoolOp (call / literal alternative) is
    # proposed, a closed one of named alternatives is confirmed — disabling the branch fails this
    boolop_src = "from tools import PRIMARY, DEFAULT\nclass A:\n    def m(self, k, x):\n        t = self.tools.get(k) or {}\n        t.run(x)\n        u = PRIMARY or DEFAULT\n        u.run(x)\n"
    bfx = E._FileIndex("<mem>", source=boolop_src)
    rows = {}
    for (line, _c), calls in bfx.calls.items():
        for c in calls:
            if ast.unparse(c.func) in ("t.run", "u.run"):
                d = E.describe_call(c, bfx)
                w = E.EngineWall(id="", file="a.py", line=line, col=0, end_line=line, end_col=0, callable="A.m",
                                 callee=ast.unparse(c.func), idiom=d["idiom"], resolver=d["resolver"], key_expr=d["key_expr"],
                                 receiver_binding=d["receiver_binding"], members=d["members"], members_open=d["members_open"],
                                 engine_status="unresolved:UnknownBaseType")
                E._suggest(w, "receiver")
                rows[ast.unparse(c.func)] = w
    check("boolop receiver: `t = self.tools.get(k) or {}; t.run(x)` -> proposed, not accepted",
          rows["t.run"].receiver_binding == "boolop" and rows["t.run"].members_open
          and rows["t.run"].confidence == "proposed" and not rows["t.run"].accept and "open BoolOp" in rows["t.run"].note)
    check("boolop receiver: `u = PRIMARY or DEFAULT; u.run(x)` -> confirmed, accepted",
          rows["u.run"].receiver_binding == "boolop" and not rows["u.run"].members_open
          and rows["u.run"].confidence == "confirmed" and rows["u.run"].accept)


def test_describe_call():
    src = '''
import logging
from tools import REGISTRY, resolve, PRIMARY, default
logger = logging.getLogger(__name__)

class A:
    def m(self, name, args, fn, tools):
        REGISTRY[name](args)                 # 8 subscript
        getattr(self, name)(args)            # 9 getattr
        f = resolve(name); f(args)           # 10 higher_order
        g = PRIMARY or default; g(args)      # 11 boolop
        t = self.tools[name]; t.run(args)    # 12 method_call / subscript receiver
        logger.debug(args)                   # 13 method_call / resolver_call receiver, constant key
        self.handler(args)                   # 14 attr_call
        fn(args)                             # 15 param_call
        for h in tools: h.run(args)          # 16 loop receiver
        resolve(args)                        # 17 name_call
        self.tools[name].run(args)           # 18 inline subscript receiver (review M1)
        REGISTRY[name].run(args)             # 19 inline subscript receiver
        getattr(self, name).run(args)        # 20 inline getattr receiver
        (PRIMARY or default).run(args)       # 21 inline BoolOp receiver
        for k, v in REGISTRY.items(): v(args)            # 22 loop_call, tuple target
        d = {k: v(args) for k, v in REGISTRY.items()}    # 23 loop_call, comprehension generator
        self.tools.get(name).run(args)       # 24 call-bound inline receiver: untyped, not a selection
        fn_name, extra = REGISTRY[name]; fn_name(args)   # 25 subscript through tuple unpacking
        unbound(args)                        # 26 name_call with no binding in sight
        t2 = self.tools[name]; t2.run(args)  # 27 subscript receiver (M1 repair: line 28 must not rebind it)
        names = [t2.name for t2 in tools]    # 28 a LATER comprehension reusing the name: its own scope
        h2 = resolve(name); h2(args)         # 29 higher_order (M1 repair: line 30 must not rebind it)
        [h2(x) for h2 in tools]              # 30 the same name as a comprehension variable: loop_call
        [[u(args) for u in grp] for grp in tools]   # 31 nested comprehension: the inner generator binds u
        [t2(x) for x in tools]               # 32 a comprehension that does not bind t2: still subscript
        for k2, t2 in t2.items(): t2.run(args)   # 33 the iterable reads the OUTER t2 (subscript); the body the loop's
'''
    fx = E._FileIndex("<mem>", source=src)
    got = {}
    for (line, _col), calls in fx.calls.items():
        for c in calls:
            d = E.describe_call(c, fx)
            got.setdefault(line, []).append((ast.unparse(c.func), d))
    def one(line, callee):
        return next(d for cal, d in got[line] if cal == callee)
    d = one(18, "self.tools[name].run")
    check("describe: inline subscript receiver is method_call/subscript",
          (d["idiom"], d["receiver_binding"], d["resolver"], d["key_expr"]) == ("method_call", "subscript", "self.tools", "name"))
    d = one(19, "REGISTRY[name].run")
    check("describe: REG[k].m() is method_call/subscript", (d["idiom"], d["receiver_binding"], d["resolver"]) == ("method_call", "subscript", "REGISTRY"))
    d = one(20, "getattr(self, name).run")
    check("describe: getattr(o, k).m() is method_call/getattr", (d["idiom"], d["receiver_binding"], d["key_expr"]) == ("method_call", "getattr", "name"))
    d = one(21, "(PRIMARY or default).run")
    check("describe: (a or b).m() is method_call/boolop with members", (d["idiom"], d["receiver_binding"], d["members"], d["members_open"])
          == ("method_call", "boolop", ["PRIMARY", "default"], False))
    d = one(22, "v")
    check("describe: tuple-target loop variable is loop_call", (d["idiom"], d["receiver_binding"], d["resolver"]) == ("loop_call", "loop", "iter(REGISTRY.items())"))
    d = one(23, "v")
    check("describe: comprehension generator variable is loop_call", (d["idiom"], d["receiver_binding"]) == ("loop_call", "loop"))
    d = one(24, "self.tools.get(name).run")
    check("describe: call-bound inline receiver is method_call/resolver_call (not a dispatch binding)",
          (d["idiom"], d["receiver_binding"]) == ("method_call", "resolver_call") and d["receiver_binding"] not in E._RECEIVER_DISPATCH_BINDINGS)
    d = one(25, "fn_name")
    check("describe: `fn, extra = REG[k]; fn(x)` is subscript", (d["idiom"], d["resolver"], d["key_expr"]) == ("subscript", "REGISTRY", "name"))
    d = one(26, "unbound")
    check("describe: unbound name stays name_call with an empty binding", (d["idiom"], d["receiver_binding"]) == ("name_call", ""))
    # review M1 repair: a comprehension is its own scope and has no position of its own — a later
    # ``[t2.name for t2 in tools]`` must not win the latest-binding race over ``t2 = self.tools[name]``
    d = one(27, "t2.run")
    check("describe: a LATER comprehension reusing the receiver name does not rebind it (subscript kept)",
          (d["idiom"], d["receiver_binding"], d["resolver"], d["key_expr"]) == ("method_call", "subscript", "self.tools", "name"), str(d))
    d = one(29, "h2")
    check("describe: a LATER comprehension reusing the callee name does not rebind it (higher_order kept)",
          (d["idiom"], d["receiver_binding"], d["resolver"]) == ("higher_order", "resolver_call", "resolve"), str(d))
    d = one(30, "h2")
    check("describe: the same name called INSIDE the comprehension is its loop variable",
          (d["idiom"], d["receiver_binding"], d["resolver"]) == ("loop_call", "loop", "iter(tools)"), str(d))
    d = one(31, "u")
    check("describe: nested comprehension — the inner generator binds the callee",
          (d["idiom"], d["receiver_binding"], d["resolver"]) == ("loop_call", "loop", "iter(grp)"), str(d))
    d = one(32, "t2")
    check("describe: a call inside a comprehension that does not bind the name keeps the def-level binding",
          (d["idiom"], d["resolver"], d["key_expr"]) == ("subscript", "self.tools", "name"), str(d))
    d = one(33, "t2.items")
    check("describe: a call in a for statement's own iterable is bound by the statement BEFORE the loop (subscript)",
          (d["idiom"], d["receiver_binding"], d["resolver"]) == ("method_call", "subscript", "self.tools"), str(d))
    d = one(33, "t2.run")
    check("describe: ... while the loop body sees the loop variable",
          (d["idiom"], d["receiver_binding"], d["resolver"]) == ("method_call", "loop", "iter(t2.items())"), str(d))
    d = one(13, "logger.debug")
    check("describe: logger = getLogger(__name__); logger.debug() is not a dispatch binding",
          d["receiver_binding"] == "resolver_call" and E._key_is_constant(d["key_expr"]))
    d = one(8, "REGISTRY[name]")
    check("describe: subscript", (d["idiom"], d["resolver"], d["key_expr"]) == ("subscript", "REGISTRY", "name"))
    d = one(9, "getattr(self, name)")
    check("describe: getattr", (d["idiom"], d["resolver"], d["key_expr"]) == ("getattr", "getattr(self)", "name"))
    d = one(10, "f")
    check("describe: higher_order", (d["idiom"], d["resolver"], d["key_expr"]) == ("higher_order", "resolve", "name"))
    d = one(11, "g")
    check("describe: boolop members", d["idiom"] == "boolop" and d["members"] == ["PRIMARY", "default"] and not d["members_open"])
    d = one(12, "t.run")
    check("describe: method_call on subscript receiver",
          (d["idiom"], d["receiver_binding"], d["resolver"], d["key_expr"]) == ("method_call", "subscript", "self.tools", "name"))
    d = one(13, "logger.debug")
    check("describe: method_call on call-bound receiver",
          (d["idiom"], d["receiver_binding"], d["key_expr"]) == ("method_call", "resolver_call", "__name__"))
    d = one(14, "self.handler")
    check("describe: attr_call", (d["idiom"], d["resolver"], d["key_expr"]) == ("attr_call", "self", "handler"))
    d = one(15, "fn")
    check("describe: param_call", d["idiom"] == "param_call")
    d = one(16, "h.run")
    check("describe: loop receiver", (d["idiom"], d["receiver_binding"]) == ("method_call", "loop"))
    d = one(17, "resolve")
    check("describe: name_call (import)", d["idiom"] == "name_call")


def test_in_repo_rel():
    run = E.EngineRun(os.path.join(R, "autogpt"))
    check("in_repo: relative filename", run.in_repo_rel("src/agent.py", "") == "src/agent.py")
    check("in_repo: copied results by full suffix",
          run.in_repo_rel("*", "/elsewhere/cond_A/src/agent.py") == "src/agent.py")
    check("in_repo: basename alone does not match",
          run.in_repo_rel("*", "/venv/site-packages/langchain_classic/agents/agent.py") == "")
    check("in_repo: external", run.in_repo_rel("*", "/venv/site-packages/x.py") == "")


# --------------------------------------------------------------------------- #
# gate 0: real result directories (excerpts)
# --------------------------------------------------------------------------- #
def test_autogpt():
    res = E.scan(os.path.join(R, "autogpt"))
    check("autogpt: exactly one wall", len(res.walls) == 1, str([w.position for w in res.walls]))
    w = wall_at(res, "agent.py", 277, 21)
    check("autogpt: 277:21 is the wall", w is not None)
    if w:
        check("autogpt: S1 UnknownIdentifierCallee", w.engine_status == "unresolved:UnknownIdentifierCallee")
        check("autogpt: idiom higher_order", w.idiom == "higher_order")
        check("autogpt: resolver / key", (w.resolver, w.key_expr) == ("self._get_command", "tool_call.name"))
        check("autogpt: tier T1 (source frame touches the call)", w.engine_tier == "T1")
        check("autogpt: accepted, confirmed", w.accept and w.confidence == "confirmed")
        check("autogpt: aligned with the AST, callable matches", w.aligned and w.callable_match)
        # ``command(**tool_call.arguments)`` has no simple positional to forward: the
        # splat is delivered per parameter by the dry run (links.forward_args), so the
        # wall row itself carries no taint args (review minor: the old ``== [] or list``
        # was always true)
        check("autogpt: taint args (splat -> none on the row)", w.taint_args == [], str(w.taint_args))
        check("autogpt: receiver / target form recorded (S1: none)", (w.receiver_class, w.target_form, w.s2_reason) == ("", "", ""))
        check("autogpt: statement span", (w.stmt_line, w.stmt_kind) == (277, "Assign"))
        check("autogpt: enclosing callable", w.callable == "agent.Agent._execute_tool")
    e = res.env
    check("autogpt: unresolved by reason",
          e["unresolved_by_reason"] == {"UnknownBaseType": 53, "CannotResolveExports": 32,
                                       "CannotFindParentClass": 10, "UnknownIdentifierCallee": 1},
          str(e["unresolved_by_reason"]))
    check("autogpt: the other 95 are environment gaps, not walls", e["env_gaps"] == 95, str(e["env_gaps"]))
    check("autogpt: logger.debug is an env gap (call-bound receiver)",
          any(g["line"] == 250 and g["reason"] == "UnknownBaseType" for g in e["env_gap_rows"]))
    check("autogpt: outcome ok", e["outcome"] == "ok")
    check("autogpt: in-repo decorator seen", any(d["decorator"] == "forge.command.command" for d in e["decorators_in_repo"]))
    st = res.status_at("agent.py", 275)
    check("autogpt: resolver call itself is resolved", st is not None and st["status"] == "resolved"
          and st["targets"] == ["agent.Agent._get_command"])
    check("autogpt: pysa version pinned", e["pysa_version_known"])
    md = E.render_md(res)
    check("autogpt: markdown row", "`agent.py:277:21`" in md and "| x |" in md)


def test_autogpt_cond_b_residual():
    cb = os.path.join(R, "autogpt_condB")
    res = E.scan(cb)
    w = wall_at(res, "agent.py", 277, 21)
    check("cond_B: the original call is still unresolved (kept by design)", w is not None)
    check("cond_B: inserted calls under the guard are not walls",
          not any(x for x in res.walls if x.line > 277 and x.file.endswith("agent.py")),
          str([x.position for x in res.walls]))
    r = E.residual(cb, links_json=os.path.join(cb, "links.json"))
    check("cond_B: residual raw 1, net 0", (r["residual_raw"], r["residual"], r["lowered_walls"]) == (1, 0, 1), str(r))
    check("cond_B: the generated block's sites are counted as generated (excluded), block inserted after -> no remap",
          r["generated_excluded"] > 0 and r["remapped"] == 0 and res.counts["generated"] == r["generated_excluded"]
          and all(s["status"] == "generated" for s in res.sites_by_file.get("agent.py", []) if 278 <= s["line"] <= 290),
          str({k: v for k, v in r.items() if k != "rows"}))
    check("cond_B: a flat tree's basename key is the relative path (no legacy warning)", not r["legacy_links"])


def test_lc_real_typed():
    res = E.scan(os.path.join(R, "lc_real"))
    w = wall_at(res, "agents/agent.py", 1398, 26)
    check("lc typed: 1398 is S3 resolved_dispatch BaseTool.run", w is not None and w.engine_status == "resolved_dispatch:BaseTool.run")
    if w:
        check("lc typed: method_call on subscript receiver",
              (w.idiom, w.receiver_binding, w.resolver, w.key_expr) == ("method_call", "subscript", "name_to_tool_map", "agent_action.tool"))
        check("lc typed: engine follows Overrides{BaseTool._run}",
              "Overrides{langchain_core.tools.base.BaseTool._run}" in w.dispatch_targets)
        check("lc typed: proposed, not accepted (typed tree: taint already crosses)",
              w.confidence == "proposed" and not w.accept and "override" in w.note)
        check("lc typed: tier T1", w.engine_tier == "T1")
    w2 = wall_at(res, "agents/agent.py", 1549, 32)
    check("lc typed: 1549 is BaseTool.arun", w2 is not None and w2.engine_status == "resolved_dispatch:BaseTool.arun")
    check("lc typed: catalogue hits", res.env["catalog_hits"].get("BaseTool.run") == 3
          and res.env["catalog_hits"].get("BaseTool.arun") == 3, str(res.env["catalog_hits"]))
    check("lc typed: nothing accepted in agent.py", not any(x.accept for x in res.walls if x.file.endswith("agents/agent.py")))


def test_lc_real_notype():
    res = E.scan(os.path.join(R, "lc_real_notype"))
    w = wall_at(res, "agents/agent.py", 1398, 26)
    check("lc notype: 1398 is S1 UnknownBaseType", w is not None and w.engine_status == "unresolved:UnknownBaseType")
    if w:
        check("lc notype: receiver bound by subscript -> accepted",
              w.receiver_binding == "subscript" and w.accept and w.confidence == "confirmed")
        check("lc notype: tier T1", w.engine_tier == "T1")
        check("lc notype: resolver / key", (w.resolver, w.key_expr) == ("name_to_tool_map", "agent_action.tool"))
    w2 = wall_at(res, "agents/agent.py", 1549, 32)
    check("lc notype: 1549 accepted too", w2 is not None and w2.accept and w2.engine_status == "unresolved:UnknownBaseType")
    w3 = wall_at(res, "agents/agent.py", 1353, 26)
    check("lc notype: ExceptionTool().run stays S3 proposed (row present, catalogue hit, not accepted)",
          w3 is not None and w3.engine_status == "resolved_dispatch:BaseTool.run" and w3.confidence == "proposed"
          and not w3.accept, str(w3 and (w3.engine_status, w3.confidence, w3.accept)))


def test_sk_real():
    res = E.scan(os.path.join(R, "sk_real"))
    w = wall_at(res, "data/vector.py", 2103, 35)
    check("sk: 2103 is the BoolOp wall", w is not None and w.idiom == "boolop"
          and w.engine_status == "unresolved:UnknownIdentifierCallee")
    if w:
        check("sk: BoolOp members", w.members == ["filter_update_function", "default_dynamic_filter_function"])
        check("sk: open alternative (parameter) flagged", w.members_open)
        check("sk: accepted, tier T2", w.accept and w.engine_tier == "T2")
        check("sk: in async def", w.in_async)
    w = wall_at(res, "data/vector.py", 2130, 24)
    check("sk: 2130 string_mapper is param_call, proposed", w is not None and w.idiom == "param_call"
          and not w.accept and w.engine_tier == "T1")
    w = wall_at(res, "data/vector.py", 997, 23)
    check("sk: 997 self.definition.deserialize is S2 resolved_stub", w is not None and w.engine_status == "resolved_stub"
          and w.accept and (w.resolver, w.key_expr) == ("self.definition", "deserialize"))
    st = res.status_at("semantic_kernel/data/vector.py", 2107)
    check("sk: 2107 self.search resolves to the @overload implementation (not a stub)",
          st is not None and st["status"] == "resolved"
          and st["targets"] == ["semantic_kernel.data.vector.VectorSearch.search"], str(st))
    check("sk: no S3 row without KernelFunction in the excerpt",
          not any(x.engine_status.startswith("resolved_dispatch") for x in res.walls))
    # review C5 policy (repair): the six ``self.definition.<m>`` stubs have a
    # typing.Protocol receiver — s2_reason receiver_unknown, no engine target BY
    # CONSTRUCTION (no override row for a Protocol) — and stay pre-accepted /
    # confirmed: the draft's recovery, not the override graph, is their candidate
    # set (README S2 row). The unlowerable rule (receiver_subclass_no_overrides)
    # must not widen to them: a _suggest extended to receiver_unknown flips all six off.
    stubs = [w for w in res.walls if w.engine_status == "resolved_stub"]
    check("sk C5 policy (repair): the six Protocol-receiver stubs are resolved_stub / receiver_unknown / 0 engine targets / accepted, confirmed",
          sorted((w.line, w.col) for w in stubs) == [(927, 19), (940, 19), (997, 23), (998, 19), (1015, 23), (1016, 18)]
          and all(w.s2_reason == "receiver_unknown" and w.dispatch_targets == [] and w.accept and w.confidence == "confirmed"
                  and w.receiver_class.endswith("Protocol") and w.target_form == "plain" for w in stubs),
          str([(w.position, w.s2_reason, w.accept, w.confidence, w.dispatch_targets) for w in stubs]))
    # review C5 policy (repair, pin of residual_confirmed): with no links.json the
    # T1/T2 residual of the excerpt is 2103 (BoolOp, confirmed) + 2130 (param_call,
    # proposed): confirmed 1 / unlowerable 0. A residual_confirmed hard-wired to 0,
    # or one counting proposed rows too (2), fails here.
    r = E.residual(os.path.join(R, "sk_real"))
    check("sk C5 policy (repair): residual (no links) raw 2 / net 2 / confirmed 1 / unlowerable 0 — 2103 confirmed, 2130 proposed",
          (r["residual_raw"], r["residual"], r["residual_confirmed"], r["residual_unlowerable"], r["lowered_walls"]) == (2, 2, 1, 0, 0)
          and sorted((x["line_cond_a"], x["confidence"], x["tier"]) for x in r["rows"]) == [(2103, "confirmed", "T2"), (2130, "proposed", "T1")]
          and all(x["s2_reason"] == "" for x in r["rows"]),
          str({k: v for k, v in r.items() if k != "rows"}) + str([(x["line_cond_a"], x["confidence"]) for x in r["rows"]]))


def test_dataset_scan():
    d = E.dataset_scan(os.path.join(R, "dataset_openmanus", "call-graph.json"))
    check("dataset openmanus: old schema, no reasons", d["by_reason"] == {"n/a": d["unresolved_in_repo"]} and d["unresolved_in_repo"] > 0)
    check("dataset openmanus: schema detected from the records (singleton/compound), not the header",
          d["schema"] == "old" and E.dataset_scan(os.path.join(R, "autogpt", "r", "call-graph.json"))["schema"] == "new")
    check("dataset openmanus: two files", d["files_with_unresolved"] == 2)
    check("dataset openmanus: ToolCollection.execute has an unresolved call",
          any(r["file"].endswith("tool_collection.py") and r["callable"].endswith("ToolCollection.execute") for r in d["rows"]))
    v = E.dataset_scan(os.path.join(R, "dataset_vanna", "call-graph.json"))
    check("dataset vanna: base.py counted", v["top_files"] and v["top_files"][0]["file"].endswith("vanna/base/base.py")
          and v["top_files"][0]["unresolved"] == 207, str(v["top_files"][:1]))


def test_lc_0_0_131_receiver_class():
    """langchain 0.0.131 (review C5): S2 override candidates are restricted to
    the receiver's static type. ``cls._validate_tools(tools)`` in ChatAgent /
    ConversationalAgent / ConversationalChatAgent resolves bare to
    ``Agent._validate_tools`` with receiver_class = the sibling class, which
    has no subclass overriding it: zero candidates, not a wall. The same
    method on receiver ``Agent`` (agent.py:379) is ``Overrides{}`` — the
    engine's own CHA. ``llm_cache.lookup`` (receiver BaseCache, 3 overrides)
    keeps its candidates.

    Review C5 policy: ``self.output_parser.parse(output)`` (agents/agent.py:176
    / :194) resolves bare to ``AgentOutputParser.parse`` — ``@abstractmethod``,
    receiver == owner, no in-tree override: an ABSTRACT stub with nothing to
    link is still a wall (the engine names a callee it cannot carry taint
    into), an UNLOWERABLE one: resolved_stub, 0 candidates, proposed, off,
    s2_reason receiver_subclass_no_overrides — and it stays in residual
    (``residual_unlowerable``). The three ``_validate_tools`` siblings call an
    EMPTY stub (``pass``) on a concrete leaf receiver: resolved, not a wall."""
    res = E.scan(os.path.join(R, "lc_0_0_131"))
    for line, fn in ((176, "plan"), (194, "aplan")):
        w = wall_at(res, "agents/agent.py", line, 15)
        check(f"lc131 C5 policy: agent.py:{line} output_parser.parse is an unlowerable wall (abstract, receiver == owner, 0 candidates)",
              w is not None and w.engine_status == "resolved_stub" and w.dispatch_targets == [] and w.accept is False
              and w.confidence == "proposed" and w.s2_reason == "receiver_subclass_no_overrides"
              and w.receiver_class == "langchain.agents.agent.AgentOutputParser" and w.target_form == "plain"
              and w.engine_targets == ["langchain.agents.agent.AgentOutputParser.parse"]
              and w.note.startswith("unlowerable: no in-tree implementation of langchain.agents.agent.AgentOutputParser.parse")
              and w.callable.endswith(f"LLMSingleActionAgent.{fn}") and w.engine_tier == "T2",
              str(w and (w.engine_status, w.accept, w.confidence, w.s2_reason, w.dispatch_targets, w.note, w.engine_tier)))
        st = res.status_at("langchain/agents/agent.py", line)
        check(f"lc131 C5 policy: the site row of agent.py:{line} is resolved_stub (not resolved)",
              st is not None and st["status"] == "resolved_stub" and st.get("s2_reason") == "receiver_subclass_no_overrides", str(st))
    check("lc131 C5 policy: the two unlowerable walls are counted (walls 33, resolved_stub 4, accepted still 2)",
          (res.counts["walls"], res.counts["by_status"].get("resolved_stub"), res.counts["accepted"]) == (33, 4, 2), str(res.counts))
    r = E.residual(os.path.join(R, "lc_0_0_131"))
    check("lc131 C5 policy: residual (no links) = the two unlowerable walls: raw 2 / net 2 / unlowerable 2 / confirmed 0",
          (r["residual_raw"], r["residual"], r["residual_unlowerable"], r["residual_confirmed"]) == (2, 2, 2, 0)
          and sorted(x["line_cond_a"] for x in r["rows"]) == [176, 194]
          and all(x["confidence"] == "proposed" and x["s2_reason"] == "receiver_subclass_no_overrides" for x in r["rows"]),
          str({k: v for k, v in r.items() if k != "rows"}))
    for f, line, cls in (("agents/chat/base.py", 95, "ChatAgent"),
                         ("agents/conversational/base.py", 105, "ConversationalAgent"),
                         ("agents/conversational_chat/base.py", 137, "ConversationalChatAgent")):
        st = res.status_at(f"langchain/{f}", line)
        check(f"lc131 C5: {f}:{line} cls._validate_tools is resolved (receiver {cls}, no overriding subclass)",
              st is not None and st["status"] == "resolved" and st.get("s2_reason") == "receiver_subclass_no_overrides"
              and st["receiver_class"].endswith("." + cls) and st["target_form"] == "plain"
              and st["targets"] == ["langchain.agents.agent.Agent._validate_tools"], str(st))
        check(f"lc131 C5: {f}:{line} has no wall row", wall_at(res, f, line) is None)
    w = wall_at(res, "llms/base.py", 30, 24)
    check("lc131 C5: BaseCache.lookup keeps the receiver's own overrides",
          w is not None and w.engine_status == "resolved_stub" and w.receiver_class == "langchain.cache.BaseCache"
          and w.target_form == "plain" and w.s2_reason == "receiver_subclasses" and w.accept
          and sorted(t.rsplit(".", 2)[-2] for t in w.dispatch_targets) == ["InMemoryCache", "RedisCache", "SQLAlchemyCache"],
          str(w and (w.receiver_class, w.s2_reason, w.dispatch_targets)))
    md = E.render_md(res)
    check("lc131 C5: receiver / form / reason rendered", "BaseCache (plain); receiver_subclasses" in md)
    # the class hierarchy behind the rule: from override-graph.json rows and ClassDef bases
    run = E.EngineRun(os.path.join(R, "lc_0_0_131"))
    h = E._ClassHierarchy(E._DefIndex(run), run.override_graph())
    check("lc131 C5: hierarchy — ZeroShotAgent < Agent (override graph), not < ChatAgent",
          h.is_subclass("langchain.agents.mrkl.base.ZeroShotAgent", "langchain.agents.agent.Agent")
          and not h.is_subclass("langchain.agents.mrkl.base.ZeroShotAgent", "langchain.agents.chat.base.ChatAgent"))
    check("lc131 C5: hierarchy — ChatAgent < Agent through its ClassDef bases (import resolved)",
          h.is_subclass("langchain.agents.chat.base.ChatAgent", "langchain.agents.agent.Agent")
          and h.is_subclass("langchain.cache.InMemoryCache", "langchain.cache.BaseCache"))
    st = res.status_at("langchain/agents/chat/base.py", 95)
    check("lc131 C5: the resolved site carries the explanation", st is not None and "no overriding subclass" in st.get("note", ""))


def test_residual_two_walls():
    """Review C1 (d): ``bench/fixtures.py::two_walls_before_stub`` — one file,
    a lowered registry wall whose block was inserted BEFORE it (its line
    shifts 14 -> 18 in cond_B) and a stub call below it. ``r_min/
    two_walls_before_stub/{cond_A,cond_B}`` are the Pysa excerpts."""
    base = os.path.join(R, "two_walls_before_stub")
    if not os.path.isdir(os.path.join(base, "cond_B", "r")):
        print("SKIP residual_two_walls: r_min/two_walls_before_stub not extracted")
        return
    ca = E.scan(os.path.join(base, "cond_A"))
    check("two_walls cond_A: the registry call is the one accepted wall (app.py:14)",
          [(w.file, w.line, w.accept) for w in ca.walls if w.accept] == [("app.py", 14, True)],
          str([(w.position, w.engine_status, w.accept) for w in ca.walls]))
    st = ca.status_at("app.py", 15)
    check("two_walls cond_A: the typed stub call is followed by the engine (Overrides{BaseParser.parse}) -> resolved",
          st is not None and st["status"] == "resolved" and st["target_form"] == "overrides"
          and st["receiver_class"] == "tools.BaseParser", str(st))
    # cond_B: the 6-line block (writeback form) sits on lines 14-19, the wall moved 14 -> 20, the stub 15 -> 21
    cb = E.scan(os.path.join(base, "cond_B"))
    gen = [s for s in cb.sites_by_file.get("app.py", []) if s["status"] == "generated"]
    check("two_walls cond_B: the sites inside the generated block are 'generated' (never walls / env gaps)",
          len(gen) == 2 and cb.counts["generated"] == 2 and sorted(s["line"] for s in gen) == [16, 18]
          and not any(w.file == "app.py" and 14 <= w.line <= 19 for w in cb.walls), str(gen))
    w = wall_at(cb, "app.py", 20)
    check("two_walls cond_B: the original wall kept by design now sits on line 20 (block inserted before it)",
          w is not None and w.engine_status == "unresolved:UnknownCallCallee" and wall_at(cb, "app.py", 14) is None)
    fx = E._FileIndex(os.path.join(base, "cond_B", "src", "app.py"))
    check("two_walls cond_B: guard block 14-19 tagged wall=app.py:14; 20 -> 14, 21 -> 15",
          [(b.start, b.end, b.wall_file, b.wall_line) for b in fx.generated] == [(14, 19, "app.py", 14)]
          and (fx.cond_a_line(20), fx.cond_a_line(21), fx.cond_a_line(16)) == (14, 15, None))
    r = E.residual(os.path.join(base, "cond_B"), links_json=os.path.join(base, "cond_B", "links.json"))
    check("two_walls residual: raw 1 / net 0 — the shifted lowered wall is mapped 20 -> 14 and netted",
          (r["residual_raw"], r["residual"], r["lowered_walls"], r["remapped"], r["generated_excluded"], r["legacy_links"])
          == (1, 0, 1, 1, 2, False), str({k: v for k, v in r.items() if k != "rows"}))
    check("two_walls residual: residual_confirmed / residual_unlowerable are reported (review C5 policy) — 0 / 0 once netted",
          (r["residual_confirmed"], r["residual_unlowerable"]) == (0, 0) and "residual_confirmed" in r and "residual_unlowerable" in r,
          str({k: v for k, v in r.items() if k != "rows"}))
    # review C1 (pin): the lowered set is keyed by the src_root-RELATIVE path, not the
    # basename. A non-legacy links.json (file carries a "/") whose wall sits in a
    # different directory with the same basename must NOT net app.py's wall — the
    # residual stays 1 with no legacy fallback. Reverting residual() to basename
    # keys (a scratch-copy mutant) fails this check while every flat-tree check passes.
    import json, tempfile
    d1 = json.load(open(os.path.join(base, "cond_B", "links.json")))
    for rec in d1["walls"] + d1["links"]:
        rec["file"] = "other/app.py"
        rec["lowered_line"] = 0
    tmp1 = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(d1, tmp1)
    tmp1.close()
    try:
        r1 = E.residual(os.path.join(base, "cond_B"), links_json=tmp1.name)
        check("two_walls residual (C1 pin): a non-legacy links.json keyed other/app.py:14 does NOT net app.py:14 (residual 1, legacy False)",
              (r1["residual"], r1["residual_raw"], r1["lowered_walls"], r1["legacy_links"]) == (1, 1, 1, False)
              and [(x["file"], x["line_cond_a"]) for x in r1["rows"]] == [("app.py", 14)],
              str({k: v for k, v in r1.items() if k != "rows"}))
        check("two_walls residual (C1 pin): the correctly keyed links.json nets it (residual 0)", r["residual"] == 0)
    finally:
        os.unlink(tmp1.name)
    check("two_walls residual: the stub call is not residual (engine follows the override; nothing to lower)",
          not any(row["line_cond_a"] == 15 for row in r["rows"]))
    # without lowered_line (a links.json written by an older pipeline) the guard-block line map alone nets it
    import json, tempfile
    d0 = json.load(open(os.path.join(base, "cond_B", "links.json")))
    for rec in d0["walls"]:
        rec["lowered_line"] = 0
    tmp0 = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(d0, tmp0)
    tmp0.close()
    try:
        r0 = E.residual(os.path.join(base, "cond_B"), links_json=tmp0.name)
        check("two_walls residual: netted through the guard-block line map alone (lowered_line absent)",
              (r0["residual"], r0["residual_raw"], r0["remapped"]) == (0, 1, 1), str({k: v for k, v in r0.items() if k != "rows"}))
    finally:
        os.unlink(tmp0.name)
    # the same links.json with the wall keyed by a bare basename (pre-C1 file) still nets it, with a warning
    import json, tempfile
    d = json.load(open(os.path.join(base, "cond_B", "links.json")))
    for rec in d["walls"] + d["links"]:
        rec["file"] = os.path.basename(rec["file"])
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(d, tmp)
    tmp.close()
    try:
        r2 = E.residual(os.path.join(base, "cond_B"), links_json=tmp.name)
        check("two_walls residual: basename-keyed (legacy) links still net a flat tree's wall",
              (r2["residual"], r2["residual_raw"]) == (0, 1))
    finally:
        os.unlink(tmp.name)


def test_c5_stub_policy_fixture():
    """Review C5 policy on a self-contained tree (synthetic call-graph.json /
    override-graph.json — no Pysa): ``Base.parse`` is ``@abstractmethod``,
    ``Base.run`` raises NotImplementedError, ``Base.validate`` is ``pass``;
    ``Leaf(Base)`` implements none of them, nothing else in the tree does.

      * ``self.p.parse`` / ``self.p.run`` (receiver Base == owner) and
        ``self.leaf.parse`` (receiver an abstract subclass): ABSTRACT stubs with
        no in-tree implementation -> unlowerable walls (resolved_stub, 0
        candidates, proposed, off, receiver_subclass_no_overrides), counted
        in ``residual_unlowerable``;
      * ``self.leaf.validate`` (EMPTY stub, concrete leaf receiver): resolved
        with the same reason — not a wall (unchanged rule);
      * review C5 policy (repair): ``self.p.render`` — ``Base.render`` is
        ``@abstractmethod`` too, but ``Impl(Base)`` implements it
        (override-graph.json ``base.Base.render -> [base.Impl]``): a LOWERABLE
        stub wall (receiver_subclasses, 1 candidate, confirmed, on). With no
        links.json it is the one ``residual_confirmed`` wall beside the three
        ``residual_unlowerable`` ones; a links.json that lowers it nets it
        (confirmed 0, unlowerable 3) — the two counters are pinned to their
        VALUES, not just their presence."""
    import json
    import shutil
    import tempfile
    tmp = tempfile.mkdtemp(prefix="ew_c5_")
    try:
        cond = os.path.join(tmp, "cond_A")
        src = os.path.join(cond, "src")
        rd = os.path.join(cond, "r")
        os.makedirs(src)
        os.makedirs(rd)
        open(os.path.join(cond, ".pyre_configuration"), "w").write('{"source_directories": ["src"]}\n')
        open(os.path.join(src, "base.py"), "w").write(
            "from abc import ABC, abstractmethod\n\n\nclass Base(ABC):\n"
            "    @abstractmethod\n    def parse(self, text):\n        \"\"\"abstract: no in-tree implementation\"\"\"\n\n"
            "    def run(self, text):\n        raise NotImplementedError\n\n"
            "    def validate(self, tools):\n        pass\n\n"
            "    @abstractmethod\n    def render(self, text):\n        \"\"\"abstract: Impl implements it\"\"\"\n\n\n"
            "class Leaf(Base):\n    pass\n\n\nclass Impl(Base):\n    def render(self, text):\n        return text\n")
        app_src = ("from base import Base, Leaf\n\n\nclass Host:\n"
                   "    def __init__(self, p: Base, leaf: Leaf):\n        self.p = p\n        self.leaf = leaf\n\n"
                   "    def go(self, text):\n        self.p.parse(text)\n        self.p.run(text)\n"
                   "        self.leaf.validate(text)\n        self.leaf.parse(text)\n        self.p.render(text)\n        return text\n")
        open(os.path.join(src, "app.py"), "w").write(app_src)
        # the engine's record of Host.go: bare (plain) targets with the receiver's static type
        tree = ast.parse(app_src)
        calls = sorted((n.lineno, n.col_offset, n.end_lineno, n.end_col_offset, ast.unparse(n.func))
                       for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute))
        target_of = {"self.p.parse": ("base.Base.parse", "base.Base"), "self.p.run": ("base.Base.run", "base.Base"),
                     "self.leaf.validate": ("base.Base.validate", "base.Leaf"), "self.leaf.parse": ("base.Base.parse", "base.Leaf"),
                     "self.p.render": ("base.Base.render", "base.Base")}
        rec_calls = {f"{l}:{c}-{el}:{ec}": {"call": {"calls": [{"target": target_of[fn][0], "index": 0, "implicit_receiver": True,
                                                                "return_type": [], "receiver_class": target_of[fn][1]}]}}
                     for l, c, el, ec, fn in calls}
        hdr = json.dumps({"file_version": 3, "config": {"repo": cond}}, separators=(",", ":"))
        j = lambda o: json.dumps(o, separators=(",", ":"))
        open(os.path.join(rd, "call-graph.json"), "w").write(hdr + "\n" + j(
            {"kind": "call_graph", "data": {"filename": "src/app.py", "callable": "app.Host.go", "calls": rec_calls}}) + "\n")
        open(os.path.join(rd, "modules.json"), "w").write(hdr + "\n" + "".join(
            j({"kind": "module", "data": {"name": m, "path": os.path.join(src, m + ".py")}}) + "\n" for m in ("app", "base")))
        open(os.path.join(rd, "functions.json"), "w").write(hdr + "\n" + "".join(
            j({"kind": "function", "data": {"name": n}}) + "\n"
            for n in ("app.Host.__init__", "app.Host.go", "base.Base.parse", "base.Base.run", "base.Base.validate",
                      "base.Base.render", "base.Impl.render")))
        open(os.path.join(rd, "taint-output.json"), "w").write(hdr + "\n" + j(
            {"kind": "model", "data": {"callable": "app.Host.go", "filename": "src/app.py", "callable_line": 9,
                                       "sources": [{"kept": True}]}}) + "\n")
        # review C5 policy (repair): the engine's override row for the one implemented abstract method
        open(os.path.join(rd, "override-graph.json"), "w").write(json.dumps({"base.Base.render": ["base.Impl"]}) + "\n")
        open(os.path.join(rd, "decorator-counts.json"), "w").write(hdr + "\n")
        open(os.path.join(rd, "higher-order-call-graph.json"), "w").write(hdr + "\n")
        line_of = {fn: l for l, _c, _el, _ec, fn in calls}
        res = E.scan(cond)
        for fn, owner_m in (("self.p.parse", "base.Base.parse"), ("self.p.run", "base.Base.run"), ("self.leaf.parse", "base.Base.parse")):
            w = wall_at(res, "app.py", line_of[fn])
            check(f"C5 policy fixture: {fn} (abstract stub, receiver {target_of[fn][1].split('.')[-1]}, no in-tree override) is an unlowerable wall",
                  w is not None and w.engine_status == "resolved_stub" and w.dispatch_targets == [] and w.accept is False
                  and w.confidence == "proposed" and w.s2_reason == "receiver_subclass_no_overrides"
                  and w.receiver_class == target_of[fn][1] and w.target_form == "plain" and w.engine_tier == "T2"
                  and w.note.startswith(f"unlowerable: no in-tree implementation of {owner_m}"),
                  str(w and (w.engine_status, w.accept, w.confidence, w.s2_reason, w.dispatch_targets, w.note, w.engine_tier)))
        st = res.status_at("app.py", line_of["self.leaf.validate"])
        check("C5 policy fixture: self.leaf.validate (EMPTY stub `pass`, concrete leaf receiver, no override) is resolved — not a wall",
              st is not None and st["status"] == "resolved" and st.get("s2_reason") == "receiver_subclass_no_overrides"
              and "no override of the stub anywhere" in st.get("note", "") and wall_at(res, "app.py", line_of["self.leaf.validate"]) is None,
              str(st))
        w = wall_at(res, "app.py", line_of["self.p.render"])
        check("C5 policy fixture (repair): self.p.render (abstract stub, receiver Base == owner, Impl implements it) is a LOWERABLE wall — 1 candidate, confirmed, on",
              w is not None and w.engine_status == "resolved_stub" and w.dispatch_targets == ["base.Impl.render"] and w.accept is True
              and w.confidence == "confirmed" and w.s2_reason == "receiver_subclasses" and w.receiver_class == "base.Base"
              and w.target_form == "plain" and w.engine_tier == "T2" and w.engine_targets == ["base.Base.render"],
              str(w and (w.engine_status, w.accept, w.confidence, w.s2_reason, w.dispatch_targets, w.note, w.engine_tier)))
        check("C5 policy fixture: the three abstract-stub walls plus the lowerable one — exactly one accepted",
              res.counts["walls"] == 4 and res.counts["accepted"] == 1 and res.counts["by_status"] == {"resolved_stub": 4}, str(res.counts))
        r = E.residual(cond)
        render_line = line_of["self.p.render"]
        check("C5 policy fixture: residual (no links) raw 4 / net 4 / unlowerable 3 / confirmed 1 — the lowerable stub is the confirmed one",
              (r["residual_raw"], r["residual"], r["residual_unlowerable"], r["residual_confirmed"]) == (4, 4, 3, 1)
              and sorted((x["line_cond_a"], x["confidence"], x["s2_reason"]) for x in r["rows"])
              == sorted([(line_of[fn], "proposed", "receiver_subclass_no_overrides") for fn in ("self.p.parse", "self.p.run", "self.leaf.parse")]
                        + [(render_line, "confirmed", "receiver_subclasses")]),
              str({k: v for k, v in r.items() if k != "rows"}) + str([(x["line_cond_a"], x["confidence"], x["s2_reason"]) for x in r["rows"]]))
        # review C5 policy (repair): a links.json that lowered the render wall nets it out of
        # BOTH the net and residual_confirmed; the unlowerable three stay (nothing lowered them)
        links_p = os.path.join(cond, "links.json")
        json.dump({"walls": [{"id": "W0", "file": "app.py", "line": render_line, "end_line": render_line,
                              "idiom": "method_call", "callee": "self.p.render"}],
                   "links": [{"id": "L0", "wall_id": "W0", "file": "app.py", "line": render_line, "status": "lowered",
                              "target": {"cls": "Impl", "name": "render", "module": "base"}}]},
                  open(links_p, "w"))
        r2 = E.residual(cond, links_json=links_p)
        check("C5 policy fixture (repair): with the render wall lowered — raw 4 / net 3 / lowered_walls 1 / confirmed 0 / unlowerable 3",
              (r2["residual_raw"], r2["residual"], r2["lowered_walls"], r2["residual_confirmed"], r2["residual_unlowerable"], r2["legacy_links"])
              == (4, 3, 1, 0, 3, False) and render_line not in [x["line_cond_a"] for x in r2["rows"]],
              str({k: v for k, v in r2.items() if k != "rows"}))
        # the classifier itself — over Base's own defs (Impl.render is the implementation, not a stub)
        base_tree = ast.parse(open(os.path.join(src, "base.py")).read())
        base_cls = next(n for n in ast.walk(base_tree) if isinstance(n, ast.ClassDef) and n.name == "Base")
        defs = {n.name: n for n in base_cls.body if isinstance(n, ast.FunctionDef)}
        impl_render = next(n for n in ast.walk(base_tree) if isinstance(n, ast.FunctionDef) and n.name == "render" and n not in base_cls.body)
        check("C5 policy fixture (repair): Impl.render has a real body — not a stub, the override row names an implementation",
              not E._def_body_trivial(impl_render)[0])
        extra = ast.parse("import abc\n\n\nclass C:\n    @abc.abstractmethod\n    def a(self):\n        ...\n\n"
                          "    def b(self):\n        raise ValueError('x')\n\n    def c(self):\n        raise NotImplementedError('x')\n\n"
                          "    def d(self):\n        'doc'\n")
        defs.update({n.name: n for n in ast.walk(extra) if isinstance(n, ast.FunctionDef)})
        kinds = {k: E._stub_kind(v) for k, v in defs.items()}
        check("C5 policy: _stub_kind — @abstractmethod / abc.abstractmethod / raise NotImplementedError(...) are abstract; pass / docstring / other raise are empty",
              kinds == {"parse": "abstract", "run": "abstract", "validate": "empty", "render": "abstract",
                        "a": "abstract", "b": "empty", "c": "abstract", "d": "empty"},
              str(kinds))
        check("C5 policy: _stub_kind only refines what _def_body_trivial accepts (every fixture def is trivial)",
              all(E._def_body_trivial(v)[0] for v in defs.values()))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_suggest_stub_boundary():
    """Review C5 policy (repair): the boundary of the unlowerable rule in
    ``_suggest``. A resolved_stub with NO dispatch target is pre-accepted
    (confirmed) unless its s2_reason is ``receiver_subclass_no_overrides``
    (destination set empty by construction); ``receiver_unknown`` (a
    typing.Protocol / untyped receiver — no override row by construction)
    stays on, its candidates come from the draft's recovery. Widening the
    rule to receiver_unknown, or dropping it, fails here."""
    def mk(status, targets, reason):
        return E.EngineWall(id="X", file="a.py", line=1, col=0, end_line=1, end_col=5, callable="a.f",
                            engine_status=status, engine_reason="r", dispatch_targets=list(targets), s2_reason=reason)
    got = {}
    for label, w in (("no_overrides", mk("resolved_stub", [], "receiver_subclass_no_overrides")),
                     ("unknown", mk("resolved_stub", [], "receiver_unknown")),
                     ("subclasses", mk("resolved_stub", ["b.C.m"], "receiver_subclasses")),
                     ("no_overrides_with_target", mk("resolved_stub", ["b.C.m"], "receiver_subclass_no_overrides")),
                     ("obscure", mk("resolved_obscure", [], ""))):
        E._suggest(w, "receiver")
        got[label] = (w.accept, w.confidence)
    check("C5 policy (repair): _suggest turns off exactly the zero-target receiver_subclass_no_overrides stub",
          got == {"no_overrides": (False, "proposed"), "unknown": (True, "confirmed"), "subclasses": (True, "confirmed"),
                  "no_overrides_with_target": (True, "confirmed"), "obscure": (True, "confirmed")}, str(got))


def test_catalog_status_views():
    """Review M4 (repair): ``env["catalog_status"]`` is the IN-REPO presence of
    each catalogue row (a functions.json name whose module prefix maps to a
    file of the tree); ``env["catalog_status_search_path"]`` is presence
    anywhere on the analysis search path (venv included). Pinned on a
    synthetic cond dir — ``two_walls_before_stub/cond_A`` plus a stub module
    OUTSIDE src recorded in modules.json / functions.json — and on two real
    excerpts (``lc_real``: the venv's langchain_core defines BaseTool.run;
    ``openmanus``: its own app.tool defines both rows). Reverting
    catalog_status to the search-path semantics ("present" if matched at all)
    fails the first and the lc_real checks."""
    import json
    import shutil
    import tempfile
    import catalog as CAT
    base = os.path.join(R, "two_walls_before_stub", "cond_A")
    tmp = tempfile.mkdtemp(prefix="ew_cat_")
    try:
        cond = os.path.join(tmp, "cond_A")
        shutil.copytree(base, cond, symlinks=False)
        venv_mod = os.path.join(tmp, "site-packages", "langchain", "tools", "base.py")    # outside the tree
        os.makedirs(os.path.dirname(venv_mod))
        open(venv_mod, "w").write("class BaseTool:\n    def run(self, x):\n        return self._run(x)\n")
        with open(os.path.join(cond, "r", "modules.json"), "a") as f:
            f.write(json.dumps({"kind": "module", "data": {"name": "langchain.tools.base", "path": venv_mod}}) + "\n")
        with open(os.path.join(cond, "r", "functions.json"), "a") as f:
            f.write(json.dumps({"kind": "function", "data": {"name": "langchain.tools.base.BaseTool.run"}}) + "\n")
            f.write(json.dumps({"kind": "function", "data": {"name": "tools.BaseTool.invoke"}}) + "\n")   # module `tools` is in-repo
        res = E.scan(cond)
        cs, sp = res.env["catalog_status"], res.env["catalog_status_search_path"]
        check("catalog_status: a row defined only by a module outside the tree is absent in-repo, present on the search path",
              cs.get("BaseTool.run") == "absent" and sp.get("BaseTool.run") == "present", str((cs.get("BaseTool.run"), sp.get("BaseTool.run"))))
        check("catalog_status: a row whose name's module prefix is an in-repo file is present in both views",
              cs.get("BaseTool.invoke") == "present" and sp.get("BaseTool.invoke") == "present", str((cs.get("BaseTool.invoke"), sp.get("BaseTool.invoke"))))
        check("catalog_status: a row nowhere in functions.json is absent in both views",
              cs.get("BaseTool.arun") == "absent" and sp.get("BaseTool.arun") == "absent")
        det = {"detected": ["langchain"], "scores": {"langchain": {"score": 40, "imports": {"langchain": 40}, "base_classes": {}, "decorators": {}}}}
        # drop the in-repo row from both views: the search-path-only run is what stale() names
        msgs = CAT.stale(det, dict(cs, **{"BaseTool.invoke": "absent"}), CAT.load(),
                         catalog_status_search_path=dict(sp, **{"BaseTool.invoke": "absent"}))
        check("catalog_status -> catalog.stale: the in-repo row keeps the catalogue fresh; without it the search-path-only row is named",
              CAT.stale(det, cs, CAT.load(), catalog_status_search_path=sp) == []
              and len(msgs) == 1 and msgs[0].startswith("langchain: none of ") and "'BaseTool.invoke'" in msgs[0]
              and msgs[0].endswith("(on the analysis search path only: ['BaseTool.run'])"), str(msgs))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    res = E.scan(os.path.join(R, "lc_real"))
    check("lc_real: BaseTool.run / arun (the venv's langchain_core) are absent in-repo, present on the search path",
          res.env["catalog_status"].get("BaseTool.run") == "absent" and res.env["catalog_status"].get("BaseTool.arun") == "absent"
          and res.env["catalog_status_search_path"].get("BaseTool.run") == "present"
          and res.env["catalog_status_search_path"].get("BaseTool.arun") == "present",
          str((res.env["catalog_status"], res.env["catalog_status_search_path"])))
    res = E.scan(os.path.join(R, "openmanus"))
    check("openmanus: its own app.tool rows are present in both views",
          res.env["catalog_status"].get("app.tool.base.BaseTool.__call__") == "present"
          and res.env["catalog_status_search_path"].get("app.tool.base.BaseTool.__call__") == "present"
          and res.env["catalog_status"].get("app.tool.tool_collection.ToolCollection.execute") == "present", str(res.env["catalog_status"]))


def test_m1_bindings():
    """Review M1 repair — ``r_min/m1_bindings`` is the Pysa 0.9.25 excerpt of a
    fixture-sized tree (``src/app.py``) with the three shapes the repair pins:

      * ``t = self.tools[name]; t.run(args); names = [t.name for t in self.tools]``
        (app.py:15, ``UnknownBaseType``): the later comprehension is its own
        scope — the receiver stays subscript-bound, a confirmed wall, not an
        env gap;
      * ``handler = resolve(name); handler(args); [handler(args) for handler in tools]``
        (app.py:23 / 24, ``UnknownIdentifierCallee``): higher_order confirmed
        outside, loop_call proposed inside the comprehension;
      * ``map(lambda h: h(args), REGISTRY.values())`` (app.py:29,
        ``UnknownIdentifierCallee``): a Name callee with NO binding in sight
        (the lambda is not a scope ``_binding_of`` knows) stays a proposed
        review row — the old unconditional ``name_call -> env`` demotion made
        it an env gap (engine_walls.scan, review M1 sub-item 3)."""
    res = E.scan(os.path.join(R, "m1_bindings"))
    check("m1: the excerpt scans clean (4 unresolved sites, 0 env gaps, outcome ok)",
          res.env["unresolved_by_reason"] == {"UnknownIdentifierCallee": 3, "UnknownBaseType": 1}
          and res.env["env_gaps"] == 0 and len(res.walls) == 4 and res.env["outcome"] == "ok",
          str((res.env["unresolved_by_reason"], res.env["env_gaps"], [w.position for w in res.walls])))
    w = wall_at(res, "app.py", 15, 8)
    check("m1: `t = self.tools[name]; t.run(args)` before a comprehension reusing t -> subscript receiver, confirmed",
          w is not None and w.engine_status == "unresolved:UnknownBaseType"
          and (w.idiom, w.receiver_binding, w.resolver, w.key_expr) == ("method_call", "subscript", "self.tools", "name")
          and w.accept and w.confidence == "confirmed" and w.aligned,
          str(w and (w.idiom, w.receiver_binding, w.resolver, w.confidence, w.accept)))
    check("m1: ... and it is not an env-gap row",
          not any(g["file"].endswith("app.py") and g["line"] == 15 for g in res.env["env_gap_rows"]))
    w = wall_at(res, "app.py", 23, 4)
    check("m1: `handler = resolve(name); handler(args)` before a comprehension reusing handler -> higher_order, confirmed",
          w is not None and (w.idiom, w.receiver_binding, w.resolver, w.key_expr) == ("higher_order", "resolver_call", "resolve", "name")
          and w.accept and w.confidence == "confirmed", str(w and (w.idiom, w.receiver_binding, w.resolver)))
    w = wall_at(res, "app.py", 24, 12)
    check("m1: the call INSIDE `[handler(args) for handler in tools]` is loop_call, proposed (anchoring)",
          w is not None and (w.idiom, w.receiver_binding, w.resolver) == ("loop_call", "loop", "iter(tools)")
          and not w.accept and w.confidence == "proposed", str(w and (w.idiom, w.receiver_binding, w.resolver)))
    w = wall_at(res, "app.py", 29, 30)
    check("m1: `lambda h: h(args)` — UnknownIdentifierCallee on a Name with no binding in sight stays a proposed row",
          w is not None and w.engine_status == "unresolved:UnknownIdentifierCallee"
          and (w.idiom, w.receiver_binding) == ("name_call", "") and not w.accept and w.confidence == "proposed"
          and "review" in w.note, str(w and (w.idiom, w.receiver_binding, w.confidence, w.note)))
    check("m1: ... and it is NOT demoted to an env gap (no UnknownIdentifierCallee env-gap row at all)",
          not any(g["reason"] == "UnknownIdentifierCallee" for g in res.env["env_gap_rows"]))


def test_tier_rules():
    """Review minor (``tier_of``): T1 means a SOURCE frame touches the call —
    the ``sources`` / ``parameter_sources`` positions of the callable's model,
    never its tito / sink summaries (they carry positions too, and a
    whole-model search made the tier depend on whether an excerpt kept them).
    Pinned on a copy of ``r_min/sk_real`` whose ``search_wrapper`` model gets
    a tito and a sink position AT the 2103 call: the tier must stay T2; a
    source position there makes it T1 (a whole-model search fails the first
    check). T3 needs the callers' records, which an excerpt does not keep:
    ``extract`` records the full tree's T2 / T3 membership in
    ``r/engine-tiers.json`` and ``scan`` unions it in — the six vector.py stub
    walls that scan T3 on ``pysa/projects/sk_real/cond_A`` are T3 on the
    excerpt only through that file, ``none`` without it; OpenManus'
    ``tool(**tool_input)`` (RESEARCH_DIRECTION: S1, T3) likewise."""
    import json
    import shutil
    import tempfile
    CALLABLE = "semantic_kernel.data.vector.VectorSearch._create_kernel_function.search_wrapper"

    def scan_with(extra: dict, drop_sidecar: bool = False):
        tmp = tempfile.mkdtemp(prefix="ew_tier_")
        try:
            cond = os.path.join(tmp, "cond_A")
            shutil.copytree(os.path.join(R, "sk_real"), cond, symlinks=False)
            if drop_sidecar:
                os.unlink(os.path.join(cond, "r", E.TIER_SIDECAR))
            p = os.path.join(cond, "r", "taint-output.json")
            out, hit = [], 0
            for line in open(p, encoding="utf-8"):
                s = line.strip().rstrip(",")
                if s and '"kind":"model"' in s and CALLABLE in s:
                    o = json.loads(s)
                    if o["data"].get("callable") == CALLABLE:
                        for k, v in extra.items():
                            o["data"].setdefault(k, []).extend(v)
                        line = json.dumps(o, separators=(",", ":")) + "\n"
                        hit += 1
                out.append(line)
            assert hit == 1, hit
            open(p, "w", encoding="utf-8").write("".join(out))
            return E.scan(cond)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    pos = {"line": 2103, "start": 35, "end": 108}
    res = scan_with({"tito": [{"port": "formal(**kwargs)", "taint": [{"kinds": [{"kind": "LocalReturn"}], "tito_positions": [pos]}]}],
                     "sinks": [{"port": "formal(**kwargs)", "taint": [{"kinds": [{"kind": "RemoteCodeExecution"}], "origin": pos}]}]})
    w = wall_at(res, "data/vector.py", 2103, 35)
    check("tier: a tito / sink position AT the call is not a source frame — 2103 stays T2 (sources-only search)",
          w is not None and w.engine_tier == "T2", str(w and w.engine_tier))
    res = scan_with({"sources": [{"port": "result", "taint": [{"kinds": [{"kind": "LLMControlled"}], "origin": pos}]}]})
    w = wall_at(res, "data/vector.py", 2103, 35)
    check("tier: a source position AT the call makes 2103 T1", w is not None and w.engine_tier == "T1", str(w and w.engine_tier))
    # T3 through the side file
    t3 = [(997, 23), (998, 19), (1015, 23), (1016, 18), (1029, 41), (1958, 15)]
    res = E.scan(os.path.join(R, "sk_real"))
    ws = [wall_at(res, "data/vector.py", l, c) for l, c in t3]
    check("tier: sk_real excerpt has r/engine-tiers.json and its six stub walls are T3 (as on the full tree)",
          res.env["tier_sidecar"] is True and all(w is not None and w.engine_tier == "T3" for w in ws),
          str([(w and w.position, w and w.engine_tier) for w in ws]))
    wa, wb = wall_at(res, "data/vector.py", 2103, 35), wall_at(res, "data/vector.py", 2130, 24)
    check("tier: the 2103 BoolOp wall is T2 / 2130 T1 with the side file too (T1 / T2 come from the kept models)",
          wa is not None and wa.engine_tier == "T2" and wb is not None and wb.engine_tier == "T1")
    res0 = scan_with({}, drop_sidecar=True)
    ws0 = [wall_at(res0, "data/vector.py", l, c) for l, c in t3]
    check("tier: without the side file the same six walls scan 'none' (T3 is not computable from an excerpt) and env says so",
          res0.env["tier_sidecar"] is False and all(w is not None and w.engine_tier == "none" for w in ws0),
          str([(w and w.position, w and w.engine_tier) for w in ws0]))
    check("tier: ... and the side file only reorders — the wall set itself is unchanged",
          sorted((w.file, w.line, w.col, w.engine_status, w.accept) for w in res.walls)
          == sorted((w.file, w.line, w.col, w.engine_status, w.accept) for w in res0.walls))
    side = E.EngineRun(os.path.join(R, "sk_real")).tier_sidecar()
    check("tier: side file shape — kind engine_tiers, the six walls' callables in 'reach', none of them in 't2'",
          side.get("kind") == "engine_tiers" and side.get("generated_by") == "engine_walls.extract"
          and {w.callable for w in ws if w} <= set(side.get("reach", []))
          and not ({w.callable for w in ws if w} & set(side.get("t2", []))), str({k: len(v) for k, v in side.items() if isinstance(v, list)}))
    check("tier: a real cond dir (no extract) has no side file",
          E.EngineRun(os.path.join(R, "two_walls_before_stub", "cond_A")).tier_sidecar() == {}
          and E.scan(os.path.join(R, "two_walls_before_stub", "cond_A")).env["tier_sidecar"] is False)
    om = E.scan(os.path.join(R, "openmanus"))
    w1 = wall_at(om, "tool/tool_collection.py", 32, 27)
    w2 = wall_at(om, "agent/toolcall.py", 189, 27)
    check("tier: openmanus tool_collection.py:32:27 `await tool(**tool_input)` and toolcall.py:189:27 are T3 through the side file",
          om.env["tier_sidecar"] is True and w1 is not None and w1.engine_tier == "T3" and w1.engine_status == "unresolved:UnknownIdentifierCallee"
          and w2 is not None and w2.engine_tier == "T3", str((w1 and w1.engine_tier, w2 and w2.engine_tier)))


def test_bench_check_engine_per_line():
    """Review minor (bench/run_bench.py:108): with a per-line ``engine``
    expectation, a detected wall line missing from the dict FAILS the fixture
    with a message — it used to fall back to the outer dict and die with a
    KeyError (leaking the temp tree). Driven directly on ``r_min/autogpt`` so
    the path is covered without ``--pyre``."""
    bench = os.path.join(HERE, "bench")
    if bench not in sys.path:
        sys.path.insert(0, bench)
    import run_bench as RBH

    class W:
        file, line = "agent.py", 277

    cond = os.path.join(R, "autogpt")
    fails = RBH.check_engine({"engine": {"999": {"status": "resolved"}}}, cond, [W()], os.path.join(cond, "src"))
    check("bench check_engine: per-line dict without the detected line -> one fail string (no KeyError)",
          len(fails) == 1 and "has no entry for line 277" in fails[0] and "['999']" in fails[0], str(fails))
    fails = RBH.check_engine({"engine": {"277": {"status": "unresolved:UnknownIdentifierCallee", "accept": True}}},
                             cond, [W()], os.path.join(cond, "src"))
    check("bench check_engine: the matching per-line entry passes", fails == [], str(fails))
    fails = RBH.check_engine({"engine": {"status": "unresolved:UnknownIdentifierCallee", "accept": False}},
                             cond, [W()], os.path.join(cond, "src"))
    check("bench check_engine: the one-dict form still compares accept", len(fails) == 1 and "accept=True, expected False" in fails[0], str(fails))


def main() -> int:
    test_sites_of()
    test_helpers()
    test_describe_call()
    test_in_repo_rel()
    test_autogpt()
    test_autogpt_cond_b_residual()
    test_lc_real_typed()
    test_lc_real_notype()
    test_sk_real()
    test_dataset_scan()
    test_lc_0_0_131_receiver_class()
    test_residual_two_walls()
    test_c5_stub_policy_fixture()
    test_suggest_stub_boundary()
    test_catalog_status_views()
    test_m1_bindings()
    test_tier_rules()
    test_bench_check_engine_per_line()
    print(f"\n{N - len(FAILS)}/{N} passed" + ("" if not FAILS else f"; FAILED: {FAILS}"))
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
