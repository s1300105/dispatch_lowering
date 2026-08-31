"""Self-contained test for dispatch_lowering.py (candidate recovery + link IR).

Run from any directory: `python3 test_registration.py`.
Fixtures are generated into a temp dir at runtime — no external files needed.
Idiom-level coverage (walls, filters, emission) lives in bench/run_bench.py.
"""
import ast, json, os, sys, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dispatch_lowering as d
import links as L

# --- fixtures written to a temp dir ---------------------------------------- #
FIX = {
    "autogpt/code_executor.py": '''\
class CodeExecutorComponent:
    @command(names=["execute_python_code"])
    async def execute_python_code(self, code: str) -> str: ...
    @command(names=["execute_python_file"])
    def execute_python_file(self, filename: str, args=None) -> str: ...
    @command(names=["execute_shell"])
    def execute_shell(self, command_line: str) -> list: ...
    @command(names=["execute_shell_popen"])
    def execute_shell_popen(self, command_line: str) -> str: ...
''',
    "autogpt/agent.py": '''\
class Agent:
    async def _execute_tool(self, tool_call):
        name = tool_call.name
        args = tool_call.arguments
        command = self._get_command(name)
        result = command(**args)
        return result
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
    # (A) legacy AutoGPT spec: detection/candidate rules of the original pass
    legacy = {"tool_decorator": "command", "dispatch_resolver_hint": "command"}
    cands = d.collect_commands(AUTOGPT, legacy)
    names = sorted(c.name for c in cands)
    check("legacy: 4 @command methods recovered", len(cands) == 4)
    check("legacy: exact method names", names == [
        "execute_python_code", "execute_python_file", "execute_shell", "execute_shell_popen"])
    check("legacy: all are class methods", all(c.cls is not None for c in cands))
    check("legacy: candidates carry module + signature",
          all(c.module == "code_executor" for c in cands)
          and next(c for c in cands if c.name == "execute_python_file").params == ["filename", "args"]
          and next(c for c in cands if c.name == "execute_python_code").is_async)
    check("legacy: tuple-unpacking compatibility", [(c, n, p) for c, n, p in cands][0][1] == "execute_python_code")
    src = open(os.path.join(AUTOGPT, "agent.py")).read()
    res = d.lower_wall_file_ex(src, cands, legacy, wall_file="agent.py")
    lowered = res.source
    check("legacy: one wall, four lowered links",
          res.stats.walls_detected == 1 and res.stats.links_lowered == 4 and res.stats.links_built == 4)
    check("legacy: guarded block with wall tag",
          "if __ctaudit_unreachable__:  # [ctaudit] resolved dynamic dispatch -> 4 targets | wall=agent.py:6" in lowered)
    check("legacy: receiver constructed, splat delivered to every parameter, writeback",
          "__ctaudit_obj = CodeExecutorComponent.__new__(CodeExecutorComponent)" in lowered
          and "__ctaudit_ret = __ctaudit_obj.execute_shell(command_line=args)  # L2" in lowered
          and "__ctaudit_obj.execute_python_file(filename=args, args=args)" in lowered
          and lowered.count("result = __ctaudit_ret") == 4)
    check("legacy: coroutine target awaited inside async wall",
          "await __ctaudit_obj.execute_python_code(" in lowered)
    check("legacy: lowered source parses", ast.parse(lowered) is not None)
    check("legacy: lowered_line points at the call",
          all(res.links[i].target.name in lowered.splitlines()[res.links[i].lowered_line - 1] for i in range(4)))
    check("legacy: precision keys keep legacy mode",
          d._coerce_spec(dict(legacy, emit="redirector"))._legacy is True)

    # (A2) redirector emission
    res_r = d.lower_wall_file_ex(src, cands, dict(legacy, emit="redirector"), wall_file="agent.py")
    check("redirector: wall calls redirectors from the synthetic module",
          "from __ctaudit_redirect import redirector_0, redirector_1, redirector_2, redirector_3" in res_r.source
          and "__ctaudit_ret = await redirector_0(code=args)" in res_r.source
          and "redirector_1(filename=args, args=args)" in res_r.source)
    check("redirector: module imports the target and constructs the receiver",
          "from code_executor import CodeExecutorComponent" in res_r.redirect_module
          and "async def redirector_0(code):" in res_r.redirect_module
          and "return await __ctaudit_obj.execute_python_code(code=code)" in res_r.redirect_module)
    check("redirector: module parses", ast.parse(res_r.redirect_module) is not None)

    # (A3) links round-trip through JSON and drive the emitter unchanged
    lp = os.path.join(root, "links.json")
    L.dump_links(lp, res.walls, res.links, res.stats)
    _w, lk = L.load_links(lp)
    res2 = d.lower_wall_file_ex(src, [], legacy, wall_file="agent.py", links=lk)
    check("links: JSON round-trip reproduces the lowering", res2.source == lowered)

    # (B) general registration recovery
    gen = {
        "tool_decorators": ["tool"],
        "register_methods": ["register", "add_tool"],
        "tool_list_names": ["tools", "TOOLS"],
        "tool_wrappers": ["Tool", "StructuredTool", "FunctionTool"],
        "registry_vars": ["REGISTRY"],
    }
    gnames = sorted(c.name for c in d.collect_candidates(GENERAL, gen))
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
    ga = sorted(c.name for c in d.collect_candidates(AUTOGPT, {"tool_decorators": ["command"]}))
    check("general-mode AutoGPT: 4 @command methods", ga == [
        "execute_python_code", "execute_python_file", "execute_shell", "execute_shell_popen"])

    # (D) trusted-registry index: static literal trusted, mutated one not
    reg = L.index_registries(GENERAL)
    check("registry index: static dict literal trusted", reg.get("REGISTRY") == frozenset({"k1", "dict_fn"}))
    open(os.path.join(GENERAL, "mut.py"), "w").write('MUT = {"a": deco_a}\nMUT["b"] = deco_b\n')
    check("registry index: mutated registry untrusted", "MUT" not in L.index_registries(GENERAL))

    # (E) review C4 / K6: the lowering stage scans the wall tree (cond_B/src, a
    # COPY of the candidate tree) next to the candidate tree — the same dict
    # literal seen through two roots must count as one binding
    copy_dir = os.path.join(root, "general_copy")
    shutil.copytree(GENERAL, copy_dir)
    check("registry index: a copied tree as a second root does not untrust the registry (K6)",
          L.index_registries([GENERAL, copy_dir]) == L.index_registries([GENERAL])
          and L.index_registries([GENERAL, copy_dir]).get("REGISTRY") == frozenset({"k1", "dict_fn"}))
    check("registry index: a copied wall FILE as an extra root counts once (K6)",
          L.index_registries([GENERAL, os.path.join(copy_dir, "wiring.py")]).get("REGISTRY") == frozenset({"k1", "dict_fn"}))
    # a genuinely different second definition (other members) still untrusts
    other = os.path.join(root, "other_pkg")
    os.makedirs(other)
    open(os.path.join(other, "reg2.py"), "w").write('REGISTRY = {"k9": never_registered}\n')
    check("registry index: a different definition under another root still untrusts",
          "REGISTRY" not in L.index_registries([GENERAL, other]))

    # (F) review C6 item 6: a relative import among BoolOp members is resolved
    # against the wall module; a target with no file under the root is a phantom
    check("relative import: level resolved against the wall module",
          L.resolve_relative_module("impl", 1, "/r/pkg/sub/walls.py", "pkg.sub.walls") == "pkg.sub.impl"
          and L.resolve_relative_module("x", 2, "/r/pkg/sub/walls.py", "pkg.sub.walls") == "pkg.x"
          and L.resolve_relative_module(None, 1, "/r/pkg/sub/__init__.py", "pkg.sub") == "pkg.sub"
          and L.resolve_relative_module("impl", 3, "/r/pkg/sub/walls.py", "pkg.sub.walls") == "")
    rel_root = os.path.join(root, "relimp")
    os.makedirs(os.path.join(rel_root, "pkg"))
    open(os.path.join(rel_root, "pkg", "__init__.py"), "w").write("")
    open(os.path.join(rel_root, "pkg", "impl.py"), "w").write("def a(x): ...\n")
    wall_src = "from .impl import a\nfrom .missing import b\n\ndef run(x, h=None):\n    f = a or b\n    f(x)\n"
    wall_path = os.path.join(rel_root, "pkg", "walls.py")
    open(wall_path, "w").write(wall_src)
    walls_r, links_r, _st = L.build_links(wall_src, wall_path, [], {"detect_boolop": True, "detect_subscript": False,
                                                                    "detect_getattr": False, "detect_higher_order": False},
                                          src_root=rel_root)
    by_name = {l.target.name: l for l in links_r}
    print("  relative-import links:", [(l.target.name, l.target.module, l.status) for l in links_r])
    check("relative import: `from .impl import a` -> module pkg.impl, lowered",
          by_name.get("a") is not None and by_name["a"].target.module == "pkg.impl" and by_name["a"].status == "lowered")
    check("relative import: `from .missing import b` -> not under src_root -> phantom",
          by_name.get("b") is not None and by_name["b"].target.module == "pkg.missing"
          and by_name["b"].status == "phantom" and not by_name["b"].target.importable)
    check("K1: WallRecord.file / DispatchLink.file are src_root-relative POSIX paths",
          walls_r and walls_r[0].file == "pkg/walls.py" and all(l.file == "pkg/walls.py" for l in links_r))
    # K4: dump_links(extra=) lands at the top level
    lp2 = os.path.join(root, "links_extra.json")
    L.dump_links(lp2, walls_r, links_r, _st, extra={"tool_version": {"combined": "abc"}})
    check("K4: dump_links(extra=) merged into the top-level JSON",
          json.load(open(lp2)).get("tool_version") == {"combined": "abc"})

    # (G) review M1 (links side): a receiver that SELECTS the callee at the call
    # site itself -- ``self.tools[name].run(args)`` (Subscript), ``getattr(o, k).m(x)``,
    # ``(a or b).m(x)`` (BoolOp) -- pinned by an engine wall_positions entry is a
    # method wall: idiom 'method_call' and is_method_wall True (the wall's
    # arguments go through the receiver's dispatch method, not the target's
    # signature). links._inline_receiver reverted to ``return False`` turned
    # them into 'higher_order' / False while every suite stayed green.
    m1_root = os.path.join(root, "m1")
    os.makedirs(os.path.join(m1_root, "pkg"))
    m1_src = ("class Agent:\n"
              "    def go(self, name, args, o, k, a, b, x):\n"
              "        r1 = self.tools[name].run(args)\n"
              "        r2 = getattr(o, k).m(x)\n"
              "        r3 = (a or b).m(x)\n"
              "        return r1, r2, r3\n")
    m1_path = os.path.join(m1_root, "pkg", "walls.py")
    open(m1_path, "w").write(m1_src)
    m1_pins = [{"at": f"pkg/walls.py:{ln}:13", "callee": c, "accept": True, "origin": "engine",
                "engine_status": "unresolved:UnknownCallCallee", "engine_tier": "T1", "confidence": "confirmed"}
               for ln, c in ((3, "self.tools[name].run"), (4, "getattr(o, k).m"), (5, "(a or b).m"))]
    m1_walls, _m1_links, m1_st = L.build_links(
        m1_src, m1_path, [], {"wall_positions": m1_pins, "detect_subscript": False, "detect_getattr": False,
                              "detect_boolop": False, "detect_higher_order": False}, src_root=m1_root)
    m1_by_line = {w.line: w for w in m1_walls}
    print("  M1 inline receivers:", [(w.line, w.callee, w.idiom, w.is_method_wall) for w in m1_walls])
    check("M1 (links): the three inline-receiver walls are matched by their engine pins (none unmatched)",
          sorted(m1_by_line) == [3, 4, 5] and m1_st.walls_unmatched == 0 and m1_st.walls_detected == 3
          and all(w.origin == "engine" for w in m1_walls))
    check("M1 (links): self.tools[name].run(args) -> idiom method_call, is_method_wall True",
          m1_by_line.get(3) is not None and m1_by_line[3].idiom == "method_call" and m1_by_line[3].is_method_wall is True)
    check("M1 (links): getattr(o, k).m(x) -> idiom method_call, is_method_wall True",
          m1_by_line.get(4) is not None and m1_by_line[4].idiom == "method_call" and m1_by_line[4].is_method_wall is True)
    check("M1 (links): (a or b).m(x) -> idiom method_call, is_method_wall True",
          m1_by_line.get(5) is not None and m1_by_line[5].idiom == "method_call" and m1_by_line[5].is_method_wall is True)
    check("M1 (links): walls_by_idiom counts the three as method_call, never higher_order",
          m1_st.walls_by_idiom.get("method_call") == 3 and "higher_order" not in m1_st.walls_by_idiom)
finally:
    shutil.rmtree(root, ignore_errors=True)

print("\nALL PASS" if ok else "\nSOME FAILED")
sys.exit(0 if ok else 1)
