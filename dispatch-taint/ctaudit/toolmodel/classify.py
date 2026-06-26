"""Classify a repo's tools into a shared :class:`RepoToolModel` (proposal §4.5.1).

Backends mirror the triage design (mock-equivalent + real-LLM, graceful fallback):

  * :class:`HeuristicClassifier` — deterministic, offline, AST-based. Gates to
    LLM-EXPOSED tools (schema method / tool base / @tool / tools path), then for
    each detects the sink op (subprocess/os.system/exec, file-write, pickle, …),
    source reads, the dangerous argument, an in-function guard, and the repo's
    aliased LLM call. Runs with no key, so the whole §5 pipeline is reproducible.
  * :class:`AnthropicClassifier` — uses the heuristic to FIND candidate tools and
    compute structural facts (qualified callable, receiver, site), then asks an
    LLM to refine the classification. Falls back per-tool on missing key / SDK /
    network error and (recall-first) NEVER drops a heuristic-flagged tool.

``get_classifier(name)`` is the factory.
"""
from __future__ import annotations

import ast
import json
import re
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import List, Optional

from .schema import LLMCallSpec, RepoToolModel, SinkSpec, SourceSpec, ToolSpec


def _callee_final_name(func: ast.AST):
    """Final callee name, unwrapping a subscripted generic.

    Handles ``TaskSuite[BankingEnvironment](...)`` (func is a ``Subscript`` whose
    ``.value`` is the real callee) as well as plain ``Name`` / ``Attribute`` callees.
    """
    if isinstance(func, ast.Subscript):     # Generic[...]  ->  unwrap to the base
        func = func.value
    if isinstance(func, ast.Attribute):
        return func.attr
    return getattr(func, "id", None)


# ---- vocabularies (the deterministic §4.5.1 layer) ------------------------ #
_SINK_CALLS = {  # final-attr/name (compared lower-cased) -> category
    "system": "code_execution", "popen": "code_execution", "run": "code_execution",
    "call": "code_execution", "check_output": "code_execution", "check_call": "code_execution",
    "spawn": "code_execution", "spawnl": "code_execution", "exec": "code_execution",
    "eval": "code_execution", "execscript": "code_execution",
    "executescript": "sql", "executemany": "sql",
    "loads": "deserialize", "load": "deserialize",
    "write_text": "file_write", "write_bytes": "file_write",
}
_DESERIALIZE_RECV = ("pickle", "yaml", "marshal", "dill")
_SOURCE_METHODS = {"read", "readlines", "read_text", "read_bytes"}
_SOURCE_BUILTINS = {"urlopen", "input"}
_HTTP_ROOTS = {"requests", "httpx", "aiohttp", "urllib", "urllib3"}
_HTTP_VERBS = {"get", "post", "request"}
_GUARD_NAMES = {
    "_check_safety", "check_safety", "safety_check", "is_safe", "is_allowed",
    "is_permitted", "validate", "validate_args", "validate_command", "sanitize",
    "sanitise", "confirm", "confirm_action", "ask_confirmation", "require_confirmation",
    "guard", "allow", "allowed", "whitelist", "is_whitelisted", "verify",
    "assert_safe", "check_command", "approve",
}
_TOOL_DECORATORS = {"tool", "function_tool", "ai_function", "openai_function", "register_tool",
                    # broadened for agent frameworks, but only SPECIFIC names — bare "command"
                    # collides with Click's @group.command(), so we leave generic @command to
                    # the LLM-discovery markers/ranking rather than the heuristic floor.
                    "register_command", "register_ability", "agent_action"}
# tool-ness gate
_SCHEMA_METHODS = {"openai_schema", "get_openai_schema", "function_schema", "tool_schema",
                   "to_openai_tool", "to_function_tool", "as_tool", "args_schema"}
_TOOL_BASES = {"BaseTool", "Tool", "FunctionTool", "StructuredTool",
               # broadened: action/agent/toolkit/skill class hierarchies (MetaGPT, SuperAGI, …)
               "Action", "BaseAction", "BaseAgent", "Agent", "Toolkit", "BaseToolkit",
               "Skill", "BaseSkill", "Ability", "BaseAbility"}
_TOOL_METHODS = {"execute", "run", "_run", "arun", "_arun", "__call__", "call",
                 "main", "invoke", "forward", "handle"}
_TOOL_PATH_PARTS = {"llm_functions", "tools", "skills", "toolkit"}

# 方向B — declarative registry of KNOWN dangerous LIBRARY tools.
# Real agents register prebuilt tools whose dangerous operation lives inside the
# library (not in user code), e.g. LangChain's PythonAstREPLTool / ShellTool.  A
# syntactic body scan of the analysed file cannot ground these, so we record the
# *known* sink semantics of the tool CLASS, keyed by its constructor name.  This is
# the same declarative-knowledge approach as the framework DispatchSpec: plain data,
# extends by appending rows, no engine change.  ``arg`` is the dangerous parameter
# name (best-effort, for the Pysa model); category drives severity.
_KNOWN_DANGEROUS_TOOLS = {
    # code / command execution
    "PythonAstREPLTool":   ("code_execution", "query"),
    "PythonREPLTool":      ("code_execution", "command"),
    "PythonREPL":          ("code_execution", "command"),
    "ShellTool":           ("code_execution", "commands"),
    "BashProcess":         ("code_execution", "command"),
    "ComputerTool":        ("code_execution", "command"),
    "TerminalTool":        ("code_execution", "command"),
    # SQL
    "QuerySQLDataBaseTool":  ("sql", "query"),
    "QuerySQLDatabaseTool":  ("sql", "query"),
    # requests / network (write side: can hit arbitrary URLs)
    "RequestsPostTool":    ("network", "url"),
    "RequestsGetTool":     ("network", "url"),
}



def _final(func: ast.AST) -> Optional[str]:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _dotted(func: ast.AST) -> str:
    parts: List[str] = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _base_name(b: ast.AST) -> str:
    return _final(b) or ""


def _module_of(path: Path, src_root: Path) -> str:
    try:
        rel = path.resolve().relative_to(src_root.resolve())
    except ValueError:
        rel = Path(path.name)
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


class HeuristicClassifier:
    name = "heuristic"

    def __init__(self, agentdojo: bool = False) -> None:
        # When True, recognise AgentDojo's plain-function domain tools as sinks /
        # sources by name (danger is domain-semantic, not syntactic), mirroring the
        # 方向B known-dangerous-tool table.  Opt-in, so the common function names
        # (create_file, send_email, …) never fire as sinks in non-AgentDojo code.
        self.agentdojo = agentdojo

    def classify(self, repo: str, src_root: Optional[str] = None) -> RepoToolModel:
        repo_p = Path(repo)
        single_file = repo_p.is_file()
        # module-name resolution needs a directory root; for a single file use its parent.
        if src_root:
            root = Path(src_root)
        else:
            root = repo_p.parent if single_file else repo_p
        tools: List[ToolSpec] = []
        llm_call: Optional[LLMCallSpec] = None

        # a single .py file target has no rglob children, so iterate it directly;
        # a directory is walked recursively as before.
        if single_file:
            py_files = [repo_p]
        else:
            py_files = sorted(repo_p.rglob("*.py"))
        for py in py_files:
            # skip vendored / test trees when walking a directory; an explicitly
            # named single file is always analyzed (the user asked for it).
            if not single_file and any(
                    part in (".venv", "site-packages", "tests", "test") for part in py.parts):
                continue
            try:
                tree = ast.parse(py.read_text(encoding="utf-8"))
            except Exception:
                continue
            module = _module_of(py, root)
            llm_call = llm_call or self._detect_llm_call(tree)
            tools.extend(self._tools_in_module(tree, module, str(py)))
        seen = {}
        for t in tools:
            # key on (name, callable): genuine duplicates share both, but two distinct
            # registered variables that wrap the SAME library tool class (e.g. shell and
            # wrapped both -> ShellTool) must each survive, since the wall's candidate is
            # the registered variable name.
            seen.setdefault((t.name, t.callable), t)
        return RepoToolModel(repo=repo_p.name, src_root=str(root),
                             tools=list(seen.values()), llm_call=llm_call)

    # -- LLM call detection (handles the aliased pattern) ------------------- #
    def _detect_llm_call(self, tree: ast.AST) -> Optional[LLMCallSpec]:
        best: Optional[LLMCallSpec] = None
        for n in ast.walk(tree):
            target = None
            if isinstance(n, ast.Call):
                target = n.func
            elif isinstance(n, ast.Assign):
                target = n.value          # e.g. completion = client.chat.completions.create
            if target is None:
                continue
            dotted = _dotted(target).lower()
            fin = (_final(target) or "").lower()
            if dotted.endswith("chat.completions.create") or dotted.endswith("completions.create"):
                return LLMCallSpec("openai._Completions.create", "messages", "openai SDK")
            if fin == "completion" and "litellm" in dotted:
                best = best or LLMCallSpec("litellm.completion", "messages", "litellm")
            if dotted.endswith("messages.create"):
                best = best or LLMCallSpec("anthropic.resources.messages.Messages.create",
                                           "messages", "anthropic SDK")
            if fin == "post" and isinstance(n, ast.Call):
                url = n.args[0] if n.args else None
                if isinstance(url, ast.Constant) and isinstance(url.value, str) and \
                   any(p in url.value for p in ("chat/completions", "/v1/messages", "/api/chat")):
                    best = best or LLMCallSpec("httpx.Client.post", "json", "HTTP provider")
        return best

    # -- tool detection with tool-ness gate --------------------------------- #
    def _tools_in_module(self, tree: ast.AST, module: str, path: str) -> List[ToolSpec]:
        out: List[ToolSpec] = []
        parts = {p.lower() for p in Path(path).parts}
        path_toolish = bool(parts & _TOOL_PATH_PARTS)
        # 項目1 support: names registered in a framework tools=[...] factory call are
        # tools by virtue of registration, even without an @tool decorator (real
        # agents pass plain functions to create_react_agent/create_agent/...).
        registered = self._framework_registered_tool_names(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if not self._is_tool_class(node, path_toolish):
                    continue
                tool_name = self._tool_name(node)
                methods = [m for m in node.body
                           if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
                # A BaseTool subclass is ONE tool; _run and _arun (sync/async) are the
                # SAME tool.  Classify each tool method, then keep a single ToolSpec per
                # resulting tool NAME (prefer a sink-bearing, then a sync method) so a
                # class defining both _run and _arun does not emit duplicate findings.
                by_name: dict = {}                       # name -> (ToolSpec, is_async)
                for m in methods:
                    if not self._is_tool_method(m):
                        continue
                    siblings = [x for x in methods if x is not m]
                    t = self._classify_fn(m, module, path, cls=node.name,
                                          default_name=tool_name, siblings=siblings)
                    if not t:
                        continue
                    is_async = isinstance(m, ast.AsyncFunctionDef)
                    cur = by_name.get(t.name)
                    if cur is None:
                        by_name[t.name] = (t, is_async)
                    else:
                        prev_t, prev_async = cur
                        prev_sink, cur_sink = prev_t.sink is not None, t.sink is not None
                        if (cur_sink and not prev_sink) or \
                           (cur_sink == prev_sink and prev_async and not is_async):
                            by_name[t.name] = (t, is_async)
                out.extend(spec for spec, _ in by_name.values())
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._is_top_level(node, tree) and (
                        self._has_tool_decorator(node) or node.name in registered):
                    t = self._classify_fn(node, module, path, cls=None,
                                          default_name=None, tool_registered=True)
                    if t:
                        out.append(t)
        # AgentDojo (opt-in): a tool registered in THIS file (e.g. in the suite's
        # TOOLS list) whose definition lives in another module is still grounded as a
        # sink/source from the declared domain tables — the sink-ness comes from the
        # name, not the body, so no cross-file definition lookup is needed.  Only emit
        # for names not already produced above (avoids duplicating same-file defs).
        if getattr(self, "agentdojo", False):
            from ..models.agentdojo import AGENTDOJO_DOMAIN_SINKS, AGENTDOJO_SOURCE_TOOLS
            have = {t.name for t in out}
            for nm in sorted(registered):
                if nm in have:
                    continue
                roles, sink, source = [], None, None
                if nm in AGENTDOJO_DOMAIN_SINKS:
                    cat, arg = AGENTDOJO_DOMAIN_SINKS[nm]
                    roles.append("sink")
                    sink = SinkSpec(category=cat, arg=arg)
                if nm in AGENTDOJO_SOURCE_TOOLS:
                    roles.append("source")
                    source = SourceSpec(capacity="string", attacker=True)
                if roles:
                    out.append(ToolSpec(
                        name=nm, callable=nm, recv=None, roles=roles,
                        sink=sink, source=source,
                        site=f"{Path(path).name}:registered:{nm}", classifier=self.name))
        # 方向B: known dangerous LIBRARY tools (PythonAstREPLTool, ShellTool, …)
        # registered in this module but whose body is library-internal.
        out.extend(self._known_library_tools(tree, module, path))
        return out

    def _known_library_tools(self, tree: ast.AST, module: str, path: str) -> List[ToolSpec]:
        """Emit ToolSpecs for variables that resolve to a KNOWN dangerous library tool.

        Resolves the common binding chains so the emitted tool *name* matches the
        wall's registered candidate (the variable the agent puts in ``tools=[...]``):

          * ``x = PythonAstREPLTool()``                       -> x is the sink tool
          * ``r = PythonAstREPLTool(); x = Tool(func=r.run)`` -> x is the sink tool
          * ``x = Tool(func=PythonAstREPLTool().run)``        -> x is the sink tool

        Only variables actually registered in a framework ``tools=[...]`` are
        emitted, so we do not flag a dangerous tool that is constructed but never
        given to an agent.
        """
        # 1) variable -> known-tool category, by resolving its constructor.
        ctor_of: dict = {}                       # var -> known tool class name
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 \
                    and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Call):
                kt = self._known_tool_of_call(n.value, ctor_of)
                if kt:
                    ctor_of[n.targets[0].id] = kt

        # 2) which variables are actually registered as tools in a factory call.
        registered = self._framework_registered_tool_names(tree)

        out: List[ToolSpec] = []
        seen = set()
        for var, klass in ctor_of.items():
            if var not in registered or var in seen:
                continue
            seen.add(var)
            cat, arg = _KNOWN_DANGEROUS_TOOLS[klass]
            out.append(ToolSpec(
                name=var, callable=klass, roles=["sink"],
                sink=SinkSpec(category=cat, arg=arg),
                site="", classifier="heuristic-known-tool"))
        return out

    def _known_tool_of_call(self, call: ast.Call, ctor_of: dict) -> Optional[str]:
        """Return the known-dangerous-tool class this call resolves to, or None.

        Handles a direct ``PythonAstREPLTool(...)`` constructor and the
        ``Tool(func=<known>.run)`` / ``Tool(func=<var bound to known>.run)`` wrapper.
        """
        fin = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", None)
        if fin in _KNOWN_DANGEROUS_TOOLS:
            return fin
        if fin in ("Tool", "StructuredTool", "from_function"):
            # find the wrapped callable (func= kwarg or a positional callable).
            cand = None
            for kw in call.keywords:
                if kw.arg == "func":
                    cand = kw.value
                    break
            if cand is None:
                for a in call.args:
                    if isinstance(a, (ast.Attribute, ast.Call, ast.Name)):
                        cand = a
                        break
            return self._known_tool_of_ref(cand, ctor_of)
        return None

    def _known_tool_of_ref(self, node: Optional[ast.AST], ctor_of: dict) -> Optional[str]:
        """Resolve a callable reference (e.g. ``python_repl.run`` or ``X().run``) to
        a known dangerous tool class, using the variable->class map when needed."""
        if node is None:
            return None
        if isinstance(node, ast.Attribute):           # <recv>.run
            recv = node.value
            if isinstance(recv, ast.Name):
                return ctor_of.get(recv.id)           # python_repl -> PythonAstREPLTool
            if isinstance(recv, ast.Call):            # PythonAstREPLTool().run
                fin = recv.func.attr if isinstance(recv.func, ast.Attribute) else getattr(recv.func, "id", None)
                return fin if fin in _KNOWN_DANGEROUS_TOOLS else None
        if isinstance(node, ast.Call):                # Tool(func=KnownTool())
            return self._known_tool_of_call(node, ctor_of)
        if isinstance(node, ast.Name):                # a var that is itself a known tool
            return ctor_of.get(node.id)
        return None

    def _framework_registered_tool_names(self, tree: ast.AST) -> set:
        """Names passed in a framework ``tools=[...]`` (or 2nd positional) registration.

        Recognises the common LangChain/LangGraph agent factories; the registered
        list's element identifiers (and ``Tool(func=f)`` wrappers) are returned so
        the corresponding top-level functions are treated as tools. This mirrors the
        engine's DispatchSpec candidate extraction, kept dependency-free here.

        When AgentDojo mode is on, also recognise ``FunctionsRuntime(TOOLS)`` and
        ``TaskSuite(name, Env, [make_function(t) for t in TOOLS])`` so the plain
        functions registered into the AgentDojo runtime are treated as tools.
        """
        factories = {"create_react_agent", "create_agent", "create_tool_calling_agent",
                     "AgentExecutor", "ToolNode"}
        names: set = set()

        def _elem(n: ast.AST):
            if isinstance(n, ast.Name):
                return n.id
            if isinstance(n, ast.Attribute):
                return n.attr
            if isinstance(n, ast.Call):
                fin = _callee_final_name(n.func)
                if fin in ("Tool", "StructuredTool", "from_function"):
                    for kw in n.keywords:
                        if kw.arg == "func":
                            return _elem(kw.value)
                    for a in n.args:
                        if isinstance(a, (ast.Name, ast.Attribute)):
                            return _elem(a)
                return fin
            return None

        # map variable -> list-literal element names, for tools=<var>.
        list_bindings = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 \
                    and isinstance(n.targets[0], ast.Name) \
                    and isinstance(n.value, (ast.List, ast.Tuple, ast.Set)):
                list_bindings[n.targets[0].id] = [e for e in (_elem(x) for x in n.value.elts) if e]

        def _collect(arg):
            if isinstance(arg, (ast.List, ast.Tuple, ast.Set)):
                for e in arg.elts:
                    nm = _elem(e)
                    if nm:
                        names.add(nm)
            elif isinstance(arg, ast.Name):
                names.update(list_bindings.get(arg.id, []))

        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                fin = _callee_final_name(n.func)
                if fin in factories:
                    for kw in n.keywords:
                        if kw.arg == "tools":
                            _collect(kw.value)
                    if len(n.args) >= 2:        # create_react_agent(model, tools, ...)
                        _collect(n.args[1])

        # AgentDojo (opt-in): FunctionsRuntime(TOOLS) / TaskSuite(name, Env, [...]).
        if getattr(self, "agentdojo", False):
            ad_factories = {"FunctionsRuntime", "TaskSuite"}

            def _collect_ad(arg):
                # list / tuple / set literal, or a Name bound to one
                _collect(arg)
                # comprehension: [make_function(t) for t in TOOLS] -> resolve TOOLS
                if isinstance(arg, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                    for gen in arg.generators:
                        it = gen.iter
                        if isinstance(it, ast.Name):
                            names.update(list_bindings.get(it.id, []))
                        elif isinstance(it, (ast.List, ast.Tuple, ast.Set)):
                            for e in it.elts:
                                nm = _elem(e)
                                if nm:
                                    names.add(nm)

            for n in ast.walk(tree):
                if isinstance(n, ast.Call):
                    fin = _callee_final_name(n.func)
                    if fin in ad_factories:
                        for a in n.args:          # tools may be any positional arg
                            _collect_ad(a)
                        for kw in n.keywords:
                            if kw.arg in ("functions", "tools"):
                                _collect_ad(kw.value)
        return names

    @staticmethod
    def _is_top_level(fn, tree) -> bool:
        return fn in getattr(tree, "body", [])

    def _is_tool_class(self, cls: ast.ClassDef, path_toolish: bool) -> bool:
        if path_toolish:
            return True
        method_names = {m.name for m in cls.body
                        if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
        if method_names & _SCHEMA_METHODS:
            return True
        if {_base_name(b) for b in cls.bases} & _TOOL_BASES:
            return True
        return any(isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and self._has_tool_decorator(m)
                   for m in cls.body)

    def _is_tool_method(self, m) -> bool:
        return m.name in _TOOL_METHODS or self._has_tool_decorator(m)

    def _has_tool_decorator(self, fn) -> bool:
        for d in fn.decorator_list:
            # unwrap a parameterized decorator: @command('name', ...) -> callee `command`
            target = d.func if isinstance(d, ast.Call) else d
            nm = (_final(target) or "").lower()
            if nm in _TOOL_DECORATORS:
                return True
        return False

    @staticmethod
    def _tool_name(cls: ast.ClassDef) -> Optional[str]:
        # 1) a `name` property/method returning a string constant (e.g. termwise BaseTool)
        for m in cls.body:
            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name == "name":
                for n in ast.walk(m):
                    if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant) \
                       and isinstance(n.value.value, str):
                        return n.value.value
        # 2) a class-level `name = "..."` / `name: str = "..."`
        for m in cls.body:
            if isinstance(m, ast.Assign):
                for tgt in m.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == "name" and \
                       isinstance(m.value, ast.Constant) and isinstance(m.value.value, str):
                        return m.value.value
            if isinstance(m, ast.AnnAssign) and isinstance(m.target, ast.Name) \
               and m.target.id == "name" and isinstance(m.value, ast.Constant) \
               and isinstance(m.value.value, str):
                return m.value.value
        # 3) a dict literal {"name": "..."} (e.g. openai_schema in shell_gpt)
        for n in ast.walk(cls):
            if isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if isinstance(k, ast.Constant) and k.value == "name" and \
                       isinstance(v, ast.Constant) and isinstance(v.value, str):
                        return v.value
        return None

    def _decorators(self, fn) -> List[str]:
        return [_final(d) or "" for d in fn.decorator_list]

    def _signals(self, fn) -> dict:
        """Walk one function; return its sink/source/guard/file-IO signals."""
        params = [a.arg for a in fn.args.args]
        real_params = [p for p in params if p not in ("self", "cls")]
        real_params += [a.arg for a in fn.args.kwonlyargs]
        kwarg = fn.args.kwarg.arg if fn.args.kwarg else None
        kw_map = {}
        if kwarg:
            for n in ast.walk(fn):
                if isinstance(n, ast.Assign) and len(n.targets) == 1 and \
                   isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Call) and \
                   _final(n.value.func) == "get" and isinstance(n.value.func, ast.Attribute) and \
                   isinstance(n.value.func.value, ast.Name) and n.value.func.value.id == kwarg and \
                   n.value.args and isinstance(n.value.args[0], ast.Constant) and \
                   isinstance(n.value.args[0].value, str):
                    kw_map[n.targets[0].id] = n.value.args[0].value

        sig = dict(sink_cat=None, sink_arg=None, sink_line=None, is_source=False,
                   returns_value=False, guard=None, sink_arg_reaches=None,
                   source_external=False)
        open_seen = False; open_path = None; open_line = None
        explicit_write = False; read_open = False; write_call = False; write_arg = None
        sink_call = None        # the AST Call chosen as the sink (for arg-reachability)

        for n in ast.walk(fn):
            if isinstance(n, ast.Return) and n.value is not None:
                sig["returns_value"] = True
            if not isinstance(n, ast.Call):
                continue
            fin = _final(n.func) or ""
            finl = fin.lower()
            dotted = _dotted(n.func)
            root = dotted.split(".")[0].lower()
            cat = None
            if finl in _SINK_CALLS:
                cat = _SINK_CALLS[finl]
                if cat == "deserialize" and root not in _DESERIALIZE_RECV:
                    cat = None
                if cat == "sql" and not any(h in dotted.lower()
                                            for h in ("cursor", "conn", "db", "session")):
                    cat = None
                if cat == "code_execution" and finl in ("run", "call", "load") \
                   and root not in ("subprocess", "os", "pty", "sh", "commands", "asyncio"):
                    cat = None
            if finl == "open":
                open_seen = True
                open_line = open_line or getattr(n, "lineno", None)
                open_path = open_path or self._danger_arg(n, real_params, kw_map)
                mode = n.args[1] if len(n.args) >= 2 else None
                if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
                    if any(c in mode.value for c in "wax"):
                        explicit_write = True
                    elif "r" in mode.value:
                        read_open = True
                elif mode is None:
                    read_open = True
            if finl in ("write", "writelines"):
                write_call = True
                write_arg = write_arg or self._danger_arg(n, real_params, kw_map)
            if any(isinstance(k, ast.keyword) and k.arg == "shell" and
                   isinstance(k.value, ast.Constant) and k.value.value is True
                   for k in n.keywords):
                cat = cat or "code_execution"
            if cat and sig["sink_cat"] is None:
                sig["sink_cat"] = cat
                sig["sink_line"] = getattr(n, "lineno", None)
                sig["sink_arg"] = self._danger_arg(n, real_params, kw_map)
                sink_call = n
            if finl in _SOURCE_METHODS or finl in _SOURCE_BUILTINS:
                sig["is_source"] = True
                sig["source_external"] = True       # reads external/untrusted data
            elif finl in _HTTP_VERBS and root in _HTTP_ROOTS:
                sig["is_source"] = True
                sig["source_external"] = True       # network fetch -> attacker can seed
            if finl in _GUARD_NAMES:
                sig["guard"] = sig["guard"] or fin

        if sig["sink_cat"] is None and (explicit_write or (open_seen and write_call)):
            sig["sink_cat"] = "file_write"
            sig["sink_line"] = open_line or sig["sink_line"]
            sig["sink_arg"] = write_arg or open_path
        if read_open and not (explicit_write or write_call):
            sig["is_source"] = True
            sig["source_external"] = True           # reads a file -> external data
        if sig["guard"] and sig["sink_line"] is not None:
            sig["guard"] = self._guard_line(fn, sig["sink_line"])
        if sig["sink_cat"] in ("code_execution", "file") and sig["returns_value"]:
            sig["is_source"] = True
        # 方向C: does a parameter actually REACH the dangerous call's argument?
        # Recall-safe: this only refines confidence; it never drops the sink.
        if sig["sink_cat"] is not None and sink_call is not None and real_params:
            verdict, reaching = self._arg_reaches(fn, real_params, sink_call)
            sig["sink_arg_reaches"] = verdict          # "reaches" | "not" | "unknown"
            if verdict == "reaches" and reaching:
                sig["sink_arg"] = reaching              # the param that provably reaches
        return sig

    @staticmethod
    def _arg_reaches(fn, params: List[str], sink_call: ast.Call):
        """Intra-function taint: does any parameter flow to ``sink_call``'s arguments?

        Returns ``(verdict, reaching_param)`` where verdict is:
          * ``"reaches"``  — a parameter provably flows into a dangerous argument
                             (directly, or through simple ``y = <tainted expr>``
                             assignments / f-strings / concatenations / containers).
          * ``"not"``      — NO parameter flows to ANY argument, and every argument is
                             built only from constants / non-parameter names
                             (provably clean — the over-approximation case).
          * ``"unknown"``  — flow could not be decided (e.g. the value passes through
                             a call, attribute, comprehension, subscript-of-param, or
                             an unresolved name); kept conservatively as a sink.

        Recall-safety: anything not clearly clean falls into ``"unknown"`` (kept), and
        the verdict NEVER removes a sink — the caller only uses it to lower severity.
        """
        # 1) compute the set of names tainted by a parameter (fixpoint over assigns).
        #    ``tainted`` = provably parameter-derived; ``unknown`` = possibly derived
        #    (e.g. assigned from a call result) — must NOT be treated as clean.
        tainted = set(params)
        unknown = set()

        def expr_taint(node) -> str:
            """'tainted' | 'clean' | 'unknown' for an expression w.r.t. params."""
            if node is None:
                return "clean"
            if isinstance(node, ast.Name):
                if node.id in tainted:
                    return "tainted"
                if node.id in unknown:
                    return "unknown"
                return "clean"
            if isinstance(node, ast.Constant):
                return "clean"
            if isinstance(node, ast.JoinedStr):        # f-string
                vs = [expr_taint(v.value) if isinstance(v, ast.FormattedValue) else "clean"
                      for v in node.values]
                return "tainted" if "tainted" in vs else ("unknown" if "unknown" in vs else "clean")
            if isinstance(node, ast.BinOp):            # a + b, "x" % p, etc.
                l, r = expr_taint(node.left), expr_taint(node.right)
                if "tainted" in (l, r):
                    return "tainted"
                return "unknown" if "unknown" in (l, r) else "clean"
            if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                vs = [expr_taint(e) for e in node.elts]
                if "tainted" in vs:
                    return "tainted"
                return "unknown" if "unknown" in vs else "clean"
            if isinstance(node, ast.Subscript):
                # base[key]: the result is the VALUE stored in base, not the key.
                # Using a parameter only as a key does NOT flow the parameter's value
                # into the result, so the result is clean w.r.t. the parameter unless
                # the BASE itself is parameter-derived (e.g. param[...] slices param).
                b = expr_taint(node.value)
                if b == "tainted":
                    return "tainted"
                if b == "unknown":
                    return "unknown"
                return "clean"
            if isinstance(node, ast.Starred):
                return expr_taint(node.value)
            # calls / attributes / comprehensions: a parameter passed in here may flow
            # into the result, so we cannot prove cleanliness -> unknown.
            return "unknown"

        # fixpoint: propagate taint/unknown through ``target = value`` assignments.
        changed = True
        passes = 0
        while changed and passes < 6:
            changed = False
            passes += 1
            for n in ast.walk(fn):
                if isinstance(n, ast.Assign) and len(n.targets) == 1 \
                        and isinstance(n.targets[0], ast.Name):
                    tgt = n.targets[0].id
                    v = expr_taint(n.value)
                    if v == "tainted" and tgt not in tainted:
                        tainted.add(tgt)
                        unknown.discard(tgt)
                        changed = True
                    elif v == "unknown" and tgt not in tainted and tgt not in unknown:
                        unknown.add(tgt)
                        changed = True

        # 2) classify the sink call's arguments.
        args = list(sink_call.args) + [k.value for k in sink_call.keywords]
        # ignore a literal shell=True style flag (handled separately as the trigger)
        verdicts = [expr_taint(a) for a in args]
        if "tainted" in verdicts:
            # find the reaching parameter (best-effort: a direct Name arg in params).
            reaching = None
            for a in args:
                if isinstance(a, ast.Name) and a.id in params:
                    reaching = a.id
                    break
            return "reaches", reaching
        if all(v == "clean" for v in verdicts):
            return "not", None
        return "unknown", None

    def _classify_fn(self, fn, module: str, path: str, cls: Optional[str],
                     default_name: Optional[str], siblings=(),
                     tool_registered: bool = False) -> Optional[ToolSpec]:
        decos = [d.lower() for d in self._decorators(fn)]
        params = [a.arg for a in fn.args.args]
        recv = None
        if cls is not None:
            if "classmethod" in decos:
                recv = "cls"
            elif "staticmethod" in decos:
                recv = None
            elif params and params[0] in ("self", "cls"):
                recv = params[0]

        # aggregate signals across the tool method AND its sibling methods (a tool's
        # capability often lives in helpers the tool method delegates to)
        prim = self._signals(fn)
        sigs = [prim] + [self._signals(s) for s in siblings]
        chosen = prim if prim["sink_cat"] else next((s for s in sigs if s["sink_cat"]), prim)
        sink_cat = chosen["sink_cat"]
        sink_arg = chosen["sink_arg"]
        guard = chosen["guard"]
        arg_reaches = chosen.get("sink_arg_reaches")
        is_source = any(s["is_source"] for s in sigs)
        # a source is attacker-influenced when it reads EXTERNAL/untrusted data
        # (HTTP fetch, file read, stdin). Source/sink GROUNDING for real targets is
        # done in Pysa's .pysa models (the data layer); this classifier feeds the
        # control-dependency / dispatch layer.
        source_external = any(s.get("source_external") for s in sigs)
        source_attacker = is_source

        # AgentDojo (opt-in): domain tools carry no syntactic sink in their body
        # (they only mutate simulated state), so recognise them by name from the
        # declared domain tables — a 方向B-style declarative grounding.
        if getattr(self, "agentdojo", False):
            fn_name = self._deco_name(fn) or fn.name
            from ..models.agentdojo import AGENTDOJO_DOMAIN_SINKS, AGENTDOJO_SOURCE_TOOLS
            if not sink_cat and fn_name in AGENTDOJO_DOMAIN_SINKS:
                cat, arg = AGENTDOJO_DOMAIN_SINKS[fn_name]
                sink_cat, sink_arg = cat, arg
            if fn_name in AGENTDOJO_SOURCE_TOOLS:
                is_source = True
                source_attacker = True   # AgentDojo source tools are declared attacker-facing

        roles = []
        if sink_cat:
            roles.append("sink")
        if is_source:
            roles.append("source")
        if not roles:
            return None

        name = default_name or self._deco_name(fn) or fn.name
        callable_q = module + "." + (f"{cls}." if cls else "") + fn.name
        return ToolSpec(
            name=name, callable=callable_q, recv=recv, roles=roles,
            sink=SinkSpec(category=sink_cat, arg=sink_arg, guard=guard,
                          arg_reaches=arg_reaches) if sink_cat else None,
            source=SourceSpec(capacity="string", attacker=source_attacker) if "source" in roles else None,
            site=f"{Path(path).name}:{getattr(fn, 'lineno', '?')}",
            classifier=self.name,
        )

    @staticmethod
    def _danger_arg(call: ast.Call, params: List[str], kw_map: Optional[dict] = None) -> Optional[str]:
        kw_map = kw_map or {}

        def resolve(nm: str) -> Optional[str]:
            if nm in params:
                return nm
            if nm in kw_map:
                return kw_map[nm]
            return None

        for a in call.args:
            if isinstance(a, ast.Name):
                r = resolve(a.id)
                if r:
                    return r
            if isinstance(a, ast.Starred) and isinstance(a.value, ast.Name):
                r = resolve(a.value.id)
                if r:
                    return r
        for k in call.keywords:
            if isinstance(k.value, ast.Name):
                r = resolve(k.value.id)
                if r:
                    return r
        return params[0] if params else None

    @staticmethod
    def _guard_line(fn, sink_line: int) -> Optional[str]:
        for n in ast.walk(fn):
            if isinstance(n, ast.Call):
                ln = getattr(n, "lineno", None)
                fin = (_final(n.func) or "")
                if ln is not None and ln < sink_line and fin.lower() in _GUARD_NAMES:
                    return fin
        return None

    def _deco_name(self, fn) -> Optional[str]:
        for d in fn.decorator_list:
            if isinstance(d, ast.Call):
                for k in d.keywords:
                    if k.arg == "name" and isinstance(k.value, ast.Constant):
                        return str(k.value.value)
        return None


def _norm(name: str) -> str:
    return (name or "").strip().lower()


def _first_json_object(text: str) -> str:
    """Return the first balanced ``{...}`` object in ``text``.

    LLMs often emit the JSON then append prose or a second block; ``json.loads``
    then fails with "Extra data". A string-aware brace-depth scan from the first
    ``{`` returns just the first complete object and ignores anything after it.
    """
    start = text.find("{")
    if start == -1:
        return text
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
    return text[start:]


_ENUM_OPS = {"walk", "listdir", "scandir", "glob", "iglob", "rglob", "iterdir"}
_GENERIC_TOOL_FN = {"execute", "run", "_run", "arun", "_arun", "call", "__call__",
                    "handle", "main", "invoke", "forward", "step", "__main__"}
# final-segment names / receiver hints that look like a real LLM SDK call. Used to
# reject an LLM-claimed llm_call that is actually an internal helper (e.g. a prompt
# builder or a tool dispatcher) — a mis-identified join@LLM node would corrupt leg (a).
_LLM_CALL_NAMES = {"create", "acreate", "invoke", "ainvoke", "complete", "completion",
                   "completions", "chat", "generate", "agenerate", "predict", "apredict",
                   "responses", "stream", "messages", "chatcompletion"}
_LLM_CALL_HINTS = ("completion", "messages", "chat", "invoke", "generate", "responses")


def _plausible_llm_call(spec) -> bool:
    if spec is None or not getattr(spec, "callable", None):
        return False
    low = spec.callable.lower()
    final = low.replace("(", "").split(".")[-1]
    return final in _LLM_CALL_NAMES or any(h in low for h in _LLM_CALL_HINTS)


def _callee_names(fn) -> set:
    names = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            f = _final(n.func)
            if f:
                names.add(f)
    return names


class LLMToolClassifier:
    """LLM-assisted classifier with a **discovery** pass (proposal §4.5.1, part b).

    The naive "LLM refines the heuristic's hits" design inherits the heuristic's
    recall hole: if the heuristic finds no tools (e.g. a dict-registry of
    top-level functions), there is nothing to refine. So this classifier runs a
    *discovery* pass — it shows the LLM the repo's likely registry/tool files (and
    the local modules they import, where sink bodies + cross-layer guards live) and
    asks it to ENUMERATE and classify the tools — then takes the **union** with the
    heuristic (recall-first: the LLM only adds tools/roles, never prunes).

    The LLM transport is injected as ``complete(system, user) -> str`` so the
    discovery+merge logic is testable without a network (see tests + the replay
    transport used by the benchmark).
    """

    name = "llm"
    DISCOVERY_SYSTEM = (
        "You audit an LLM agent for cross-tool implicit flows (CWE-1426). Given "
        "source files defining the agent's TOOL REGISTRY (tools the model can call "
        "by name) and their implementations, ENUMERATE every LLM-callable tool and "
        "classify each. A tool is a SOURCE if its output is attacker-influenceable "
        "and returns to the model; a SINK if it performs a dangerous action driven "
        "by an argument. For a sink give category "
        "(code_execution|sql|network|file_write|deserialize), the dangerous argument "
        "name, and any guard validating it — the guard MAY live in a dispatcher or "
        "wrapper rather than the tool body (report its function name). Tools may be "
        "methods of tool classes, top-level functions, or entries in a registry dict "
        "dispatched centrally. Exclude pure control-flow tools (no I/O). Respond with "
        'ONLY JSON: {"tools":[{"name":str,"callable":str|null,"recv":"self"|"cls"|null,'
        '"roles":[...],"sink":{"category":str,"arg":str|null,"guard":str|null}|null,'
        '"source":{"capacity":str,"attacker":bool}|null}],'
        '"llm_call":{"callable":str,"prompt_arg":str}|null}.'
    )
    _MARKERS = ("TOOL_SCHEMAS", "_ALL_TOOLS", "register_tool", "def run_tool",
                "openai_schema", "BaseTool", "@tool",
                # broadened for class/registry-style frameworks
                "@command", "@ability", "CommandRegistry", "ToolRegistry", "AbilityRegistry",
                "command_registry", "register_command", "class Action", "BaseAction",
                "function_tool", "Toolkit", "@function_tool")
    _REGISTRY_FILENAMES = {"tools.py", "functions.py", "registry.py",
                           "executor.py", "commands.py", "toolkit.py",
                           "command_registry.py", "abilities.py", "actions.py",
                           "skills.py", "tool.py", "command.py"}

    def __init__(self, complete=None, model: Optional[str] = None, ground: bool = True) -> None:
        self.model = model or os.environ.get("CTAUDIT_TRIAGE_MODEL", "claude-sonnet-4-5-20250929")
        self._heur = HeuristicClassifier()
        self._complete = complete            # callable(system, user) -> str, or None
        self.ground = ground                 # deterministic recall-first grounding post-filter

    def classify(self, repo: str, src_root: Optional[str] = None) -> RepoToolModel:
        self._cur_src_root = src_root or repo
        base = self._heur.classify(repo, src_root)     # recall-first heuristic floor
        if self._complete is None:
            for t in base.tools:
                t.classifier = (t.classifier or "heuristic") + " (LLM unavailable)"
            return base
        try:
            disc = self._discover(repo, src_root)
        except Exception as exc:
            # make the failure visible (auth error, wrong endpoint, parse error, …)
            # instead of silently looking like the LLM "did nothing".
            sys.stderr.write(
                f"[ctaudit.toolmodel] LLM discovery failed for {Path(repo).name}: "
                f"{type(exc).__name__}: {exc}\n"
                f"[ctaudit.toolmodel] -> falling back to the heuristic floor for this repo.\n")
            disc = None
        if disc is None:
            return base                                # never below the heuristic floor
        merged = self._merge(base, disc)
        if self.ground:
            merged = self._ground(merged, repo)        # drop LLM roles not backed by real I/O
            merged = self._trace_guards(merged, repo)   # deterministic cross-layer guard tracing
            merged = self._fill_provenance(merged, repo)  # deterministic callable / site (feeds leg a)
        return merged

    # -- discovery ---------------------------------------------------------- #
    # discovery file budget — bounded, but ranked so big repos keep their tool-dense files.
    # Kept conservative: a too-large blob can exceed the LLM context/token limit and make the
    # whole discovery call fail (which would silently fall back to the heuristic floor).
    _MAX_PRIMARY = 10        # top-ranked toolish files fed to the LLM
    _MAX_EXTRA = 4           # local modules they import (sink bodies / guards)

    def _file_score(self, py: Path, txt: str) -> int:
        """Relevance of a file as a tool carrier (higher = more likely to define tools)."""
        parts = {p.lower() for p in py.parts}
        score = 0
        if parts & _TOOL_PATH_PARTS:
            score += 4
        if py.name in self._REGISTRY_FILENAMES:
            score += 4
        score += sum(txt.count(m) for m in self._MARKERS)          # marker density
        score += 2 * len(re.findall(r"@(?:tool|function_tool|command|ability)\b", txt))
        score += len(re.findall(r"\bclass\s+\w+\([^)]*(?:Tool|Action|Agent|Toolkit|Skill|Ability)",
                                txt))
        return score

    def _candidate_files(self, repo: Path) -> List[Path]:
        scored: List[tuple] = []
        for py in sorted(repo.rglob("*.py")):
            if any(part in (".venv", "site-packages", "tests", "test", "node_modules")
                   for part in py.parts):
                continue
            try:
                txt = py.read_text(encoding="utf-8")
            except Exception:
                continue
            s = self._file_score(py, txt)
            if s > 0:
                scored.append((s, py))
        # rank by relevance (then path for determinism) and keep the top primaries — this is
        # what makes discovery on a 1000+ file repo behave like a small one: the tool-dense
        # files survive the budget instead of being cut blindly.
        scored.sort(key=lambda sp: (-sp[0], str(sp[1])))
        cands = [py for _, py in scored[:self._MAX_PRIMARY]]
        # pull local modules imported by the candidates (sink bodies / guards live there)
        imported = set()
        for py in cands:
            try:
                tree = ast.parse(py.read_text(encoding="utf-8"))
            except Exception:
                continue
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    for a in n.names:
                        imported.add(a.name.split(".")[0])
                elif isinstance(n, ast.ImportFrom) and n.module:
                    imported.add(n.module.split(".")[0])
        extra = [py for py in sorted(repo.rglob("*.py"))
                 if py.stem in imported and py not in cands
                 and not any(part in (".venv", "site-packages") for part in py.parts)]
        return cands + extra[:self._MAX_EXTRA]

    def _discover(self, repo: str, src_root: Optional[str]) -> Optional[RepoToolModel]:
        repo_p = Path(repo)
        files = self._candidate_files(repo_p)
        if not files:
            return None
        blob = []
        for p in files:
            try:
                blob.append(f"# FILE: {p.name}\n{p.read_text(encoding='utf-8')[:4500]}")
            except Exception:
                continue
        user = f"REPO: {repo_p.name}\n\n" + "\n\n".join(blob)
        text = (self._complete(self.DISCOVERY_SYSTEM, user[:24000]) or "").strip()
        if text.startswith("```"):
            text = text.strip("`")
        text = _first_json_object(text)   # tolerate fences / labels / trailing prose / extra blocks
        data = json.loads(text)
        tools = []
        for t in data.get("tools", []):
            sk = t.get("sink")
            sr = t.get("source")
            sink = None
            if sk and sk.get("category"):
                sink = SinkSpec(category=sk["category"], arg=sk.get("arg"), guard=sk.get("guard"))
            source = None
            if sr:
                source = SourceSpec(capacity=sr.get("capacity", "string"),
                                    attacker=bool(sr.get("attacker", True)))
            tools.append(ToolSpec(
                name=t["name"], callable=t.get("callable"), recv=t.get("recv"),
                roles=t.get("roles", []), sink=sink, source=source,
                site=t.get("site", ""), classifier="llm-discovered"))
        lc = data.get("llm_call")
        llm_call = LLMCallSpec(callable=lc["callable"], prompt_arg=lc.get("prompt_arg", "messages")) \
            if lc and lc.get("callable") else None
        return RepoToolModel(repo=repo_p.name, src_root=str(src_root or repo), tools=tools,
                             llm_call=llm_call)

    @staticmethod
    def _merge(base: RepoToolModel, disc: RepoToolModel) -> RepoToolModel:
        by = {_norm(t.name): t for t in base.tools}      # heuristic floor preserved
        for d in disc.tools:
            if not d.roles:
                continue
            k = _norm(d.name)
            if k not in by:
                by[k] = d                                 # tool the heuristic MISSED
            else:                                          # union, recall-first
                t = by[k]
                t.roles = sorted(set(t.roles) | set(d.roles))
                if not t.sink and d.sink:
                    # adopt the category/arg the LLM found, but NOT its (unverified)
                    # guard claim — guards are set only by deterministic analysis.
                    t.sink = SinkSpec(category=d.sink.category, arg=d.sink.arg,
                                      capacity=d.sink.capacity, guard=None)
                if not t.source and d.source:
                    t.source = d.source
        # llm_call: prefer the heuristic's deterministic detection; only accept the
        # LLM's claim if it actually looks like an LLM SDK call (never a helper name).
        llm_call = base.llm_call or (disc.llm_call if _plausible_llm_call(disc.llm_call) else None)
        return RepoToolModel(repo=base.repo, src_root=base.src_root,
                             tools=list(by.values()), llm_call=llm_call)

    # -- grounding (recall-first precision filter) -------------------------- #
    def _index_functions(self, repo: Path, src_root=None):
        root = Path(src_root or getattr(self, "_cur_src_root", None) or repo)
        funcs = defaultdict(list)   # normalised name -> [FunctionDef]
        all_fns = []

        def index(node, prefix):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    index(child, prefix + child.name + ".")
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    child._ct_qual = prefix + child.name      # e.g. "write_file" | "ShellTool.execute"
                    child._ct_mod = mod
                    child._ct_file = str(py)
                    funcs[child.name.lstrip("_")].append(child)
                    all_fns.append(child)
                    index(child, prefix)                      # nested defs (rare)

        for py in sorted(repo.rglob("*.py")):
            if any(p in (".venv", "site-packages", "tests", "test") for p in py.parts):
                continue
            try:
                tree = ast.parse(py.read_text(encoding="utf-8"))
            except Exception:
                continue
            try:
                rel = py.resolve().relative_to(root.resolve())
                mod = ".".join(rel.with_suffix("").parts)
            except Exception:
                mod = py.stem
            index(tree, "")
        return funcs, all_fns

    def _fn_sink_io(self, fn) -> bool:
        return self._heur._signals(fn)["sink_cat"] is not None

    def _fn_source_io(self, fn) -> bool:
        if self._heur._signals(fn)["is_source"]:
            return True
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and (_final(n.func) or "").lower() in _ENUM_OPS:
                return True
        return False

    def _reaches_io(self, start_names, funcs, kind: str, depth: int = 2) -> bool:
        seen = set()
        stack = [(nm.lstrip("_"), depth) for nm in start_names]
        while stack:
            key, d = stack.pop()
            if key in seen:
                continue
            seen.add(key)
            for fn in funcs.get(key, []):
                if kind == "sink" and self._fn_sink_io(fn):
                    return True
                if kind == "source" and self._fn_source_io(fn):
                    return True
                if d > 0:
                    for callee in _callee_names(fn):
                        stack.append((callee.lstrip("_"), d - 1))
        return False

    def _output_reaches_sink(self, tool_names, sink_funcs, all_fns) -> bool:
        tnorm = {n.lstrip("_") for n in tool_names}
        for fn in all_fns:
            assigned = set()
            # pass 1: vars assigned from a call to the tool
            for n in ast.walk(fn):
                if isinstance(n, ast.Assign) and len(n.targets) == 1 and \
                   isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Call) and \
                   (_final(n.value.func) or "").lstrip("_") in tnorm:
                    assigned.add(n.targets[0].id)
            # pass 2: a sink-function call that consumes the tool's output
            for n in ast.walk(fn):
                if isinstance(n, ast.Call) and (_final(n.func) or "").lstrip("_") in sink_funcs:
                    for a in list(n.args) + [k.value for k in n.keywords]:
                        if isinstance(a, ast.Name) and a.id in assigned:
                            return True
                        if isinstance(a, ast.Call) and (_final(a.func) or "").lstrip("_") in tnorm:
                            return True
        return False

    def _resolve_impls(self, t: ToolSpec, funcs):
        names = {t.name}
        if t.callable:
            names.add(t.callable.split(".")[-1])
        impls = []
        for nm in names:
            impls += funcs.get(nm.lstrip("_"), [])
        return impls, names

    def _ground(self, model: RepoToolModel, repo: str) -> RepoToolModel:
        funcs, all_fns = self._index_functions(Path(repo))
        sink_funcs = {k for k, fns in funcs.items() if any(self._fn_sink_io(fn) for fn in fns)}
        kept = []
        for t in model.tools:
            if "heuristic" in (t.classifier or ""):     # grounded by construction
                kept.append(t)
                continue
            impls, names = self._resolve_impls(t, funcs)
            if not impls:                                # unresolved -> recall-safe keep
                kept.append(t)
                continue
            sink_ok = (self._reaches_io(names, funcs, "sink", 2)
                       or self._output_reaches_sink(names, sink_funcs, all_fns))
            src_ok = self._reaches_io(names, funcs, "source", 2)
            roles = []
            if "sink" in t.roles and sink_ok:
                roles.append("sink")
            if "source" in t.roles and src_ok:
                roles.append("source")
            if not roles:                                # no role backed by real I/O -> drop
                continue
            t.roles = roles
            if "sink" not in roles:
                t.sink = None
            if "source" not in roles:
                t.source = None
            t.classifier = (t.classifier or "") + "+grounded"
            kept.append(t)
        model.tools = kept
        return model

    # -- cross-layer guard tracing (deterministic, conservative) ------------ #
    def _intra_guard(self, fns) -> Optional[str]:
        for fn in fns:
            for n in ast.walk(fn):
                if isinstance(n, ast.Call) and (_final(n.func) or "").lower() in _GUARD_NAMES:
                    return _final(n.func)
        return None

    def _crosslayer_guard(self, impl_names, all_fns) -> Optional[str]:
        tnorm = {n.lstrip("_") for n in impl_names}
        # generic method names (execute/run/…) are matched dynamically by dispatchers
        # and collide across the repo, so cross-layer matching is unreliable -> skip.
        if not tnorm or tnorm <= _GENERIC_TOOL_FN:
            return None
        for fn in all_fns:
            g = self._guard_dominating_call(fn, tnorm)
            if g:
                return g
        return None

    @staticmethod
    def _guard_dominating_call(fn, tnorm) -> Optional[str]:
        """Guard name that lexically *dominates* a call to the tool inside ``fn``.

        Block/branch-scoped (not a flat line scan): a guard established in an
        ``if`` test (``if confirm(): tool()`` or the ``if not confirm(): return``
        early-exit idiom) dominates the tool call only within the same branch — a
        guard in a *sibling* dispatch branch does not leak onto an unguarded one.
        """
        found = [None]

        def has_tool_call(node) -> bool:
            return any(isinstance(n, ast.Call) and (_final(n.func) or "").lstrip("_") in tnorm
                       for n in ast.walk(node))

        def guards_in(node):
            return [_final(c.func) for c in ast.walk(node)
                    if isinstance(c, ast.Call) and (_final(c.func) or "").lower() in _GUARD_NAMES]

        def block(stmts, guards):
            if found[0]:
                return
            local = list(guards)
            for st in stmts:
                if found[0]:
                    return
                if isinstance(st, ast.If):
                    tg = guards_in(st.test)
                    block(st.body, local + tg)        # positive branch is guarded
                    block(st.orelse, local)           # else branch is not
                    local += tg                       # guard-and-return dominates the rest
                elif isinstance(st, ast.Try):
                    block(st.body, local)
                    for h in st.handlers:
                        block(h.body, list(guards))
                    block(st.orelse, local)
                    block(st.finalbody, local)
                elif isinstance(st, (ast.For, ast.AsyncFor, ast.While)):
                    block(st.body, local)
                    block(st.orelse, local)
                elif isinstance(st, (ast.With, ast.AsyncWith)):
                    block(st.body, local)
                else:                                  # leaf statement
                    if has_tool_call(st) and local:
                        found[0] = local[-1]
                        return
                    local += guards_in(st)

        block(fn.body, [])
        return found[0]

    def _trace_guards(self, model: RepoToolModel, repo: str) -> RepoToolModel:
        funcs, all_fns = self._index_functions(Path(repo))
        for t in model.tools:
            if not t.sink:
                continue
            if "heuristic" in (t.classifier or ""):     # heuristic guard is already deterministic
                continue
            impls, names = self._resolve_impls(t, funcs)
            impl_names = {fn.name for fn in impls} or set(names)
            # deterministic & conservative: ignore the LLM's (variable) guard claim;
            # set a guard ONLY if a real guard call is found intra- or cross-layer.
            t.sink.guard = self._intra_guard(impls) or self._crosslayer_guard(impl_names, all_fns)
        return model

    # -- deterministic provenance (callable / site) for the Pysa leg -------- #
    def _fill_provenance(self, model: RepoToolModel, repo: str) -> RepoToolModel:
        """Fill ``callable`` and ``site`` from the located implementation, deterministically.

        The LLM often omits the qualified callable (``callable: null``); without it the
        Pysa emit (``to_pysa``) skips the tool. We already locate the impl FunctionDef
        during grounding, so we derive ``module.qualname`` + ``file:line`` from it — no
        reliance on the LLM. Only set when exactly one impl resolves (recall-safe; leave
        ambiguous tools as-is).
        """
        funcs, _ = self._index_functions(Path(repo))
        for t in model.tools:
            if "heuristic" in (t.classifier or ""):   # heuristic already sets these
                continue
            impls, _names = self._resolve_impls(t, funcs)
            if len(impls) == 1:
                fn = impls[0]
                mod = getattr(fn, "_ct_mod", "")
                qual = getattr(fn, "_ct_qual", fn.name)
                t.callable = f"{mod}.{qual}" if mod else qual
                f = getattr(fn, "_ct_file", "")
                if f and getattr(fn, "lineno", None):
                    t.site = f"{f}:{fn.lineno}"
        return model


def _anthropic_transport(model: Optional[str] = None):
    """Return a complete(system,user)->str backed by the Anthropic SDK, or None."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic  # type: ignore
        client = anthropic.Anthropic()
    except Exception:
        return None
    m = model or os.environ.get("CTAUDIT_TRIAGE_MODEL", "claude-sonnet-4-5-20250929")

    def complete(system: str, user: str) -> str:
        msg = client.messages.create(model=m, max_tokens=4096, temperature=0, system=system,
                                      messages=[{"role": "user", "content": user}])
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    return complete


def make_replay_transport(fixtures_dir: str):
    """A transport that replays a captured discovery JSON, keyed by the REPO marker.

    Lets the discovery+merge pipeline run end-to-end (and be measured) without a
    network — the JSON is the LLM's captured output; everything else is real code.
    """
    import re
    d = Path(fixtures_dir)

    def complete(system: str, user: str) -> str:
        m = re.search(r"REPO:\s*(\S+)", user)
        key = m.group(1) if m else ""
        f = d / f"{key}.json"
        if f.exists():
            return f.read_text(encoding="utf-8")
        return '{"tools": [], "llm_call": null}'
    return complete


def _openai_compat_transport(*, api_key_env: str = "OPENAI_API_KEY",
                             base_url: Optional[str] = None,
                             default_model: str = "gpt-4o-mini",
                             model: Optional[str] = None):
    """complete(system,user)->str over any OpenAI-compatible Chat Completions API
    (OpenAI, **DeepSeek** https://api.deepseek.com, Together/Groq/OpenRouter/Ollama).
    Returns None if the key or the ``openai`` SDK is missing."""
    key = (os.environ.get(api_key_env)
           or os.environ.get("CTAUDIT_TOOLMODEL_API_KEY")
           or os.environ.get("CTAUDIT_TRIAGE_API_KEY"))
    if not key:
        return None
    try:
        from openai import OpenAI  # type: ignore
    except Exception:
        return None
    try:
        kwargs = {"api_key": key}
        bu = (base_url or os.environ.get("CTAUDIT_TOOLMODEL_BASE_URL")
              or os.environ.get("CTAUDIT_TRIAGE_BASE_URL"))
        if bu:
            kwargs["base_url"] = bu
        client = OpenAI(**kwargs)
    except Exception:
        return None
    m = (model or os.environ.get("CTAUDIT_TOOLMODEL_MODEL")
         or os.environ.get("CTAUDIT_TRIAGE_MODEL", default_model))

    def complete(system: str, user: str) -> str:
        resp = client.chat.completions.create(
            model=m, temperature=0, max_tokens=4096,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}])
        return resp.choices[0].message.content or ""
    return complete


class AnthropicClassifier(LLMToolClassifier):
    """Discovery+merge classifier backed by the Anthropic SDK (graceful fallback)."""
    name = "anthropic"

    def __init__(self, model: Optional[str] = None, ground: bool = True) -> None:
        super().__init__(complete=_anthropic_transport(model), model=model, ground=ground)


def get_classifier(name: str = "heuristic", model: Optional[str] = None,
                   fixtures: Optional[str] = None, ground: bool = True,
                   agentdojo: bool = False):
    if name == "replay":
        if not fixtures:
            raise ValueError("replay classifier needs fixtures=<dir>")
        return LLMToolClassifier(complete=make_replay_transport(fixtures), model=model, ground=ground)
    if name in ("anthropic", "llm"):
        return AnthropicClassifier(model, ground=ground)
    if name == "deepseek":
        return LLMToolClassifier(
            complete=_openai_compat_transport(api_key_env="DEEPSEEK_API_KEY",
                                              base_url="https://api.deepseek.com",
                                              default_model="deepseek-chat", model=model),
            model=model, ground=ground)
    if name in ("openai", "openai-compat"):
        return LLMToolClassifier(
            complete=_openai_compat_transport(api_key_env="OPENAI_API_KEY", model=model),
            model=model, ground=ground)
    return HeuristicClassifier(agentdojo=agentdojo)
