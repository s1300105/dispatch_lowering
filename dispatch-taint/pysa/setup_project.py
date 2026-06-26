#!/usr/bin/env python3
"""Point dispatch_lowering + Pysa at a real project: discover what to model, emit config.

This scans a target source tree and reports the project-specific things you must
wire into Pysa (steps 1 and 2 of the setup):

  * LLM entry points  -> need a `TaintInTaintOut[Via[llm_node]]` model
  * @tool / @function_tool decorators -> covered by the source ModelQueries
  * hide()/store-by-reference helpers -> need a `Sanitize` model
  * Pyre's bundled stdlib taint stubs path + its sink kinds (for the ~236 sinks)

It also writes a ready `.pyre_configuration` for the target. Nothing here runs
Pyre; it just tells you exactly what to fill into frameworks.pysa / taint.config.

Usage:
    python setup_project.py --target /path/to/your/package
    python setup_project.py --target ../myagent --out ../myagent/.pyre_configuration
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# call attributes that usually denote an LLM invocation (the §4.4 join node).
LLM_CALL_ATTRS = {
    "invoke", "ainvoke", "stream", "astream", "batch", "abatch",      # LangChain
    "run", "run_sync", "run_streamed",                                # OpenAI Agents
    "create_message",                                                 # MCP sampling
    "create",                                                         # *.messages.create / *.chat.completions.create
}
TOOL_DECORATORS = {"tool", "function_tool", "mcp_tool"}
HIDE_NAME_HINTS = ("hide", "redact", "by_ref", "byref", "store_ref", "to_ref", "opaque")
# framework constructs that MEDIATE the LLM<->tool wiring (so direct .invoke /
# @tool may be absent in user code, as in a LangChain ReAct AgentExecutor app).
FRAMEWORK_CALLS = {
    "AgentExecutor", "initialize_agent", "from_agent_and_tools", "from_llm_and_tools",
    "create_react_agent", "create_tool_calling_agent", "create_openai_tools_agent",
    "create_openai_functions_agent", "ConversationalChatAgent", "ReActAgent",
    "Tool", "StructuredTool", "from_function", "Runner",
}
import re as _re
_LLM_CTOR = _re.compile(r"^(Chat[A-Z]\w*|\w*LLM|OpenAI|AzureChatOpenAI|ChatOllama)$")


def _iter_py(root: Path):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in {".venv", "venv", "__pycache__", ".git", "node_modules"}]
        for fn in fns:
            if fn.endswith(".py"):
                yield Path(dp) / fn


def _attr_name(func: ast.AST) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _dotted(func: ast.AST) -> str:
    # best-effort "recv.attr" text for reporting
    if isinstance(func, ast.Attribute):
        base = _dotted(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    if isinstance(func, ast.Name):
        return func.id
    return _attr_name(func)


def _returns_ref_dict(fn: ast.AST) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            for k in node.value.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and "ref" in k.value.lower():
                    return True
    return False


def scan(root: Path) -> Dict[str, List[Tuple[str, int, str]]]:
    found = {"llm": [], "tools": [], "hide": [], "framework": []}
    for fp in _iter_py(root):
        try:
            tree = ast.parse(fp.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = str(fp.relative_to(root))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                attr = _attr_name(node.func)
                if attr in LLM_CALL_ATTRS:
                    found["llm"].append((rel, getattr(node, "lineno", 0), _dotted(node.func) + "(...)"))
                if attr in FRAMEWORK_CALLS or _LLM_CTOR.match(attr or ""):
                    found["framework"].append((rel, getattr(node, "lineno", 0), _dotted(node.func) + "(...)"))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if _attr_name(dec) in TOOL_DECORATORS:
                        found["tools"].append((rel, node.lineno, f"@{_attr_name(dec)} {node.name}"))
                name = node.name.lower()
                if any(h in name for h in HIDE_NAME_HINTS) or _returns_ref_dict(node):
                    found["hide"].append((rel, node.lineno, node.name))
    for k in found:
        found[k] = sorted(set(found[k]))
    return found


def bundled_taint_stubs() -> Tuple[str, List[str]]:
    """Locate Pyre's bundled stdlib taint stubs and read its sink kinds."""
    try:
        import pyre_check  # type: ignore
    except Exception:
        return "", []
    base = Path(pyre_check.__file__).parent
    for cand in (base / "taint", base / "stubs" / "taint", base / "pysa_stubs"):
        cfg = cand / "taint.config"
        if cfg.exists():
            try:
                data = json.loads(cfg.read_text(encoding="utf-8"))
                sinks = [s.get("name") for s in data.get("sinks", []) if s.get("name")]
            except Exception:
                sinks = []
            return str(cand), sinks
    return "", []


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="setup_project")
    ap.add_argument("--target", required=True, help="path to the project's source package/dir")
    ap.add_argument("--out", default=None, help="where to write the generated .pyre_configuration")
    ap.add_argument("--with-bundled-sinks", action="store_true",
                    help="add Pyre's bundled stdlib taint stubs to taint_models_path")
    args = ap.parse_args(argv)

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"target not found: {target}", file=sys.stderr)
        return 2

    found = scan(target)
    stubs_path, stub_sinks = bundled_taint_stubs()

    print("=" * 74)
    print(f"dispatch_lowering + Pysa — project discovery for {target}")
    print("=" * 74)

    print("\n[1] LLM entry points  -> model each as TaintInTaintOut[Via[llm_node]]")
    if found["llm"]:
        for rel, ln, txt in found["llm"][:50]:
            print(f"    {rel}:{ln}: {txt}")
    else:
        print("    (none auto-detected — check how your code calls the model)")

    print("\n[1b] agent/tool framework constructs (LLM<->tool wiring is MEDIATED here)")
    if found["framework"]:
        for rel, ln, txt in found["framework"][:50]:
            print(f"    {rel}:{ln}: {txt}")
        print("    -> the LLM call and tool dispatch happen INSIDE the framework, not in")
        print("       user code. Model the framework's LLM class (e.g. ChatXxx.invoke) as")
        print("       TaintInTaintOut[Via[llm_node]]; tool inputs are LLM-routed.")
    else:
        print("    (none found)")

    print("\n[2] tool decorators  -> covered by the @tool/@function_tool ModelQueries")
    if found["tools"]:
        for rel, ln, txt in found["tools"][:50]:
            print(f"    {rel}:{ln}: {txt}")
    else:
        print("    (none found; if tools are plain functions, add explicit source models)")

    print("\n[3] hide()/by-reference helpers  -> model as Sanitize")
    if found["hide"]:
        for rel, ln, txt in found["hide"]:
            print(f"    {rel}:{ln}: {txt}()")
    else:
        print("    (none detected; selective hiding may not be used in this project)")

    print("\n[4] Pyre bundled stdlib taint stubs (the ~236 sinks)")
    if stubs_path:
        print(f"    path : {stubs_path}")
        print(f"    sink kinds ({len(stub_sinks)}): {', '.join(stub_sinks[:25])}"
              + (" …" if len(stub_sinks) > 25 else ""))
        print("    -> add rules `ToolOutput -> <kind>` in taint.config for the kinds you care about.")
    else:
        print("    (pyre_check bundled stubs not found; install pyre-check, or model")
        print("     your project's specific sinks in a custom *.pysa file instead.)")

    # emit a .pyre_configuration for the target
    taint_paths = ["models", "frameworks"]
    if args.with_bundled_sinks and stubs_path:
        taint_paths.append(stubs_path)
    cfg = {
        "source_directories": [str(target)],
        "taint_models_path": taint_paths,
        "search_path": [],
        "exclude": [],
        "strict": False,
    }
    out = Path(args.out) if args.out else (Path.cwd() / ".pyre_configuration.suggested")
    out.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote suggested config -> {out}")
    print("Next: review frameworks.pysa against [1]-[3] above, install the project's")
    print("deps into this venv, then run:  pyre analyze --save-results-to ./pysa-results")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
