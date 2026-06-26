#!/usr/bin/env python3
"""gen_tool_sources.py — emit Pysa source models for MCP @tool function params (Mode 2).

Scans a source root for functions decorated with an MCP tool decorator
(@mcp.tool / @server.tool / @app.tool / @<x>.tool / @tool, with or without "()")
and emits, for each, a Pysa model marking every user-facing parameter as
TaintSource[LLMControlled]. Module paths are computed RELATIVE to <src_root>,
so Pysa must run with source_directories = [<src_root>] (hunt.sh does this).

The list of discovered tools is printed to stderr for sanity-checking.

Usage:
    python3 gen_tool_sources.py <src_root>  > tool_sources.pysa
"""
import ast
import os
import sys

SKIP_DIRS = {".git", ".venv", "venv", "env", "__pycache__", "node_modules",
             "tests", "test", "examples", "docs", "build", "dist"}


def _decorator_is_tool(dec):
    node = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(node, ast.Attribute):
        return node.attr == "tool"          # @mcp.tool / @server.tool / @app.tool / @x.tool()
    if isinstance(node, ast.Name):
        return node.id == "tool"            # bare @tool
    return False


def _module_of(path, root):
    rel = os.path.relpath(path, root)
    rel = rel[:-3] if rel.endswith(".py") else rel
    parts = [p for p in rel.split(os.sep) if p and p != "."]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _params(fn):
    a = fn.args
    out = []
    for p in (getattr(a, "posonlyargs", []) + a.args):
        if p.arg not in ("self", "cls"):
            out.append(p.arg)
    for p in a.kwonlyargs:
        out.append(p.arg)
    return out


def main(root):
    root = os.path.abspath(root)
    models, found = [], []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(dirpath, f)
            try:
                tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
            except Exception:
                continue
            mod = _module_of(path, root)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                        any(_decorator_is_tool(d) for d in node.decorator_list):
                    params = _params(node)
                    if not params:
                        continue
                    qual = f"{mod}.{node.name}" if mod else node.name
                    ann = ", ".join(f"{p}: TaintSource[LLMControlled]" for p in params)
                    models.append(f"def {qual}({ann}): ...")
                    found.append((qual, params, os.path.relpath(path, root)))

    sys.stderr.write(f"# gen_tool_sources: {len(found)} @tool function(s) found under {root}\n")
    for qual, params, rel in found:
        sys.stderr.write(f"#   {qual}  params={params}  ({rel})\n")
    if not found:
        sys.stderr.write("# WARNING: 0 tools found — check the decorator style / src_root. "
                         "Tools nested in methods or registered without a @*.tool decorator "
                         "need manual source models.\n")

    print("# auto-generated MCP tool-parameter sources (Mode 2).")
    print("# source_directories must equal the root this was generated from.")
    for m in models:
        print(m)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: gen_tool_sources.py <src_root>")
    main(sys.argv[1])
