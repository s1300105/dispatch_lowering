# server.py — SecurityNik Vulnerable MCP Server (real tool bodies).
#   https://github.com/SecurityNik/MCP-Stuff
# The two @mcp.tool() functions below are the unmodified server code (the
# security-relevant subprocess/open calls are byte-for-byte the original). The
# FastMCP instance is shimmed so this target is self-contained for static
# analysis (no need to install `mcp`); swap in `from mcp.server.fastmcp import
# FastMCP` for the install-based variant.
import subprocess


class _FastMCP:                      # analysis shim for mcp.server.fastmcp.FastMCP
    def __init__(self, name: str = "") -> None: ...
    def tool(self, *a, **k):
        def deco(fn):
            return fn
        return deco


mcp = _FastMCP(name="SecurityNik Vulnerable MCP Server for testing")


@mcp.tool()
def read_file(path: str) -> str:
    """Reads file from disk"""
    with open(file=path, mode="r") as fp:
        data = fp.read()
    return data


@mcp.tool()
def run_command(cmd: str) -> str:
    """Runs a shell command"""
    result = subprocess.check_output(cmd, shell=True)
    return result.decode()
