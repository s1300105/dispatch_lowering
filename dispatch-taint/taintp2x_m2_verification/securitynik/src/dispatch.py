# dispatch.py — faithful reduction of mcp.server.fastmcp's tool-dispatch chain.
#
# Real chain (mcp SDK):
#   FastMCP.call_tool(name, arguments)                         server.py:343
#     -> ToolManager.call_tool(name, arguments)                tools/tool_manager.py:81
#       -> Tool.run(arguments)                                 tools/base.py:101
#         -> FuncMetadata.call_fn_with_arg_validation(self.fn,..,arguments)
#           -> fn(**arguments_parsed_dict)                     utilities/func_metadata.py:96   <-- WALL
#
# The pydantic argument-validation layer (pre_parse_json / model_validate /
# model_dump_one_level) is omitted as orthogonal to the function-value-dispatch
# wall; the wall `fn(**arguments_parsed_dict)` is preserved exactly. Tools are
# the real server code, imported here so the recovered targets resolve.
from typing import Any, Callable

from server import read_file, run_command


def _call_fn(fn: Callable[..., Any], arguments_parsed_dict: dict) -> Any:
    # func_metadata.py:96 — fn is a runtime-selected value: the static call graph
    # has no edge from here to read_file / run_command.
    result = fn(**arguments_parsed_dict)
    return result


class Tool:
    def __init__(self, fn: Callable[..., Any]) -> None:
        self.fn = fn

    def run(self, arguments: dict) -> Any:
        # base.py:101 -> call_fn_with_arg_validation(self.fn, .., arguments)
        return _call_fn(self.fn, arguments)


class ToolManager:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def add_tool(self, fn: Callable[..., Any], name: str) -> None:
        self._tools[name] = Tool(fn)

    def get_tool(self, name: str) -> "Tool | None":
        return self._tools.get(name)

    def call_tool(self, name: str, arguments: dict) -> Any:
        # tool_manager.py:81 -> get_tool(name).run(arguments)
        tool = self.get_tool(name)
        if tool is None:
            raise ValueError(f"Unknown tool: {name}")
        return tool.run(arguments)


# registration mirrors the two @mcp.tool() decorators in server.py
_manager = ToolManager()
_manager.add_tool(run_command, "run_command")
_manager.add_tool(read_file, "read_file")
