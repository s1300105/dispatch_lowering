# DIAGNOSTIC — does taint from the real entry survive the REAL pydantic
# validate/dump and reach the dispatch wall?  (cond_A = host alone; cond_B also
# applies wall lowering.)
#
# Faithful to mcp.server.fastmcp: ToolManager.call_tool -> Tool.run ->
# call_fn_with_arg_validation -> fn(**arguments_parsed_dict).  The pydantic part
# (the suspected TITO gap) is REAL: ArgModelBase.model_dump_one_level is copied
# verbatim from func_metadata.py and model_validate is real pydantic.  Two taint
# PROBES (modeled as sinks) mark how far taint reaches; the first probe that does
# NOT fire localises the blocker.  Source is the real dispatch entry.
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict

from server import read_file, run_command


# ---- taint probes (sinks in diag.pysa). distinct sink kinds the real tools
#      never emit (SSRF=5015, SQL=5008) so they are unambiguous in the breakdown.
def _probe_A_callfn_entry(x: Any) -> None:   # did taint survive call_tool -> run -> call_fn ?
    ...


def _probe_B_post_pydantic(x: Any) -> None:  # did taint survive model_validate + model_dump ?
    ...


# ---- REAL mcp code: func_metadata.ArgModelBase.model_dump_one_level (verbatim) ----
class ArgModelBase(BaseModel):
    """A model representing the arguments to a function. (mcp func_metadata.py)"""

    def model_dump_one_level(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {}
        for field_name, field_info in self.__class__.model_fields.items():
            value = getattr(self, field_name)
            output_name = field_info.alias if field_info.alias else field_name
            kwargs[output_name] = value
        return kwargs

    model_config = ConfigDict(arbitrary_types_allowed=True)


class _RunCommandArgs(ArgModelBase):
    cmd: str


class _ReadFileArgs(ArgModelBase):
    path: str


def call_fn_with_arg_validation(
    fn: Callable[..., Any], arg_model: type[ArgModelBase], arguments_to_validate: dict
) -> Any:
    # mirrors func_metadata.call_fn_with_arg_validation; model_validate/dump are REAL pydantic
    _probe_A_callfn_entry(arguments_to_validate)                  # PROBE A (pre-pydantic)
    arguments_parsed_model = arg_model.model_validate(arguments_to_validate)
    arguments_parsed_dict = arguments_parsed_model.model_dump_one_level()
    _probe_B_post_pydantic(arguments_parsed_dict)                 # PROBE B (post-pydantic)
    result = fn(**arguments_parsed_dict)                          # WALL (param_call: fn)
    return result


# ---- faithful hops: ToolManager.call_tool -> Tool.run -> call_fn ----
class Tool:
    def __init__(self, fn: Callable[..., Any], arg_model: type[ArgModelBase]) -> None:
        self.fn = fn
        self.arg_model = arg_model

    def run(self, arguments: dict) -> Any:
        return call_fn_with_arg_validation(self.fn, self.arg_model, arguments)


class ToolManager:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def add_tool(self, fn: Callable[..., Any], name: str, arg_model: type[ArgModelBase]) -> None:
        self._tools[name] = Tool(fn, arg_model)

    def get_tool(self, name: str) -> "Tool | None":
        return self._tools.get(name)

    def call_tool(self, name: str, arguments: dict) -> Any:   # SOURCE on arguments (real entry)
        tool = self.get_tool(name)
        if tool is None:
            raise ValueError(f"Unknown tool: {name}")
        return tool.run(arguments)


_manager = ToolManager()
_manager.add_tool(run_command, "run_command", _RunCommandArgs)
_manager.add_tool(read_file, "read_file", _ReadFileArgs)
