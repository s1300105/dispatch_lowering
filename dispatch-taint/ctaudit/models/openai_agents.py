"""OpenAI Agents SDK wiring models (§4.2, table row 3).

    source : @function_tool decorated functions
    entry  : ToolCallOutputItem(...)             -> tool output wrapper
    bridge : result.to_input_list()              -> aggregate (§4.3 rule 2)
    exit   : Runner.run(input=...) / run_sync(...) -> control-region start
"""

from __future__ import annotations

from .base import CalleePattern as P
from .base import BridgeSpec, EntrySpec, ExitSpec, ModelRegistry, ToolSpec

FRAMEWORK = "openai-agents"


def models() -> ModelRegistry:
    return ModelRegistry(
        tools=[
            ToolSpec(decorators=("function_tool",), framework=FRAMEWORK, output_type="string"),
        ],
        entries=[
            EntrySpec(P("ToolCallOutputItem"), content_kwargs=("output",),
                      content_positional=(0,), framework=FRAMEWORK, output_type="string"),
        ],
        bridges=[
            # to_input_list() flattens a run result (incl. tool outputs) into the
            # next turn's input list: an aggregate read of a tainted collection.
            BridgeSpec(P("to_input_list"), kind="aggregate", framework=FRAMEWORK),
        ],
        exits=[
            ExitSpec(P("run", recv_contains="runner"), prompt_kwargs=("input",),
                     prompt_positional=(1,), framework=FRAMEWORK, taints_result=True),
            ExitSpec(P("run_sync", recv_contains="runner"), prompt_kwargs=("input",),
                     prompt_positional=(1,), framework=FRAMEWORK, taints_result=True),
            ExitSpec(P("run_streamed", recv_contains="runner"), prompt_kwargs=("input",),
                     prompt_positional=(1,), framework=FRAMEWORK, taints_result=True),
        ],
    )
