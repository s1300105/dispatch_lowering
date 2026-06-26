"""MCP Python SDK wiring models (§4.2, table row 2).

    source : session.call_tool(...)              -> result is attacker-controlled
    entry  : CallToolResult(content=..., structuredContent=...)
    exit   : session.create_message(...)         -> MCP sampling (CreateMessageRequestParams.messages)

The proposal is explicit (§4.2, "定型性の限界の明示") that the layer converting a
``CallToolResult`` into prompt messages is *framework-specific* — there is no
single cross-cutting model for it (implementations have even been reported to
silently drop ``structuredContent``).  We therefore model the well-defined parts
(the result source, the result wrapper, the sampling exit) and leave the
conversion layer to be modelled per implementation.  ``conversion_layer_note``
documents this boundary for the report.
"""

from __future__ import annotations

from .base import CalleePattern as P
from .base import EntrySpec, ExitSpec, ModelRegistry, ToolSpec

FRAMEWORK = "mcp"

conversion_layer_note = (
    "MCP CallToolResult -> prompt-message conversion is framework-specific and "
    "is NOT reducible to a small cross-cutting model (§4.2). Model it per "
    "implementation; structuredContent handling in particular varies."
)


def models() -> ModelRegistry:
    return ModelRegistry(
        tools=[
            # MCP client dispatch: a single generic call whose result is the
            # (attacker-influenceable) tool output.
            ToolSpec(callee=P("call_tool"), framework=FRAMEWORK, output_type="string"),
            ToolSpec(callee=P("read_resource"), framework=FRAMEWORK, output_type="string"),
        ],
        entries=[
            EntrySpec(P("CallToolResult"),
                      content_kwargs=("content", "structuredContent"),
                      framework=FRAMEWORK, output_type="string"),
        ],
        exits=[
            # MCP sampling: ctx.session.create_message(messages=[...]) and the
            # lower-level CreateMessageRequestParams(messages=[...]).
            ExitSpec(P("create_message"), prompt_kwargs=("messages",),
                     prompt_positional=(0,), framework=FRAMEWORK),
            ExitSpec(P("CreateMessageRequestParams"), prompt_kwargs=("messages",),
                     prompt_positional=(0,), framework=FRAMEWORK),
        ],
    )
