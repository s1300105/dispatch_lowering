"""VULNERABLE — MCP Python SDK server doing agentic sampling (§4.2 table row 2).

    session.call_tool(...)  -->  CallToolResult(content=...)  -->
    appended to messages  -->  ctx.session.create_message(messages=...)  (exit) -->
    model-chosen args  -->  cursor.execute   (SINK, SQL injection via routing)

Per the proposal's "定型性の限界の明示", the CallToolResult -> message conversion
is framework-specific; here it is written explicitly (the common shape), which is
exactly what a per-implementation MCP model would target.

Analysis target only; never executed.
"""

from mcp import ClientSession
from mcp.types import CallToolResult, SamplingMessage, TextContent


async def agent_step(session: ClientSession, db, user_request: str) -> None:
    messages = [SamplingMessage(role="user", content=TextContent(type="text", text=user_request))]

    # untrusted tool output via MCP dispatch
    result = await session.call_tool("lookup_account", {"q": user_request})
    tool_text = result.content[0].text

    # conversion layer (framework-specific): wrap the result as a message.
    wrapped = CallToolResult(content=tool_text)
    messages.append(SamplingMessage(role="user", content=wrapped))

    # LLM node: MCP sampling over the (now tainted) message list.
    decision = await session.create_message(messages=messages, max_tokens=1024)

    # SINK: the model emits a SQL string after reading the tool output.
    db.cursor().execute(decision.content.text)
