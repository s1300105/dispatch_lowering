"""LangChain / LangGraph wiring models (§4.2, table row 1).

    entry  : ToolMessage(content=...)            -> ctl-taint source
    bridge : add_messages reducer / MessagesState (declarative merge, §4.3 rule 3)
    exit   : llm.invoke(state["messages"])       -> control-region start

Native ``list.append`` / ``+=`` into the message list are handled by the
engine's built-in collection rules (§4.3 rules 1-2), not modelled here.
"""

from __future__ import annotations

from .base import CalleePattern as P
from .base import BridgeSpec, DispatchSpec, EntrySpec, ExitSpec, ModelRegistry, ToolSpec

FRAMEWORK = "langchain"


def models() -> ModelRegistry:
    return ModelRegistry(
        tools=[
            # @tool / @tool(...) decorated functions are local tools.
            ToolSpec(decorators=("tool",), framework=FRAMEWORK, output_type="string"),
        ],
        entries=[
            EntrySpec(P("ToolMessage"), content_kwargs=("content",),
                      framework=FRAMEWORK, output_type="string"),
            EntrySpec(P("FunctionMessage"), content_kwargs=("content",),
                      framework=FRAMEWORK, output_type="string"),
        ],
        bridges=[
            # LangGraph's declarative reducer: returning {"messages": [...]} from a
            # node merges into state["messages"].  Modelled as a reducer step that
            # joins new-message labels with existing-history labels (§4.3 rule 3).
            BridgeSpec(P("add_messages"), kind="reducer", reducer_key="messages",
                       framework="langgraph"),
        ],
        exits=[
            # Receiver-agnostic: llm.invoke(...), chain.invoke(...), model.ainvoke(...)
            ExitSpec(P("invoke"), prompt_positional=(0,), framework=FRAMEWORK),
            ExitSpec(P("ainvoke"), prompt_positional=(0,), framework=FRAMEWORK),
            ExitSpec(P("stream"), prompt_positional=(0,), framework=FRAMEWORK),
            ExitSpec(P("batch"), prompt_positional=(0,), framework=FRAMEWORK),
        ],
        dispatches=[
            # 項目1: framework-managed dispatch.  A factory call registers the tool
            # set (tools=[...]); the returned object's .invoke/.stream/.ainvoke is
            # the dispatch wall (LangGraph's ToolNode selects+runs the tool inside).
            # The candidate set is the registered tool list; the launch's first
            # positional arg carries the {"messages": [...]} prompt.
            #
            #   create_react_agent(model, tools=[a, b, c])   (langgraph.prebuilt)
            #   create_agent(model=..., tools=[...])         (langchain)
            #   AgentExecutor(agent=..., tools=[...])         (classic langchain)
            # Each factory's agent is launched by .invoke / .ainvoke / .stream;
            # all three trigger the framework's internal dispatch (the wall).
            DispatchSpec(factory=P("create_react_agent"), launch=P("invoke"),
                         tools_kwarg=("tools",), tools_positional=(1,),
                         prompt_positional=(0,), framework="langgraph"),
            DispatchSpec(factory=P("create_react_agent"), launch=P("ainvoke"),
                         tools_kwarg=("tools",), tools_positional=(1,),
                         prompt_positional=(0,), framework="langgraph"),
            DispatchSpec(factory=P("create_react_agent"), launch=P("stream"),
                         tools_kwarg=("tools",), tools_positional=(1,),
                         prompt_positional=(0,), framework="langgraph"),
            DispatchSpec(factory=P("create_agent"), launch=P("invoke"),
                         tools_kwarg=("tools",), prompt_positional=(0,),
                         framework=FRAMEWORK),
            DispatchSpec(factory=P("create_agent"), launch=P("ainvoke"),
                         tools_kwarg=("tools",), prompt_positional=(0,),
                         framework=FRAMEWORK),
            DispatchSpec(factory=P("create_agent"), launch=P("stream"),
                         tools_kwarg=("tools",), prompt_positional=(0,),
                         framework=FRAMEWORK),
            DispatchSpec(factory=P("AgentExecutor"), launch=P("invoke"),
                         tools_kwarg=("tools",), prompt_positional=(0,),
                         framework=FRAMEWORK),
            DispatchSpec(factory=P("AgentExecutor"), launch=P("ainvoke"),
                         tools_kwarg=("tools",), prompt_positional=(0,),
                         framework=FRAMEWORK),
            DispatchSpec(factory=P("AgentExecutor"), launch=P("stream"),
                         tools_kwarg=("tools",), prompt_positional=(0,),
                         framework=FRAMEWORK),
        ],
    )
