"""AgentDojo runtime model (項目1 — declarative support part, applicability demo).

Reconnaissance of AgentDojo (Debenedetti et al., 2024) established that its dispatch
is a textbook dict-registry wall living in *library* code:

    class FunctionsRuntime:
        def run_function(self, env, function, kwargs):
            f = self.functions[function]   # lookup by LLM-chosen name
            return f(**kwargs)             # the wall (indirected through a local)

and that each task suite registers a plain-function ``TOOLS`` list into that
runtime (``FunctionsRuntime([...])`` / ``TaskSuite(name, Env, [make_function(t)
for t in TOOLS])``).  The wall, candidate set, and tool-output sources can all be
supplied *declaratively* — exactly as the LangChain ``create_react_agent`` spec
absorbs that framework's managed dispatch — so we never penetrate the runtime
internals or the cross-file pipeline.

This module declares:
  * a ``DispatchSpec`` whose factory is ``FunctionsRuntime(TOOLS)`` (tools at
    positional 0) and whose launch/wall is ``.run_function``;
  * the AgentDojo *domain* sinks (send_money, update_password, …) — danger here is
    domain-semantic, not syntactic, so it must be declared (a 方向B extension).

It is a support part (not a novelty claim): it connects AgentDojo's runtime to the
existing wall-resolution machinery so the applicability of the core dynamic-dispatch
resolution can be demonstrated on a standard public benchmark.
"""

from .base import CalleePattern, DispatchSpec, ModelRegistry, SinkSpec


# Domain sinks — danger is the capability, not a syntactic call in the body
# (AgentDojo tools only mutate simulated state, e.g. send_money appends to
# account.transactions).  Declared like 方向B's known-dangerous library tools.
# name -> (category, dangerous-kwarg-name)
AGENTDOJO_DOMAIN_SINKS = {
    # banking
    "send_money": ("transaction", "recipient"),
    "schedule_transaction": ("transaction", "recipient"),
    "update_scheduled_transaction": ("transaction", "recipient"),
    "update_password": ("credential_change", "password"),
    "update_user_info": ("pii_change", None),
    # workspace / email / slack / cloud
    "send_email": ("network_exfil", "recipients"),
    "send_direct_message": ("network_exfil", "recipient"),
    "send_channel_message": ("network_exfil", "channel"),
    "post_webpage": ("network_exfil", "content"),
    "create_file": ("file_write", None),
    "append_to_file": ("file_write", None),
    "share_file": ("network_exfil", "email"),
    "invite_user_to_slack": ("access_control", "user"),
    # travel
    "reserve_hotel": ("transaction", None),
    "reserve_restaurant": ("transaction", None),
    "reserve_car_rental": ("transaction", None),
}

# Tools that return environment data the model later reads -> tool-output sources.
AGENTDOJO_SOURCE_TOOLS = {
    "get_most_recent_transactions",
    "get_scheduled_transactions",
    "read_file",
    "read_email",
    "get_unread_emails",
    "search_emails",
    "read_channel_messages",
    "read_inbox",
    "get_webpage",
    "list_files",
    "search_files",
    "get_user_info",
}


def agentdojo_registry() -> ModelRegistry:
    """Declarative model of the AgentDojo runtime (wall + domain sinks)."""
    reg = ModelRegistry()

    # The dispatch wall: FunctionsRuntime(TOOLS).run_function(env, name, kwargs).
    # factory == FunctionsRuntime(...) (bare Name call), tool list at positional 0;
    # launch/wall == .run_function (the dict-registry call, indirected via a local).
    reg.dispatches.append(
        DispatchSpec(
            factory=CalleePattern(attr="FunctionsRuntime", bare=True),
            launch=CalleePattern(attr="run_function"),
            tools_kwarg=("functions", "tools"),
            tools_positional=(0,),
            prompt_positional=(1,),
            framework="agentdojo",
        )
    )

    # Domain sinks (declared; danger is semantic, not syntactic).
    for name, (category, arg) in AGENTDOJO_DOMAIN_SINKS.items():
        reg.sinks.append(
            SinkSpec(
                name=name,
                callee=CalleePattern(attr=name, bare=True),
                category=category,
                dangerous_kwargs=(arg,) if arg else (),
            )
        )

    return reg
