"""Default model registry: one place that assembles every framework's models.

Adding support for a new framework is exactly the work the proposal claims for
RQ4 (portability, §4.2): write a handful of models and ``extend`` them in here.
"""

from __future__ import annotations

from . import langchain, mcp_sdk, openai_agents
from .base import CalleePattern as P
from .base import ExitSpec, ModelRegistry
from .sinks import sink_models


def _generic_raw_api() -> ModelRegistry:
    """Raw-SDK agent loops that build a `messages` list by hand and call the
    provider's completion endpoint directly (no agent framework)."""
    return ModelRegistry(
        exits=[
            # Anthropic: client.messages.create(messages=[...])
            ExitSpec(P("create", recv_contains="messages"),
                     prompt_kwargs=("messages",), framework="generic"),
            # OpenAI: client.chat.completions.create(messages=[...])
            ExitSpec(P("create", recv_contains="completions"),
                     prompt_kwargs=("messages",), framework="generic"),
            # legacy OpenAI 0.x: openai.ChatCompletion.create(messages=[...])
            ExitSpec(P("create", recv_contains="chatcompletion"),
                     prompt_kwargs=("messages",), framework="generic"),
            # litellm: litellm.completion(model=..., messages=[...]) (or `from litellm
            # import completion` — the alias resolver maps the bare name back here).
            ExitSpec(P("completion", recv_contains="litellm"),
                     prompt_kwargs=("messages",), framework="generic"),
        ],
    )


def default_registry() -> ModelRegistry:
    reg = ModelRegistry()
    reg.extend(langchain.models())
    reg.extend(mcp_sdk.models())
    reg.extend(openai_agents.models())
    reg.extend(_generic_raw_api())
    reg.sinks += sink_models()
    return reg
