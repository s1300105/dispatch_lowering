"""Shared tool model + classifier (proposal §6 fusion #5, §4.5.1 classification).

One classifier produces a :class:`RepoToolModel`; two emitters feed both legs:
``to_pysa`` (leg a, data-flow) and ``to_enumeration`` (leg b, registry).
"""
from .schema import (  # noqa: F401
    RepoToolModel, ToolSpec, SinkSpec, SourceSpec, LLMCallSpec,
)
from .emit import to_pysa, to_enumeration  # noqa: F401
from .classify import (  # noqa: F401
    get_classifier, HeuristicClassifier, AnthropicClassifier,
    LLMToolClassifier, make_replay_transport,
)
