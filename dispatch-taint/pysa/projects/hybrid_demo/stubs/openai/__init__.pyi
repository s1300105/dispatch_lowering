from typing import Any
class _Completions:
    def create(self, *, messages: Any = ..., **kwargs: Any) -> Any: ...
class _Chat:
    completions: _Completions
class OpenAI:
    chat: _Chat
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
