from typing import Any, Dict, List, Optional, Union


@staticmethod
def Llama(
    query: list[dict[str, str]],
    **kwargs: Any
) -> dict[str, Any]: ...

class Llama:
    @staticmethod
    def create_chat_completion(
        query: list[dict[str, str]],
        **kwargs: Any
    ) -> dict[str, Any]: ...

    @staticmethod
    def create_completion(
        query: list[dict[str, str]],
        **kwargs: Any
    ) -> dict[str, Any]: ...

class AsyncLlama:
    @staticmethod
    def create_chat_completion(
        query: list[dict[str, str]],
        **kwargs: Any
    ) -> dict[str, Any]: ...

    @staticmethod
    def create_completion(
        query: list[dict[str, str]],
        **kwargs: Any
    ) -> dict[str, Any]: ...
