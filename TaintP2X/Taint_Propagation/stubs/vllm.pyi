from typing import Any, Dict, List, Optional, Union

class LLM:
    @staticmethod
    def generate(
        query: list[dict[str, str]],
        **kwargs: Any
    ) -> dict[str, Any]: ...

    @staticmethod
    def create_chat_completion(
        query: list[dict[str, str]],
        **kwargs: Any
    ) -> dict[str, Any]: ...