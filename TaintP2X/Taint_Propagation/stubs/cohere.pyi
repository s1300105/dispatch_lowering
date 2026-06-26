from typing import Any, Dict, List, Optional, Union

class ClientV2:
    @staticmethod
    def chat(
        query: list[dict[str, str]],
        **kwargs: Any
    ) -> dict[str, Any]: ...

    @staticmethod
    def chat_stream(
        query: list[dict[str, str]],
        **kwargs: Any
    ) -> dict[str, Any]: ...

class Client:
    @staticmethod
    def chat(
        query: list[dict[str, str]],
        **kwargs: Any
    ) -> dict[str, Any]: ...