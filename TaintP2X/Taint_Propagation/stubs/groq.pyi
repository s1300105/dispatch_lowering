from typing import Any, Dict, List, Optional, Union

class Groq:
    class chat:
        class completions:
            @staticmethod
            def create(
                query: list[dict[str, str]],
                **kwargs: Any
            ) -> dict[str, Any]:...

class AsyncGroq:
    class chat:
        class completions:
            @staticmethod
            def create(
                query: list[dict[str, str]],
                **kwargs: Any
            ) -> dict[str, Any]:...