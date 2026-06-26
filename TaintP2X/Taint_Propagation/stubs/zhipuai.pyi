# zhipuai.pyi
from typing import Any, Dict, List, Optional, Union

class ZhipuAI:
    class chat:
        class completions:
            @staticmethod
            def create(
                model: str,
                messages: list[dict[str, str]],
                **kwargs: Any
            ) -> dict[str, Any]: ...

            @staticmethod
            def create_async(
                model: str,
                messages: list[dict[str, str]],
                **kwargs: Any
            ) -> dict[str, Any]: ...