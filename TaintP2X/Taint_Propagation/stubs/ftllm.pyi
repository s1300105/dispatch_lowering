from typing import Any, Dict, List, Optional, Union

class llm:
    class model:
        @staticmethod
        def response(
            query: list[dict[str, str]],
            **kwargs: Any
        ) -> dict[str, Any]: ...