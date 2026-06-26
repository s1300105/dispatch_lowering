from typing import Any, Dict, List, Optional, Union

class ExLlamaV2:
    @staticmethod
    def generate(
        query: list[dict[str, str]],
        **kwargs: Any
    ) -> dict[str, Any]: ...