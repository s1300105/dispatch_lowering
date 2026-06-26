from typing import Any, Dict, List, Optional, Union

class chat:
    class completions:
        @staticmethod
        def create(
            model: str,
            messages: List[Dict[str, str]],  
            **kwargs: Any
        ) -> Dict[str, Any]: ...