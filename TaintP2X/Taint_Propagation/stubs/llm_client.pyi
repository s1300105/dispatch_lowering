from typing import Any, Dict, List, Optional, Union

@staticmethod
def call_model(
    model: str,
    messages: List[Dict[str, str]],  
    **kwargs: Any
) -> Dict[str, Any]: ...