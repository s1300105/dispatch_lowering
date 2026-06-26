from typing import Any, Dict, List, Optional, Union

@staticmethod
def completion(
    model: str,
    messages: List[Dict[str, str]],  
    **kwargs: Any
) -> Dict[str, Any]: ...