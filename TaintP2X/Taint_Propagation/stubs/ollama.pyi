from typing import Any, Dict, List, Optional, Union\

class Client:
    @staticmethod
    def generate(
        model: str,
        prompt: List[Dict[str, str]],  
        **kwargs: Any
    ) -> Dict[str, Any]: ...

def chat(
    model: str,
    prompt: List[Dict[str, str]],  
    **kwargs: Any
) -> Dict[str, Any]: ...