from typing import Any, Dict, List, Optional, Union

class client:
    class MistralClient:
        @staticmethod
        def chat(
            model: str,
            messages: List[Dict[str, str]],  
            **kwargs: Any
        ) -> Dict[str, Any]: ...

class Mistral:
    class chat:
        @staticmethod
        def complete(
            model: str,
            messages: List[Dict[str, str]],  
            **kwargs: Any
        ) -> Dict[str, Any]: ...

        class completions:
            def create(
                model: str,
                messages: List[Dict[str, str]],  
                **kwargs: Any
            ) -> Dict[str, Any]: ...    
    class code:
        class completions:
            def create(
                model: str,
                messages: List[Dict[str, str]],  
                **kwargs: Any
            ) -> Dict[str, Any]: ...  

class AsyncMistral:
    class chat:
        @staticmethod
        def complete(
            model: str,
            messages: List[Dict[str, str]],  
            **kwargs: Any
        ) -> Dict[str, Any]: ...

        class completions:
            def create(
                model: str,
                messages: List[Dict[str, str]],  
                **kwargs: Any
            ) -> Dict[str, Any]: ...    
    class code:
        class completions:
            def create(
                model: str,
                messages: List[Dict[str, str]],  
                **kwargs: Any
            ) -> Dict[str, Any]: ...  
