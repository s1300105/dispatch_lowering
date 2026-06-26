# openai.pyi
from typing import Any, Dict, List, Optional, Union

class ChatCompletion:
    @staticmethod
    def create(
        model: str,
        messages: List[Dict[str, str]],  
        **kwargs: Any
    ) -> Dict[str, Any]: ...

    @staticmethod
    def acreate(
        model: str,
        messages: List[Dict[str, str]],  
        **kwargs: Any
    ) -> Dict[str, Any]: ...
        
class OpenAI:
    class chat:
        class completions:
            @staticmethod
            def create(
                model: str,
                messages: List[Dict[str, str]],  
                **kwargs: Any
            ) -> Dict[str, Any]: ...

def createChatCompletion(
    model: str,
    messages: List[Dict[str, str]],  
    **kwargs: Any
) -> Dict[str, Any]: ...

class AsyncChatCompletion:
    @staticmethod
    def create(
        model: str,
        messages: List[Dict[str, str]],  
        **kwargs: Any
    ) -> Dict[str, Any]: ...
        
class AsyncOpenAI:
    class chat:
        class completions:
            @staticmethod
            def create(
                model: str,
                messages: List[Dict[str, str]],  
                **kwargs: Any
            ) -> Dict[str, Any]: ...

class AsyncAzureOpenAI:
    class chat:
        class completions:
            @staticmethod
            def create(
                model: str,
                messages: List[Dict[str, str]],  
                **kwargs: Any
            ) -> Dict[str, Any]: ...

def createChatCompletionAsync(
    model: str,
    messages: List[Dict[str, str]],  
    **kwargs: Any
) -> Dict[str, Any]: ...


