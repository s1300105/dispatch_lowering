from typing import Any, Dict, List, Optional, Union\

class HuggingFaceLLM:
    @staticmethod
    def chat(
        self, 
        messages: str,
        **kwargs
    ) -> Dict[str, Any]: ...
    
    @staticmethod
    def stream_chat(
        self, 
        messages: str,
        **kwargs
    ) -> Dict[str, Any]: ...

    @staticmethod
    def complete(
        self, 
        messages: str,
        **kwargs
    ) -> Dict[str, Any]: ...

    @staticmethod
    def achat(
        self, 
        messages: str,
        **kwargs
    ) -> Dict[str, Any]: ...