from typing import Any, Dict, List, Optional, Union

class generativeai:
    class GenerativeModel:
        @staticmethod
        def generate_content(
            prompt: List[Dict[str, str]],  
            **kwargs: Any
        ) -> Dict[str, Any]: ...

        @staticmethod
        def generate_content_async(
            prompt: List[Dict[str, str]],  
            **kwargs: Any
        ) -> Dict[str, Any]: ...

    @staticmethod
    def generate_text(
        prompt: List[Dict[str, str]],  
        **kwargs: Any
    ) -> Dict[str, Any]: ...

    @staticmethod
    def generate_text_async(
        prompt: List[Dict[str, str]],  
        **kwargs: Any
    ) -> Dict[str, Any]: ...

class cloud:
    class Client:
        def query(
            self,
            sql: str
        ) -> Any: ...