from typing import Any, Dict, List, Optional, Union

class AutoModel:
    class from_pretrained:
        @staticmethod
        def stream_chat(
            query: List[Dict[str, str]],  
            **kwargs: Any
        ) -> Dict[str, Any]: ...

def pipeline(
    query: List[Dict[str, str]],  
    **kwargs: Any
) -> Dict[str, Any]: ...

def AsyncPipeline(
    query: List[Dict[str, str]],  
    **kwargs: Any
) -> Dict[str, Any]: ...

class Llama4ForConditionalGeneration:
    class from_pretrained:
        @staticmethod
        def generate(
            query: List[Dict[str, str]],  
            **kwargs: Any
        ) -> Dict[str, Any]: ...

class AutoModelForCausalLM:
    class from_pretrained:
        @staticmethod
        def generate(
            query: List[Dict[str, str]],  
            **kwargs: Any
        ) -> Dict[str, Any]: ...

class HfAgent:
    @staticmethod
    def run(
        query: List[Dict[str, str]],  
        **kwargs: Any
    ) -> Dict[str, Any]: ...