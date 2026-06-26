from typing import Any, Dict, List, Optional, Union

class Anthropic:
    class messages:
        @staticmethod
        def create(
            messages: List[Dict[str, str]],  
            model: str,                      
            **kwargs: Any                                  
        ) -> Dict[str, Any]: ...
    
    class completions:
        @staticmethod
        def create(
            messages: List[Dict[str, str]],  
            model: str,                      
            **kwargs: Any                                  
        ) -> Dict[str, Any]: ...

class AsyncAnthropic:
    class messages:
        @staticmethod
        def create(
            messages: List[Dict[str, str]],  
            model: str,                      
            **kwargs: Any                                  
        ) -> Dict[str, Any]: ...
    
    class completions:
        @staticmethod
        def create(
            messages: List[Dict[str, str]],  
            model: str,                      
            **kwargs: Any                                  
        ) -> Dict[str, Any]: ...