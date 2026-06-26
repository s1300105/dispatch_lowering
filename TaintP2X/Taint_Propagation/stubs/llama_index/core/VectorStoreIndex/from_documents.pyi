from typing import Any, Dict, List, Optional, Union

class as_chat_engine:
    @staticmethod
    def chat(
        self, 
        messages: str,
        **kwargs                            
    ) -> Dict[str, Any]: ...

    @staticmethods
    def stream_chat(
        self, 
        messages: str,
        **kwargs                                
    ) -> Dict[str, Any]: ...

    @staticmethods
    def query(
        self, 
        messages: str,
        **kwargs                                
    ) -> Dict[str, Any]: ...