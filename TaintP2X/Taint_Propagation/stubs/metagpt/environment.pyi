from typing import Any, Dict, List, Optional, Union

class Environment:
    @staticmethod
    def publish_message(
        self, 
        messages: str,
        **kwargs                            
    ) -> Dict[str, Any]: ...

    @staticmethod
    def run(
        self, 
        messages: str,
        **kwargs                            
    ) -> Dict[str, Any]: ...