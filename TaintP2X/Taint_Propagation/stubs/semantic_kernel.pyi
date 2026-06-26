from typing import Any, Dict, List, Optional, Union

class Kernel:
    @staticmethod
    def invoke_prompt(
        self,
        prompt: str,
        **kwargs                        
    ) -> Dict[str, Any]: ...

    @staticmethod
    def invoke_function(
        self,
        prompt: str,
        **kwargs                       
    ) -> Dict[str, Any]: ...

class agents:
    class Team:
        @staticmethod
        def solve_task(
            self,
            prompt: str,
            **kwargs                       
        ) -> Dict[str, Any]: ...