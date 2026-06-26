from typing import Any, Dict, List, Optional, Union

class components:
    class generators:
        class OpenAIGenerator:
            @staticmethod
            def run(
                self,
                prompt: str,
                **kwargs                    
            ) -> Dict[str, Any]: ...
        
        class OllamaGenerator:
            @staticmethod
            def run(
                self,
                prompt: str,
                **kwargs                    
            ) -> Dict[str, Any]: ...

        class HuggingFaceTGIGenerator:
            @staticmethod
            def run(
                self,
                prompt: str,
                **kwargs                    
            ) -> Dict[str, Any]: ...

class Pipeline:
    @staticmethod
    def run(
        self,
        prompt: str,
        **kwargs                    
    ) -> Dict[str, Any]: ...

class agents:
    class Agent:
        @staticmethod
        def run(
            self,
            prompt: str,
            **kwargs                    
        ) -> Dict[str, Any]: ...