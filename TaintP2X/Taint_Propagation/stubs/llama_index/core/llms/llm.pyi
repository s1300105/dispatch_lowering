from typing import Any, Dict, List, Optional, Union

class LLM:
    @staticmethod
    def predict(                   
        *args: Any                                  
    ) -> Dict[str, Any]: ...

    @staticmethod
    def predict_and_call(                   
        *args: Any                                  
    ) -> Dict[str, Any]: ...