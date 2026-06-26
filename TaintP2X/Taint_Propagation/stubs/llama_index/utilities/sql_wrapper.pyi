from typing import Any, Dict, List, Optional, Union

class SQLDatabase:
    @staticmethod
    def run_sql(                   
        self,
        command: str                                  
    ) -> Tuple[str, Dict]: ...