from typing import Any, Dict, List, Optional, Union

class extensions:
    class cursor:
        def execute(
            self,
            sql: str
        ) -> Any: ...