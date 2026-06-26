from typing import Any, List, Optional

class RawSQL(Expression):
    def __init__(
        self,
        sql: str,
        params: Optional[List[Any]] = None,
        output_field: Optional[Any] = None,
    ) -> None: ...