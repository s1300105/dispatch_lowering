# sqlite_utils.pyi
from typing import Any, Dict, List, Optional, Union

class Database:
    def query(
        self,
        sql: str,
        *args: Any,
        **kwargs: Any
    ) -> List[Dict[str, Any]]: ...

    def execute(
        self,
        sql: str,
        *args: Any,
        **kwargs: Any
    ) -> Any: ...

class Table:
    def insert(
        self,
        record: Dict[str, Any],
        *args: Any,
        **kwargs: Any
    ) -> Any: ...

    def update(
        self,
        pk: Any,
        updates: Dict[str, Any],
        *args: Any,
        **kwargs: Any
    ) -> Any: ...