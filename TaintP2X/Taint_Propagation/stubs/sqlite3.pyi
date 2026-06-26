# sqlite3.pyi
from typing import Any, Dict, List, Optional, Sequence, Union

class Connection:
    def execute(
        self,
        sql: str,
        parameters: Optional[Sequence[Any]] = None,
        **kwargs: Any
    ) -> Any: ...

    def executemany(
        self,
        sql: str,
        parameters: Optional[Sequence[Sequence[Any]]] = None,
        **kwargs: Any
    ) -> Any: ...

    def executescript(
        self,
        sql_script: str,
        **kwargs: Any
    ) -> Any: ...

class Cursor:
    def execute(
        self,
        sql: str,
        parameters: Optional[Sequence[Any]] = None,
        **kwargs: Any
    ) -> Any: ...

    def executemany(
        self,
        sql: str,
        parameters: Optional[Sequence[Sequence[Any]]] = None,
        **kwargs: Any
    ) -> Any: ...

    def executescript(
        self,
        sql_script: str,
        **kwargs: Any
    ) -> Any: ...