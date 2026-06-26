from typing import Any, Dict, List, Optional, Union

class connector:
    class cursor:
        class MySQLCursor:
            def execute(
                self,
                sql: str
            ) -> Any: ...