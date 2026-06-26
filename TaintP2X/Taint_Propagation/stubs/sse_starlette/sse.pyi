from typing import Any, AsyncGenerator, Dict, Optional, Union

class EventSourceResponse:
    def __init__(
        self,
        content: Union[AsyncGenerator[Dict[str, Any], None], Any],
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None
    ) -> None: ...

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None: ...

    async def stream_response(self, send: Any) -> None: ...

    async def body_iterator(self) -> AsyncGenerator[bytes, None]: ...