"""AsyncSession: a Session for asyncio code.

Each request runs on a thread pool. ctypes releases the GIL for the native
call, so many requests are in flight at once; the pool size bounds how many.
"""

from __future__ import annotations

import asyncio
import functools
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .response import Response
from .sessions import Session

DEFAULT_WORKERS = 64

_shared: ThreadPoolExecutor | None = None
_shared_lock = threading.Lock()


def _shared_pool() -> ThreadPoolExecutor:
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = ThreadPoolExecutor(max_workers=DEFAULT_WORKERS, thread_name_prefix="tlsmask")
        return _shared


class AsyncSession:
    """Takes Session's arguments, plus `max_workers` for a pool of its own
    (by default all AsyncSessions share one pool of 64 threads)."""

    def __init__(self, *args: Any, max_workers: int | None = None, **kwargs: Any) -> None:
        object.__setattr__(self, "_session", Session(*args, **kwargs))
        object.__setattr__(self, "_max_workers", max_workers)
        object.__setattr__(self, "_own_pool", None)

    def _pool(self) -> ThreadPoolExecutor:
        if self._max_workers is None:
            return _shared_pool()
        if self._own_pool is None:  # made on first use, and again after close()
            pool = ThreadPoolExecutor(max_workers=self._max_workers, thread_name_prefix="tlsmask")
            object.__setattr__(self, "_own_pool", pool)
        return self._own_pool

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):  # our own attributes, missing while copy/pickle rebuild us
            raise AttributeError(name)
        return getattr(self._session, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._session, name, value)

    async def _run(self, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._pool(), functools.partial(function, *args, **kwargs)
        )

    async def execute_request(self, method: str, url: str, **kwargs: Any) -> Response:
        return await self._run(self._session.execute_request, method, url, **kwargs)

    request = execute_request

    async def get(self, url: str, **kwargs: Any) -> Response:
        return await self.execute_request("GET", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> Response:
        return await self.execute_request("OPTIONS", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Response:
        return await self.execute_request("HEAD", url, **kwargs)

    async def post(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:
        return await self.execute_request("POST", url, data=data, json=json, **kwargs)

    async def put(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:
        return await self.execute_request("PUT", url, data=data, json=json, **kwargs)

    async def patch(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:
        return await self.execute_request("PATCH", url, data=data, json=json, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> Response:
        return await self.execute_request("DELETE", url, **kwargs)

    async def close(self) -> None:
        """Close the session's connections. Safe to call twice; the session still
        works afterwards, like a Session does."""
        await self._run(self._session.close)
        pool = self._own_pool
        if pool is not None:
            object.__setattr__(self, "_own_pool", None)
            pool.shutdown(wait=False)

    async def __aenter__(self) -> AsyncSession:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()
