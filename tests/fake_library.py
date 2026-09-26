"""A stand-in for bogdanfinn's library, shaped like v1.16.0's C API.

Each function takes the JSON bytes tlsmask sends and returns the address of a
C string holding the answer, which is what ctypes hands back from the real
library. Every call and every freeMemory is recorded.
"""

from __future__ import annotations

import base64
import ctypes
import json
import threading
from typing import Any


def reply(
    status: int = 200,
    body: bytes = b"",
    headers: dict[str, list[str]] | None = None,
    url: str = "",
    protocol: str = "HTTP/2.0",
    mime: str = "application/octet-stream",
) -> dict[str, Any]:
    """An answer shaped like upstream's Response, the body as isByteResponse sends it."""
    return {
        "status": status,
        "body": f"data:{mime};base64,{base64.b64encode(body).decode()}",
        "headers": headers or {},
        "target": url,
        "usedProtocol": protocol,
        "cookies": {},
    }


def failure(message: str) -> dict[str, Any]:
    """Upstream's answer when it could not make the request."""
    return {"status": 0, "body": message, "headers": None, "cookies": None}


class FakeLibrary:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.freed: list[str] = []
        self.replies: list[Any] = []  # queued answers for `request`: dicts, or raw bytes
        self._buffers: list[Any] = []
        self._lock = threading.Lock()
        self._next_id = 0

    @property
    def requests(self) -> list[dict[str, Any]]:
        return [payload for name, payload in self.calls if name == "request"]

    def _answer(self, value: Any) -> int:
        with self._lock:
            if isinstance(value, dict):
                self._next_id += 1
                value = json.dumps({"id": f"answer-{self._next_id}", **value}).encode()
            buffer = ctypes.create_string_buffer(value)
            self._buffers.append(buffer)
            return ctypes.addressof(buffer)

    def request(self, raw: bytes) -> int:
        payload = json.loads(raw)
        with self._lock:
            self.calls.append(("request", payload))
            queued = self.replies.pop(0) if self.replies else None
        if queued is None:
            queued = reply(url=payload.get("requestUrl", ""))
        return self._answer(queued)

    def destroySession(self, raw: bytes) -> int:
        with self._lock:
            self.calls.append(("destroySession", json.loads(raw)))
        return self._answer({"success": True})

    def freeMemory(self, raw: bytes) -> None:
        with self._lock:
            self.freed.append(raw.decode())
