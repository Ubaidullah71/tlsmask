"""The errors tlsmask raises."""

from __future__ import annotations

from typing import Any


class TLSClientException(IOError):
    """tls-client could not make the request, or its library is missing or not the pinned file."""


# The old tls-client package's (misspelled) name, so existing `except` clauses keep working.
TLSClientExeption = TLSClientException


class HTTPError(TLSClientException):
    """Raised by Response.raise_for_status() for a 4xx or 5xx answer."""

    def __init__(self, message: str, response: Any = None) -> None:
        super().__init__(message)
        self.response = response
