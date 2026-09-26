"""What a request returns: the old wrapper's Response, with the body kept as bytes."""

from __future__ import annotations

import base64
import email.message
import json as jsonlib
from collections.abc import Mapping
from http import HTTPStatus
from typing import Any

from .cookies import CookieJar
from .exceptions import HTTPError
from .structures import CaseInsensitiveDict


def decode_body(body: str) -> bytes:
    """tlsmask asks for every body as bytes (isByteResponse), which upstream sends
    as `data:<mime>;base64,<data>`. Anything else (library error text) is taken as text."""
    if body.startswith("data:"):
        _head, sep, data = body.partition(";base64,")
        if sep:
            return base64.b64decode(data)
    return body.encode("utf-8", "surrogateescape")


def charset_of(content_type: Any) -> str | None:
    if isinstance(content_type, list):
        content_type = content_type[0] if content_type else None
    if not content_type:
        return None
    message = email.message.Message()
    message["content-type"] = str(content_type)
    return message.get_content_charset()


def set_cookie_values(answer: Mapping[str, Any]) -> list[str]:
    for name, values in (answer.get("headers") or {}).items():
        if name.lower() == "set-cookie":
            return [str(v) for v in values] if isinstance(values, list) else [str(values)]
    return []


class Response:
    def __init__(self) -> None:
        self.url: str | None = None
        self.status_code: int | None = None
        self.headers: CaseInsensitiveDict = CaseInsensitiveDict()
        self.cookies: CookieJar = CookieJar()  # the cookies this response set
        self.history: list[Response] = []  # the redirects that led here
        self.protocol: str = ""  # e.g. "HTTP/2.0"
        self.encoding: str | None = None
        self._content: bytes = b""
        self._text: str | None = None

    @property
    def content(self) -> bytes:
        return self._content

    @property
    def text(self) -> str:
        if self._text is None:
            try:
                self._text = self._content.decode(self.encoding or "utf-8", "replace")
            except LookupError:  # a charset Python does not know
                self._text = self._content.decode("utf-8", "replace")
        return self._text

    @text.setter
    def text(self, value: str) -> None:
        self._text = value

    @property
    def ok(self) -> bool:
        return self.status_code is not None and self.status_code < 400

    @property
    def reason(self) -> str:
        try:
            return HTTPStatus(self.status_code).phrase
        except (ValueError, TypeError):
            return ""

    def json(self, **kwargs: Any) -> Any:
        if self._text is None and not self.encoding and self._content:
            # no declared charset: let json find it (UTF-8, -16 or -32, with or without a BOM)
            return jsonlib.loads(self._content, **kwargs)
        return jsonlib.loads(self.text.lstrip(chr(0xFEFF)), **kwargs)

    def raise_for_status(self) -> None:
        if not self.ok:
            raise HTTPError(f"{self.status_code} {self.reason} for url: {self.url}", response=self)

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


def build_response(answer: Mapping[str, Any], request_url: str) -> Response:
    response = Response()
    response.url = str(answer.get("target") or request_url)
    response.status_code = int(answer.get("status") or 0)
    response.protocol = str(answer.get("usedProtocol") or "")
    headers = CaseInsensitiveDict()
    for name, values in (answer.get("headers") or {}).items():
        if isinstance(values, list):
            headers[name] = values[0] if len(values) == 1 else list(values)
        else:
            headers[name] = values
    response.headers = headers
    response._content = decode_body(str(answer.get("body") or ""))
    response.encoding = charset_of(headers.get("content-type"))
    return response
