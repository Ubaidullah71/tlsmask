"""The session's cookie store, and the glue between it and tls-client.

tlsmask keeps cookies only here, in Python. tls-client runs with its own jar
switched off, each request gets a `Cookie` header built from this jar, and
each response's `Set-Cookie` headers are stored back into it. So deleting or
clearing a cookie takes effect on the very next request (the old wrapper kept
a second copy inside Go that it could not delete).
"""

from __future__ import annotations

import copy
import email.message
import http.cookiejar
import threading
import urllib.request
from collections.abc import Iterable, Iterator, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_MISSING = object()


def make_cookie(
    name: str,
    value: str,
    *,
    domain: str = "",
    path: str = "/",
    secure: bool = False,
    expires: int | None = None,
    host_only: bool = False,
) -> http.cookiejar.Cookie:
    """A cookie as `CookieJar.set` stores it. An empty domain matches every host, as
    in requests; `host_only` keeps a cookie to exactly `domain`, as if that host set it."""
    return http.cookiejar.Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=domain,
        domain_specified=bool(domain) and not host_only,
        domain_initial_dot=domain.startswith("."),
        path=path,
        path_specified=True,
        secure=secure,
        expires=expires,
        discard=expires is None,
        comment=None,
        comment_url=None,
        rest={},
        rfc2109=False,
    )


class CookieJar(http.cookiejar.CookieJar):
    """A standard `http.cookiejar.CookieJar` with the dict-style helpers of requests' jar."""

    # The jar's lock can't be pickled; leave it out and make a new one (as requests does).
    def __getstate__(self) -> dict[str, Any]:
        state = self.__dict__.copy()
        state.pop("_cookies_lock", None)
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._cookies_lock = threading.RLock()

    def _matching(
        self, name: str, domain: str | None = None, path: str | None = None
    ) -> list[http.cookiejar.Cookie]:
        return [
            cookie
            for cookie in self
            if cookie.name == name
            and (domain is None or cookie.domain == domain)
            and (path is None or cookie.path == path)
        ]

    def get(
        self, name: str, default: Any = None, domain: str | None = None, path: str | None = None
    ) -> Any:
        found = self._matching(name, domain, path)
        return found[0].value if found else default

    def set(
        self,
        name: str,
        value: Any,
        *,
        domain: str = "",
        path: str = "/",
        secure: bool = False,
        expires: int | None = None,
    ) -> None:
        """Store a cookie; a value of None removes every cookie with that name."""
        if value is None:
            self._remove(name, domain or None)
            return
        self.set_cookie(
            make_cookie(name, str(value), domain=domain, path=path, secure=secure, expires=expires)
        )

    def _remove(self, name: str, domain: str | None = None) -> bool:
        found = self._matching(name, domain)
        for cookie in found:
            self.clear(cookie.domain, cookie.path, cookie.name)
        return bool(found)

    def get_dict(self, domain: str | None = None, path: str | None = None) -> dict[str, str]:
        return {
            cookie.name: cookie.value
            for cookie in self
            if (domain is None or cookie.domain == domain) and (path is None or cookie.path == path)
        }

    def update(self, other: Mapping[str, Any] | http.cookiejar.CookieJar) -> None:
        if isinstance(other, http.cookiejar.CookieJar):
            for cookie in other:
                self.set_cookie(copy.copy(cookie))
        else:
            for name, value in dict(other).items():
                self.set(name, value)

    def keys(self) -> list[str]:
        return [cookie.name for cookie in self]

    def values(self) -> list[str]:
        return [cookie.value for cookie in self]

    def items(self) -> list[tuple[str, str]]:
        return [(cookie.name, cookie.value) for cookie in self]

    def __getitem__(self, name: str) -> str:
        value = self.get(name, _MISSING)
        if value is _MISSING:
            raise KeyError(name)
        return value

    def __setitem__(self, name: str, value: Any) -> None:
        self.set(name, value)

    def __delitem__(self, name: str) -> None:
        if not self._remove(name):
            raise KeyError(name)

    def __contains__(self, name: object) -> bool:
        if isinstance(name, str):
            return any(cookie.name == name for cookie in self)
        return any(cookie is name for cookie in self)

    def pop(self, name: str, default: Any = _MISSING) -> Any:
        value = self.get(name, _MISSING)
        if value is _MISSING:
            if default is _MISSING:
                raise KeyError(name)
            return default
        self._remove(name)
        return value

    def setdefault(self, name: str, default: Any = None) -> Any:
        value = self.get(name, _MISSING)
        if value is _MISSING:
            self.set(name, default)
            return default
        return value

    def list_domains(self) -> list[str]:
        return list(dict.fromkeys(cookie.domain for cookie in self))

    def list_paths(self) -> list[str]:
        return list(dict.fromkeys(cookie.path for cookie in self))

    def multiple_domains(self) -> bool:
        """Whether some cookie name is set for more than one domain."""
        domains = [cookie.domain for cookie in self]
        return len(domains) != len(set(domains))

    def iterkeys(self) -> Iterator[str]:
        return (cookie.name for cookie in self)

    def itervalues(self) -> Iterator[str]:
        return (cookie.value for cookie in self)

    def iteritems(self) -> Iterator[tuple[str, str]]:
        return ((cookie.name, cookie.value) for cookie in self)

    def get_policy(self) -> http.cookiejar.CookiePolicy:
        return self._policy

    def copy(self) -> CookieJar:
        new = CookieJar(self._policy)
        new.update(self)
        return new


def without_userinfo(url: str) -> str:
    """`url` without a user name and password in it."""
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url
    return urlunsplit(parts._replace(netloc=parts.netloc.rpartition("@")[2]))


def cookie_header(jar: http.cookiejar.CookieJar, url: str) -> str | None:
    """The `Cookie` header `jar` sends to `url`, with domain, path, secure and expiry rules applied."""
    request = urllib.request.Request(without_userinfo(url))
    jar.add_cookie_header(request)
    return request.get_header("Cookie")


class _SetCookies:
    """The one thing `CookieJar.extract_cookies` reads from a response."""

    def __init__(self, values: Iterable[str]) -> None:
        self._headers = email.message.Message()
        for value in values:
            self._headers["Set-Cookie"] = value

    def info(self) -> email.message.Message:
        return self._headers


def extract_cookies(
    jar: http.cookiejar.CookieJar, url: str, set_cookie_values: Iterable[str]
) -> None:
    """Store the `Set-Cookie` values a response to `url` carried."""
    values = list(set_cookie_values)
    if values:
        jar.extract_cookies(_SetCookies(values), urllib.request.Request(without_userinfo(url)))
