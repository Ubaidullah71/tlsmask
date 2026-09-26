"""Session: the old `tls_client.Session` API on top of tlsmask's safe core.

Every constructor argument of the old wrapper is accepted with the same
meaning (plus tls-client 1.16's newer options) and becomes an attribute of the
same name. What changed, and why, is in README.md ("Coming from tls-client")
and pinned by tests/test_sessions.py.
"""

from __future__ import annotations

import http.cookiejar
import threading
import uuid
import warnings
import weakref
from collections import OrderedDict
from collections.abc import Mapping
from typing import Any
from urllib.parse import SplitResult, urljoin, urlsplit

from . import _library, _payload
from ._pins import DEFAULT_PROFILE
from ._version import __version__
from .cookies import CookieJar, cookie_header, extract_cookies, make_cookie, without_userinfo
from .exceptions import TLSClientException
from .profiles import ClientIdentifier
from .response import Response, build_response, set_cookie_values
from .structures import CaseInsensitiveDict

MAX_REDIRECTS = 30
DEFAULT_TIMEOUT = 30  # seconds, as in the old tls-client package
# Upstream keeps a Go client per sessionId until it is destroyed, and each
# distinct client setting gets its own, so the oldest are dropped past this many.
MAX_GO_CLIENTS = 8
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_BODY_HEADERS = ("content-type", "content-length", "transfer-encoding")
_SAFE_TO_REPEAT = frozenset({"GET", "HEAD", "OPTIONS"})


class Session:
    def __init__(
        self,
        client_identifier: ClientIdentifier | None = DEFAULT_PROFILE,
        ja3_string: str | None = None,
        h2_settings: dict[str, int] | None = None,
        h2_settings_order: list[str] | None = None,
        supported_signature_algorithms: list[str] | None = None,
        supported_delegated_credentials_algorithms: list[str] | None = None,
        supported_versions: list[str] | None = None,
        key_share_curves: list[str] | None = None,
        cert_compression_algo: str | None = None,
        additional_decode: str | None = None,
        pseudo_header_order: list[str] | None = None,
        connection_flow: int | None = None,
        priority_frames: list[dict[str, Any]] | None = None,
        header_order: list[str] | None = None,
        header_priority: dict[str, Any] | None = None,
        random_tls_extension_order: bool = False,
        force_http1: bool = False,
        catch_panics: bool = True,
        debug: bool = False,
        certificate_pinning: dict[str, list[str]] | None = None,
        *,
        cert_compression_algos: list[str] | None = None,
        alpn_protocols: list[str] | None = None,
        alps_protocols: list[str] | None = None,
        record_size_limit: int | None = None,
        ech_candidate_payloads: list[int] | None = None,
        ech_candidate_cipher_suites: list[dict[str, str]] | None = None,
        h3_settings: dict[str, int] | None = None,
        h3_settings_order: list[str] | None = None,
        h3_pseudo_header_order: list[str] | None = None,
        h3_priority_param: int | None = None,
        h3_send_grease_frames: bool | None = None,
        stream_id: int | None = None,
        disable_http3: bool = False,
        with_protocol_racing: bool = False,
        disable_ipv4: bool = False,
        disable_ipv6: bool = False,
        local_address: str | None = None,
        server_name_overwrite: str | None = None,
        transport_options: dict[str, Any] | None = None,
        is_rotating_proxy: bool = False,
    ) -> None:
        # Every argument becomes an attribute of the same name, as in the old
        # wrapper; each request reads them back, so changing one later applies.
        options = dict(locals())
        del options["self"]
        for name, value in options.items():
            setattr(self, name, value)
        if additional_decode is not None:
            warnings.warn(
                "additional_decode has no effect: tls-client decodes every Content-Encoding itself",
                DeprecationWarning,
                stacklevel=2,
            )
        if client_identifier is not None and _payload.custom_fields_set(options):
            warnings.warn(
                "ja3_string and the other custom TLS settings apply only with "
                f"client_identifier=None; this session sends the {client_identifier} profile",
                UserWarning,
                stacklevel=2,
            )
        self._session_id = str(uuid.uuid4())
        self._go_sessions: OrderedDict[str, None] = OrderedDict()
        self._broken: dict[str, int] = {}  # client key -> Go clients tls-client failed to build
        self._lock = threading.Lock()
        # A session dropped without close() still ends its Go clients. Not at
        # interpreter exit, where the process is going away anyway.
        finalizer = weakref.finalize(self, _destroy, self._go_sessions, self._lock, quiet=True)
        finalizer.atexit = False
        self.headers: Any = CaseInsensitiveDict(
            {
                "User-Agent": f"tlsmask/{__version__}",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept": "*/*",
                "Connection": "keep-alive",
            }
        )
        self.proxies: Any = {}
        self.params: Any = {}
        self.cookies: Any = CookieJar()
        self.timeout_seconds: float = DEFAULT_TIMEOUT
        # A bad profile or custom client fails here, not at the first request.
        _payload.client_options(self._settings(), timeout_ms=1, insecure_skip_verify=False)

    # --- public API -------------------------------------------------------------

    def execute_request(
        self,
        method: str,
        url: str,
        params: Any = None,
        data: Any = None,
        headers: Mapping[str, Any] | None = None,
        cookies: Mapping[str, Any] | http.cookiejar.CookieJar | None = None,
        json: Any = None,
        allow_redirects: bool = False,
        insecure_skip_verify: bool = False,
        timeout_seconds: float | None = None,
        proxy: str | Mapping[str, str] | None = None,
        *,
        timeout: float | None = None,
        header_order: list[str] | None = None,
    ) -> Response:
        if isinstance(url, (bytes, bytearray)):
            url = bytes(url).decode("utf-8")
        if urlsplit(url).scheme.lower() not in ("http", "https"):
            # the old wrapper raised its own exception here too (from Go)
            raise TLSClientException(f"{url!r} is not an http:// or https:// URL")
        if timeout is None:
            timeout = timeout_seconds or self.timeout_seconds or DEFAULT_TIMEOUT
        client = _payload.client_options(
            self._settings(),
            timeout_ms=_milliseconds(timeout),
            insecure_skip_verify=insecure_skip_verify,
        )
        session_id = self._go_session(client)
        proxies = proxy if proxy is not None else self.proxies
        order = header_order if header_order is not None else self.header_order

        # one ASCII form of the URL from here on, so cookies are stored under the
        # same host name that redirects (and upstream) report back
        url = _payload.requote(_payload.with_params(url, *self._param_sets(params)))
        jar = self._jar()
        send_jar = jar
        if cookies:
            send_jar = CookieJar()
            send_jar.update(jar)
            _add_request_cookies(send_jar, cookies, urlsplit(url).hostname or "")
        body, content_type = _payload.encode_body(data, json)
        request_headers = _merge_headers(self.headers, headers)
        if content_type and "content-type" not in request_headers:
            request_headers["Content-Type"] = content_type  # this request only

        history: list[Response] = []
        while True:
            response = self._send(
                session_id,
                client,
                method,
                url,
                request_headers,
                order,
                body,
                jar,
                send_jar,
                proxies,
            )
            location = _location(response) if allow_redirects else None
            if location is None:
                break
            if len(history) >= MAX_REDIRECTS:
                raise TLSClientException(f"too many redirects (more than {MAX_REDIRECTS})")
            history.append(response)
            next_url = _payload.requote(urljoin(response.url or url, location))
            method, body, request_headers = _follow(
                response.status_code or 0, method, body, request_headers, url, next_url
            )
            url = next_url
        response.history = history
        return response

    request = execute_request

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.execute_request("GET", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        return self.execute_request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        return self.execute_request("HEAD", url, **kwargs)

    def post(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:
        return self.execute_request("POST", url, data=data, json=json, **kwargs)

    def put(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:
        return self.execute_request("PUT", url, data=data, json=json, **kwargs)

    def patch(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:
        return self.execute_request("PATCH", url, data=data, json=json, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Response:
        return self.execute_request("DELETE", url, **kwargs)

    def close(self) -> None:
        """Destroy every Go client this session created. Safe to call twice."""
        _destroy(self._go_sessions, self._lock)

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # --- internals --------------------------------------------------------------

    def _settings(self) -> dict[str, Any]:
        return {name: getattr(self, name, None) for name in _payload.SETTINGS}

    def _go_session(self, client: Mapping[str, Any]) -> str:
        key = _payload.client_key(client)
        evicted: list[str] = []
        with self._lock:
            session_id = f"{self._session_id}-{key}-{self._broken.get(key, 0)}"
            self._go_sessions[session_id] = None
            self._go_sessions.move_to_end(session_id)
            while len(self._go_sessions) > MAX_GO_CLIENTS:
                evicted.append(self._go_sessions.popitem(last=False)[0])
        for old in evicted:
            _library.call("destroySession", {"sessionId": old})
        return session_id

    def _abandon(self, session_id: str) -> None:
        """Forget a Go client tls-client failed to build. tls-client keeps a nil
        entry for it, and destroying that entry is a Go panic that ends the whole
        process, so it is never destroyed; the next request gets a fresh id."""
        key = session_id.rsplit("-", 2)[-2]
        with self._lock:
            self._go_sessions.pop(session_id, None)
            self._broken[key] = self._broken.get(key, 0) + 1

    def _jar(self) -> http.cookiejar.CookieJar:
        if not isinstance(self.cookies, http.cookiejar.CookieJar):
            # `session.cookies = {"name": "value"}`, a habit from the old wrapper
            jar = CookieJar()
            jar.update(self.cookies or {})
            self.cookies = jar
        return self.cookies

    def _param_sets(self, params: Any) -> tuple[Any, ...]:
        if isinstance(self.params, Mapping) and isinstance(params, Mapping):
            return ({**self.params, **params},)
        return (self.params, params)

    def _send(
        self,
        session_id: str,
        client: Mapping[str, Any],
        method: str,
        url: str,
        headers: CaseInsensitiveDict,
        order: list[str] | None,
        body: str | bytes | None,
        jar: http.cookiejar.CookieJar,
        send_jar: http.cookiejar.CookieJar,
        proxies: Any,
    ) -> Response:
        headers = CaseInsensitiveDict(headers)
        if "cookie" not in headers:
            cookie = cookie_header(send_jar, url)
            if cookie:
                headers["Cookie"] = cookie
        wire_headers = {name: _header_value(value) for name, value in headers.items()}
        payload = _payload.request_payload(
            session_id=session_id,
            client=client,
            method=method,
            url=_payload.requote(url),
            headers=wire_headers,
            header_order=_payload.header_order(wire_headers, order),
            body=body,
            proxy=_payload.pick_proxy(proxies, url),
            is_rotating_proxy=bool(self.is_rotating_proxy),
        )
        answer = _library.call("request", payload)
        if int(answer.get("status") or 0) == 0:
            retry_headers = _without_brotli(method, answer, wire_headers)
            if retry_headers is not None:
                payload["headers"] = retry_headers
                payload["headerOrder"] = _payload.header_order(retry_headers, order)
                answer = _library.call("request", payload)
        if int(answer.get("status") or 0) == 0:
            reason = str(answer.get("body") or "tls-client could not make the request")
            if reason.startswith("failed to build client"):
                self._abandon(session_id)
            raise TLSClientException(f"{method.upper()} {without_userinfo(url)}: {reason}")
        response = build_response(answer, url)
        set_cookies = set_cookie_values(answer)
        extract_cookies(jar, url, set_cookies)
        if send_jar is not jar:
            extract_cookies(send_jar, url, set_cookies)
        extract_cookies(response.cookies, url, set_cookies)
        return response


def _destroy(
    go_sessions: OrderedDict[str, None], lock: threading.Lock, quiet: bool = False
) -> None:
    with lock:
        session_ids = list(go_sessions)
        go_sessions.clear()
    for session_id in session_ids:
        try:
            _library.call("destroySession", {"sessionId": session_id})
        except Exception:
            if not quiet:  # a garbage-collected session has nobody to tell
                raise


def _merge_headers(session_headers: Any, request_headers: Any) -> CaseInsensitiveDict:
    merged = CaseInsensitiveDict(session_headers or {})
    if request_headers:
        merged.update(request_headers)
    for name in [name for name, value in merged.items() if value is None]:
        del merged[name]
    return merged


def _add_request_cookies(jar: CookieJar, cookies: Any, host: str) -> None:
    """Cookies passed to one request go to that request's host only, even when a
    redirect leads somewhere else (a jar's cookies keep their own domains)."""
    if isinstance(cookies, http.cookiejar.CookieJar):
        jar.update(cookies)
        return
    for name, value in dict(cookies).items():
        if value is not None:
            jar.set_cookie(make_cookie(name, str(value), domain=host, host_only=True))


def _milliseconds(timeout: Any) -> int:
    """A timeout in seconds, or requests' (connect, read) pair, in milliseconds.
    tls-client has one timeout for the whole request, so a pair is added up."""
    if isinstance(timeout, (tuple, list)):
        timeout = sum(part for part in timeout if part is not None)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0 < timeout < float("inf")
    ):
        raise ValueError(f"timeout must be a positive number of seconds, not {timeout!r}")
    return min(max(1, round(timeout * 1000)), 2**31 - 1)


def _header_value(value: Any) -> str:
    return value.decode("latin-1") if isinstance(value, (bytes, bytearray)) else str(value)


def _location(response: Response) -> str | None:
    if response.status_code not in _REDIRECT_CODES:
        return None
    location = response.headers.get("location")
    if isinstance(location, list):
        location = location[0] if location else None
    return location or None


def _follow(
    status: int,
    method: str,
    body: str | bytes | None,
    headers: CaseInsensitiveDict,
    old_url: str,
    new_url: str,
) -> tuple[str, str | bytes | None, CaseInsensitiveDict]:
    """The next hop's method, body and headers, by the browser (Fetch standard) rules."""
    headers = CaseInsensitiveDict(headers)
    method = method.upper()
    if (status in (301, 302) and method == "POST") or (
        status == 303 and method not in ("GET", "HEAD")
    ):
        method, body = "GET", None
        for name in _BODY_HEADERS:
            headers.pop(name, None)
    if not _keeps_credentials(old_url, new_url):
        headers.pop("authorization", None)
        headers.pop("cookie", None)
    return method, body, headers


def _port(parts: SplitResult) -> int | None:
    return parts.port or {"http": 80, "https": 443}.get(parts.scheme)


def _keeps_credentials(old_url: str, new_url: str) -> bool:
    """Credentials follow a redirect only to the same origin, or on an upgrade from
    http to https on the same host and default ports (as requests does)."""
    old, new = urlsplit(old_url), urlsplit(new_url)
    if old.hostname != new.hostname:
        return False
    if old.scheme == new.scheme and _port(old) == _port(new):
        return True
    return (old.scheme, new.scheme) == ("http", "https") and (_port(old), _port(new)) == (80, 443)


def _without_brotli(
    method: str, answer: Mapping[str, Any], headers: Mapping[str, str]
) -> dict[str, str] | None:
    """Headers for asking once more without brotli, or None.

    tls-client 1.16.0 cannot decode an empty brotli body: a HEAD, 204 or 304 from a
    server that answers `Content-Encoding: br` fails with "unexpected EOF". A request
    that is safe to repeat is asked again without br (gzip, deflate and zstd decode fine).
    """
    if method.upper() not in _SAFE_TO_REPEAT or "unexpected EOF" not in str(answer.get("body")):
        return None
    for name, value in headers.items():
        if name.lower() == "accept-encoding":
            codings = [coding.strip() for coding in value.split(",") if coding.strip()]
            kept = [coding for coding in codings if coding.lower() != "br"]
            if len(kept) == len(codings):
                return None
            return {**headers, name: ", ".join(kept) or "identity"}
    # Without the header the library offers "gzip, deflate, br" itself.
    return {**headers, "Accept-Encoding": "gzip, deflate"}
