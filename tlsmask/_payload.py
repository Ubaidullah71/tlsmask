"""Pure translation from tlsmask's settings to the JSON tls-client reads.

Nothing here does I/O, so every option is tested without the library. Field
names are upstream's (cffi_src/types.go); tests/test_contract.py checks each
one against the snapshot of the pinned version.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from ._pins import LIBRARY_VERSION, PROFILES
from .exceptions import TLSClientException

# Session attribute -> customTlsClient field; sent only with client_identifier=None.
CUSTOM_FIELDS: dict[str, str] = {
    "ja3_string": "ja3String",
    "h2_settings": "h2Settings",
    "h2_settings_order": "h2SettingsOrder",
    "supported_signature_algorithms": "supportedSignatureAlgorithms",
    "supported_delegated_credentials_algorithms": "supportedDelegatedCredentialsAlgorithms",
    "supported_versions": "supportedVersions",
    "key_share_curves": "keyShareCurves",
    "cert_compression_algos": "certCompressionAlgos",
    "pseudo_header_order": "pseudoHeaderOrder",
    "connection_flow": "connectionFlow",
    "priority_frames": "priorityFrames",
    "header_priority": "headerPriority",
    "alpn_protocols": "alpnProtocols",
    "alps_protocols": "alpsProtocols",
    "record_size_limit": "recordSizeLimit",
    "ech_candidate_payloads": "ECHCandidatePayloads",
    "ech_candidate_cipher_suites": "ECHCandidateCipherSuites",
    "h3_settings": "h3Settings",
    "h3_settings_order": "h3SettingsOrder",
    "h3_pseudo_header_order": "h3PseudoHeaderOrder",
    "h3_priority_param": "h3PriorityParam",
    "h3_send_grease_frames": "h3SendGreaseFrames",
    "stream_id": "streamId",
}

# Session attribute -> top-level field that shapes the Go client.
CLIENT_FIELDS: dict[str, str] = {
    "random_tls_extension_order": "withRandomTLSExtensionOrder",
    "force_http1": "forceHttp1",
    "catch_panics": "catchPanics",
    "debug": "withDebug",
    "certificate_pinning": "certificatePinningHosts",
    "disable_http3": "disableHttp3",
    "with_protocol_racing": "withProtocolRacing",
    "disable_ipv4": "disableIPV4",
    "disable_ipv6": "disableIPV6",
    "local_address": "localAddress",
    "server_name_overwrite": "serverNameOverwrite",
    "transport_options": "transportOptions",
}

# Every Session attribute client_options() reads.
SETTINGS: tuple[str, ...] = (
    "client_identifier",
    "cert_compression_algo",
    *CUSTOM_FIELDS,
    *CLIENT_FIELDS,
)

# The proxy schemes tls-client can dial.
_PROXY_SCHEMES = frozenset({"http", "https", "socks5", "socks5h"})
# What requests' requote_uri leaves alone.
_SAFE = "!#$%&'()*+,/:;=?@[]~"
# The ALPS extension's code points (old and new).
_ALPS = frozenset({"17513", "17613"})
# JA3 extensions tls-client 1.16 cannot build without a matching setting; left
# out, the handshake fails later with messages like "tls: internal error".
_JA3_NEEDS = {
    "13": (
        "signature_algorithms",
        "supported_signature_algorithms",
        "supportedSignatureAlgorithms",
    ),
    "27": ("compress_certificate", "cert_compression_algos", "certCompressionAlgos"),
    "43": ("supported_versions", "supported_versions", "supportedVersions"),
    "51": ("key_share", "key_share_curves", "keyShareCurves"),
}
# Dots other scripts use in host names (NFKC leaves U+3002 as it is).
_IDEOGRAPHIC_DOTS = {0x3002: ".", 0xFF0E: ".", 0xFF61: "."}
# Characters a URL cannot carry as they are (besides controls and non-ASCII).
_UNSAFE = frozenset(' "<>\\^`{|}')


def check_profile(name: str) -> None:
    """Refuse a profile the pinned library does not ship: it would silently send its default."""
    if name in PROFILES:
        return
    close = difflib.get_close_matches(str(name), sorted(PROFILES), n=3, cutoff=0.6)
    hint = f" (did you mean {', '.join(close)}?)" if close else ""
    raise ValueError(
        f"tls-client {LIBRARY_VERSION} has no profile {name!r}{hint}; "
        "it would silently send its default browser instead"
    )


def custom_fields_set(settings: Mapping[str, Any]) -> bool:
    return any(settings.get(attr) is not None for attr in (*CUSTOM_FIELDS, "cert_compression_algo"))


def client_options(
    settings: Mapping[str, Any], *, timeout_ms: int, insecure_skip_verify: bool
) -> dict[str, Any]:
    """The fields that shape the Go client.

    Upstream builds a session's client on its first request and afterwards only
    changes its proxy, so tlsmask names each Go client after these fields
    (client_key): a different setting gets a client of its own.
    """
    # tls-client refuses these combinations only when it builds the client
    if settings.get("disable_ipv4") and settings.get("disable_ipv6"):
        raise ValueError("disable_ipv4 and disable_ipv6 together leave no way to connect")
    if settings.get("with_protocol_racing") and (
        settings.get("disable_http3") or settings.get("force_http1")
    ):
        raise ValueError(
            "with_protocol_racing races HTTP/3 against HTTP/2, so it cannot be combined "
            "with disable_http3 or force_http1"
        )
    options: dict[str, Any] = {
        "timeoutMilliseconds": int(timeout_ms),
        "insecureSkipVerify": bool(insecure_skip_verify),
        "withoutCookieJar": True,
    }
    for attr, field in CLIENT_FIELDS.items():
        value = settings.get(attr)
        if value is not None:
            options[field] = value
    identifier = settings.get("client_identifier")
    if identifier is None:
        options["customTlsClient"] = _custom_client(settings)
    else:
        check_profile(identifier)
        options["tlsClientIdentifier"] = identifier
    return options


def _custom_client(settings: Mapping[str, Any]) -> dict[str, Any]:
    if not settings.get("ja3_string"):
        raise ValueError(
            "client_identifier=None builds a custom TLS client, which needs ja3_string"
        )
    custom = {
        field: settings[attr]
        for attr, field in CUSTOM_FIELDS.items()
        if settings.get(attr) is not None
    }
    legacy = settings.get("cert_compression_algo")
    if legacy and "certCompressionAlgos" not in custom:
        # The old wrapper sent certCompressionAlgo (one string); v1.16 reads a list.
        custom["certCompressionAlgos"] = [legacy]
    # tls-client 1.16 builds the ALPN (and ALPS) extensions from these lists. Left
    # empty, it sends an empty ALPN extension and servers stall, and the old
    # tls-client package had no such settings, so default to what browsers offer.
    extensions = _ja3_extensions(custom["ja3String"])
    custom.setdefault("alpnProtocols", ["h2", "http/1.1"])
    if "alpsProtocols" not in custom and extensions & _ALPS:
        custom["alpsProtocols"] = ["h2"]
    for extension, (name, attr, field) in _JA3_NEEDS.items():
        if extension in extensions and not custom.get(field):
            raise ValueError(
                f"the JA3 string lists extension {extension} ({name}), "
                f"so tls-client also needs {attr}"
            )
    return custom


def _ja3_extensions(ja3: str) -> set[str]:
    fields = ja3.split(",")
    return set(fields[2].split("-")) if len(fields) > 2 else set()


def client_key(options: Mapping[str, Any]) -> str:
    blob = json.dumps(options, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def pick_proxy(proxy: str | Mapping[str, str] | None, url: str) -> str:
    """The proxy for `url`: a string as-is; from a dict, the entry for the URL's
    scheme, then "all", then any entry. A non-empty dict never means "no proxy"
    (the old wrapper read only "http" and sent the rest direct)."""
    return _checked_proxy(_choose_proxy(proxy, url))


def _choose_proxy(proxy: str | Mapping[str, str] | None, url: str) -> str:
    if not proxy:
        return ""
    if isinstance(proxy, str):
        return proxy
    scheme = urlsplit(url).scheme.lower()
    for key in (scheme, "all"):
        if proxy.get(key):
            return str(proxy[key])
    for value in proxy.values():
        if value:
            return str(value)
    return ""


def _checked_proxy(proxy: str) -> str:
    """`host:port` means an http:// proxy, as in requests. A proxy tls-client
    cannot use is refused here: tls-client itself would keep a broken client."""
    if not proxy:
        return ""
    if "://" not in proxy:
        proxy = f"http://{proxy}"
    parts = urlsplit(proxy)
    if parts.scheme.lower() not in _PROXY_SCHEMES or not parts.hostname:
        raise TLSClientException(
            f"tls-client cannot use a {parts.scheme}:// proxy at {parts.hostname or '?'}; "
            "it takes http://, https://, socks5:// or socks5h:// with a host and port"
        )
    return proxy


def with_params(url: str, *param_sets: Any) -> str:
    """`url` with each set's parameters appended to its query, keeping the existing ones."""
    chunks: list[str] = []
    for params in param_sets:
        if not params:
            continue
        if isinstance(params, (str, bytes)):
            text = params.decode() if isinstance(params, bytes) else params
            chunks.append(text.lstrip("?"))
            continue
        pairs = params.items() if isinstance(params, Mapping) else params
        chunks.append(urlencode([(k, v) for k, v in pairs if v is not None], doseq=True))
    chunks = [chunk for chunk in chunks if chunk]
    if not chunks:
        return url
    parts = urlsplit(url)
    query = "&".join(([parts.query] if parts.query else []) + chunks)
    return urlunsplit(parts._replace(query=query))


def _ascii_host(host: str) -> str:
    """A host name as browsers send it: each non-ASCII label lower-cased and in
    punycode. (Python's "idna" codec follows IDNA 2003, which turns ß into ss,
    and that is a different domain.)"""
    # compatibility forms (full-width letters, ideographic dots) become plain ones,
    # as a browser's URL parser does; lower() rather than casefold() keeps ß
    host = unicodedata.normalize("NFKC", host).translate(_IDEOGRAPHIC_DOTS)
    labels = []
    for label in host.split("."):
        if not label.isascii():
            label = "xn--" + unicodedata.normalize("NFC", label.lower()).encode("punycode").decode()
        labels.append(label)
    return ".".join(labels)


def requote(url: str) -> str:
    """`url` as a browser sends it: a non-ASCII host in punycode, and spaces and
    other characters a URL cannot carry percent-encoded. Existing %XX escapes are
    kept, and a URL that needs nothing is returned untouched."""
    if url.isascii() and not any(c in _UNSAFE or ord(c) < 33 or ord(c) == 127 for c in url):
        return url
    parts = urlsplit(url)
    netloc = parts.netloc
    if not netloc.isascii():
        userinfo, at, hostport = netloc.rpartition("@")
        host, colon, port = hostport.partition(":")
        netloc = f"{userinfo}{at}{_ascii_host(host)}{colon}{port}"
    return urlunsplit(
        (
            parts.scheme,
            netloc,
            quote(parts.path, safe=_SAFE),
            quote(parts.query, safe=_SAFE),
            quote(parts.fragment, safe=_SAFE),
        )
    )


def encode_body(data: Any, json_value: Any) -> tuple[str | bytes | None, str | None]:
    """(body, the Content-Type to add for this request only)."""
    if data is None and json_value is not None:
        if isinstance(json_value, (bytes, bytearray)):
            return bytes(json_value), "application/json"
        if isinstance(json_value, str):
            return json_value, "application/json"
        return json.dumps(json_value, separators=(",", ":")), "application/json"
    if data is None:
        return None, None
    if isinstance(data, (bytes, bytearray)):
        return bytes(data), None
    if isinstance(data, str):
        return data, None
    if isinstance(data, Mapping):
        data = list(data.items())
    if isinstance(data, (list, tuple)):
        return urlencode(data, doseq=True), "application/x-www-form-urlencoded"
    raise TypeError(
        f"data must be str, bytes, a dict or a list of pairs, not {type(data).__name__}"
    )


def header_order(headers: Iterable[str], order: Iterable[str] | None = None) -> list[str]:
    """Lower-cased: the names in `order`, then every other header in the order
    it was set. Upstream sorts any header missing from this list alphabetically.
    Host leads, as browsers send it over HTTP/1.1, unless `order` places it."""
    order = list(order or ())
    result: list[str] = [] if any(name.lower() == "host" for name in order) else ["host"]
    for name in [*order, *headers]:
        low = name.lower()
        if low not in result:
            result.append(low)
    return result


def request_payload(
    *,
    session_id: str,
    client: Mapping[str, Any],
    method: str,
    url: str,
    headers: Mapping[str, str],
    header_order: Iterable[str],
    body: str | bytes | None,
    proxy: str,
    is_rotating_proxy: bool = False,
) -> dict[str, Any]:
    payload = dict(client)
    payload.update(
        sessionId=session_id,
        requestMethod=method.upper(),
        requestUrl=url,
        headers=dict(headers),
        headerOrder=list(header_order),
        proxyUrl=proxy,
        isRotatingProxy=bool(is_rotating_proxy),
        followRedirects=False,  # tlsmask follows redirects itself, so each hop's cookies are kept
        isByteResponse=True,  # bodies come back as base64, so binary survives
        requestCookies=[],  # cookies travel in the Cookie header
    )
    if isinstance(body, bytes):
        payload["isByteRequest"] = True
        payload["requestBody"] = base64.b64encode(body).decode("ascii")
    elif body:
        payload["requestBody"] = body
    return payload
