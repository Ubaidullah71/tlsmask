"""Pure translation from settings to the JSON tls-client reads."""

from __future__ import annotations

import pytest

from tlsmask import _payload

BASE = {"client_identifier": "chrome_150"}


def test_client_options_for_a_profile():
    options = _payload.client_options(
        {**BASE, "catch_panics": True, "certificate_pinning": None},
        timeout_ms=1500,
        insecure_skip_verify=True,
    )
    assert options == {
        "timeoutMilliseconds": 1500,
        "insecureSkipVerify": True,
        "withoutCookieJar": True,
        "catchPanics": True,
        "tlsClientIdentifier": "chrome_150",
    }


def test_a_custom_client_translates_the_old_singular_cert_compression():
    options = _payload.client_options(
        {"client_identifier": None, "ja3_string": "771,1,0,29,0", "cert_compression_algo": "zlib"},
        timeout_ms=1,
        insecure_skip_verify=False,
    )
    assert "tlsClientIdentifier" not in options
    assert options["customTlsClient"] == {
        "ja3String": "771,1,0,29,0",
        "certCompressionAlgos": ["zlib"],
        "alpnProtocols": ["h2", "http/1.1"],
    }
    both = _payload.client_options(
        {
            "client_identifier": None,
            "ja3_string": "j",
            "cert_compression_algo": "zlib",
            "cert_compression_algos": ["brotli"],
        },
        timeout_ms=1,
        insecure_skip_verify=False,
    )
    assert both["customTlsClient"]["certCompressionAlgos"] == ["brotli"]


def test_a_custom_client_needs_ja3():
    with pytest.raises(ValueError, match="ja3_string"):
        _payload.client_options(
            {"client_identifier": None}, timeout_ms=1, insecure_skip_verify=False
        )


def test_check_profile_suggests_close_names():
    with pytest.raises(ValueError, match="did you mean.*chrome_150"):
        _payload.check_profile("chrome_15")
    with pytest.raises(ValueError, match="confirmed_android"):
        _payload.check_profile("confirmed_android_2")
    _payload.check_profile("chrome_150")


def test_the_client_key_follows_every_client_setting():
    a = _payload.client_options(BASE, timeout_ms=1000, insecure_skip_verify=False)
    b = _payload.client_options(BASE, timeout_ms=2000, insecure_skip_verify=False)
    assert _payload.client_key(a) == _payload.client_key(dict(a))
    assert _payload.client_key(a) != _payload.client_key(b)
    assert len(_payload.client_key(a)) == 16


@pytest.mark.parametrize(
    "proxy, url, expected",
    [
        (None, "https://x", ""),
        ({}, "https://x", ""),
        ("http://p:1", "https://x", "http://p:1"),
        ({"https": "http://s:1"}, "http://x", "http://s:1"),
        ({"http": "http://a:1", "https": "http://b:2"}, "https://x", "http://b:2"),
        ({"http": "http://a:1", "https": "http://b:2"}, "http://x", "http://a:1"),
        ({"all": "http://c:3", "http": "http://a:1"}, "https://x", "http://c:3"),
        ({"http": ""}, "https://x", ""),
    ],
)
def test_pick_proxy(proxy, url, expected):
    assert _payload.pick_proxy(proxy, url) == expected


@pytest.mark.parametrize(
    "url, sets, expected",
    [
        ("https://x/p", ({"a": "1"},), "https://x/p?a=1"),
        ("https://x/p?z=0", ({"a": "1"}, {"b": ["2", "3"]}), "https://x/p?z=0&a=1&b=2&b=3"),
        ("https://x/p", ({"a": None},), "https://x/p"),
        ("https://x/p#frag", ([("a", "1")],), "https://x/p?a=1#frag"),
        ("https://x/p", ("?raw=1",), "https://x/p?raw=1"),
        ("https://x/p", (None, {}), "https://x/p"),
    ],
)
def test_with_params(url, sets, expected):
    assert _payload.with_params(url, *sets) == expected


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://x.test/a%20b?q=1", "https://x.test/a%20b?q=1"),
        (
            "https://bücher.test/straße?q=grüße",
            "https://xn--bcher-kva.test/stra%C3%9Fe?q=gr%C3%BC%C3%9Fe",
        ),
        ("http://u:p@bücher.test:8080/", "http://u:p@xn--bcher-kva.test:8080/"),
        ("https://x.test/a b?q=x y", "https://x.test/a%20b?q=x%20y"),
        ("https://straße.de/", "https://xn--strae-oqa.de/"),
        ("https://BÜCHER.test/", "https://xn--bcher-kva.test/"),
        ("https://ｅｘａｍｐｌｅ.com/", "https://example.com/"),
        ("https://bücher。example/", "https://xn--bcher-kva.example/"),
    ],
)
def test_requote(url, expected):
    assert _payload.requote(url) == expected


@pytest.mark.parametrize(
    "data, json_value, expected",
    [
        (None, {"a": 1}, ('{"a":1}', "application/json")),
        (None, '{"raw":1}', ('{"raw":1}', "application/json")),
        ({"a": "1"}, {"ignored": True}, ("a=1", "application/x-www-form-urlencoded")),
        ([("a", "1"), ("a", "2")], None, ("a=1&a=2", "application/x-www-form-urlencoded")),
        (b"\x00", None, (b"\x00", None)),
        (bytearray(b"\x01"), None, (b"\x01", None)),
        ("text", None, ("text", None)),
        (None, None, (None, None)),
    ],
)
def test_encode_body(data, json_value, expected):
    assert _payload.encode_body(data, json_value) == expected


def test_encode_body_refuses_what_it_cannot_send():
    with pytest.raises(TypeError, match="data must be"):
        _payload.encode_body(object(), None)


def test_header_order():
    assert _payload.header_order(["User-Agent", "Accept", "X-B"]) == [
        "host",
        "user-agent",
        "accept",
        "x-b",
    ]
    assert _payload.header_order(["User-Agent", "Accept"], ["accept", "cookie"]) == [
        "host",
        "accept",
        "cookie",
        "user-agent",
    ]


def test_request_payload_bodies_and_fixed_fields():
    common = dict(
        session_id="s",
        client={"tlsClientIdentifier": "chrome_150"},
        method="post",
        url="https://x/",
        headers={"A": "1"},
        header_order=["a"],
        proxy="",
    )
    as_bytes = _payload.request_payload(body=b"\x00\xff", **common)
    assert as_bytes["isByteRequest"] is True and as_bytes["requestBody"] == "AP8="
    assert as_bytes["requestMethod"] == "POST"
    as_text = _payload.request_payload(body="hi", **common)
    assert as_text["requestBody"] == "hi" and "isByteRequest" not in as_text
    assert "requestBody" not in _payload.request_payload(body=None, **common)
    assert as_text["followRedirects"] is False
    assert as_text["isByteResponse"] is True
    assert as_text["requestCookies"] == []
    assert as_text["tlsClientIdentifier"] == "chrome_150" and as_text["sessionId"] == "s"


CHROME_JA3 = (
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
    "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
)


FULL = {
    "client_identifier": None,
    "ja3_string": CHROME_JA3,
    "supported_signature_algorithms": ["ECDSAWithP256AndSHA256"],
    "supported_versions": ["1.3", "1.2"],
    "key_share_curves": ["X25519"],
    "cert_compression_algos": ["brotli"],
}


@pytest.mark.parametrize(
    "missing",
    [
        "supported_signature_algorithms",
        "supported_versions",
        "key_share_curves",
        "cert_compression_algos",
    ],
)
def test_a_custom_client_names_the_setting_its_ja3_needs(missing):
    # tls-client only fails later, with messages like "tls: internal error"
    settings = {k: v for k, v in FULL.items() if k != missing}
    with pytest.raises(ValueError, match=missing):
        _payload.client_options(settings, timeout_ms=1, insecure_skip_verify=False)


def test_the_old_singular_cert_compression_setting_counts():
    settings = {k: v for k, v in FULL.items() if k != "cert_compression_algos"}
    settings["cert_compression_algo"] = "brotli"
    _payload.client_options(settings, timeout_ms=1, insecure_skip_verify=False)


def test_a_custom_client_offers_alpn_like_a_browser_unless_told_otherwise():
    # without ALPN protocols tls-client 1.16 sends an empty ALPN extension and
    # servers stall; the old tls-client package had no such setting
    custom = _payload.client_options(FULL, timeout_ms=1, insecure_skip_verify=False)[
        "customTlsClient"
    ]
    assert custom["alpnProtocols"] == ["h2", "http/1.1"]
    assert custom["alpsProtocols"] == ["h2"]  # the JA3 lists extension 17513 (ALPS)
    chosen = _payload.client_options(
        {**FULL, "alpn_protocols": ["http/1.1"]}, timeout_ms=1, insecure_skip_verify=False
    )["customTlsClient"]
    assert chosen["alpnProtocols"] == ["http/1.1"]
    no_alps = _payload.client_options(
        {"client_identifier": None, "ja3_string": "771,4865,0-16,29,0"},
        timeout_ms=1,
        insecure_skip_verify=False,
    )["customTlsClient"]
    assert "alpsProtocols" not in no_alps
