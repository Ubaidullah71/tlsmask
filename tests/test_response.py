from __future__ import annotations

import codecs
import pickle

import pytest
from fake_library import reply

from tlsmask import HTTPError
from tlsmask.response import build_response, decode_body, set_cookie_values


def test_bodies_come_back_byte_for_byte():
    r = build_response(reply(body=bytes(range(256))), "https://x.test/")
    assert r.content == bytes(range(256))


def test_a_plain_text_body_is_tolerated():
    assert decode_body("plain error text") == b"plain error text"
    assert decode_body("data:text/plain; charset=utf-8;base64,aGk=") == b"hi"


def test_text_uses_the_declared_charset():
    r = build_response(
        reply(
            body="é".encode("latin-1"),
            headers={"Content-Type": ["text/plain; charset=ISO-8859-1"]},
        ),
        "https://x.test/",
    )
    assert r.encoding == "iso-8859-1" and r.text == "é"


def test_text_falls_back_to_utf8_and_never_raises():
    r = build_response(
        reply(body=b"\xff ok", headers={"Content-Type": ["text/plain; charset=nonsense"]}), "u"
    )
    assert r.text == chr(0xFFFD) + " ok"


def test_empty_bodies():
    for status in (204, 304):
        r = build_response(reply(status=status), "https://x.test/")
        assert r.content == b"" and r.text == ""
    with pytest.raises(ValueError):
        r.json()


def test_status_helpers():
    r = build_response(reply(status=404), "https://x.test/a")
    assert not r.ok and r.reason == "Not Found" and repr(r) == "<Response [404]>"
    with pytest.raises(HTTPError, match="404 Not Found for url: https://x.test/a") as info:
        r.raise_for_status()
    assert info.value.response is r
    build_response(reply(status=200), "u").raise_for_status()
    assert build_response(reply(status=599), "u").reason == ""


def test_the_final_url_headers_and_protocol():
    r = build_response(
        reply(url="https://x.test/final", headers={"X-A": ["1"], "X-B": ["1", "2"]}),
        "https://x.test/start",
    )
    assert r.url == "https://x.test/final" and r.protocol == "HTTP/2.0"
    assert r.headers["x-a"] == "1" and r.headers["X-B"] == ["1", "2"]
    assert build_response(reply(), "https://x.test/start").url == "https://x.test/start"


def test_set_cookie_values_are_read_whatever_the_case():
    assert set_cookie_values({"headers": {"set-cookie": ["a=1", "b=2"]}}) == ["a=1", "b=2"]
    assert set_cookie_values({"headers": None}) == []


def test_text_can_be_set_like_the_old_attribute():
    r = build_response(reply(body=b"x"), "u")
    r.text = "patched"
    assert r.text == "patched"


def test_a_response_survives_pickle():
    r = build_response(reply(body=b'{"a":1}', headers={"Set-Cookie": ["x=1"]}), "https://x.test/")
    clone = pickle.loads(pickle.dumps(r))
    assert clone.json() == {"a": 1} and clone.status_code == 200


def test_json_with_a_byte_order_mark_or_in_utf16():
    with_bom = build_response(reply(body=codecs.BOM_UTF8 + b'{"a":1}'), "u")
    assert with_bom.json() == {"a": 1}
    declared = build_response(
        reply(
            body=codecs.BOM_UTF8 + b'{"a":1}',
            headers={"Content-Type": ["application/json; charset=utf-8"]},
        ),
        "u",
    )
    assert declared.json() == {"a": 1}
    utf16 = build_response(reply(body='{"a":1}'.encode("utf-16")), "u")
    assert utf16.json() == {"a": 1}
