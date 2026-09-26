"""tlsmask against bogdanfinn's real library and a local server (no internet)."""

from __future__ import annotations

import base64
import subprocess
import sys
import time
from urllib.parse import urlencode

import pytest

from tlsmask import CaseInsensitiveDict, Session, TLSClientException, _library


def echo(response):
    return response.json()


def arrived(response) -> dict:
    return dict(echo(response)["headers"])


def test_get_and_post(server):
    with Session() as s:
        r = s.get(f"{server}/echo")
        assert r.status_code == 200 and r.protocol == "HTTP/1.1"
        assert echo(r)["method"] == "GET"
        data = echo(s.post(f"{server}/echo", json={"a": 1}))
    assert base64.b64decode(data["body"]) == b'{"a":1}'
    assert dict(data["headers"])["Content-Type"] == "application/json"


def test_headers_reach_the_wire_in_our_order(server):
    wanted = ["user-agent", "x-zeta", "accept", "x-alpha"]
    with Session() as s:
        s.headers = CaseInsensitiveDict()
        r = s.get(
            f"{server}/echo",
            headers={"User-Agent": "UA", "X-Zeta": "z", "Accept": "*/*", "X-Alpha": "a"},
        )
    names = [name.lower() for name, _ in echo(r)["headers"] if name.lower() in wanted]
    assert names == wanted


def test_binary_bodies_survive_both_ways(server):
    with Session() as s:
        assert s.get(f"{server}/bytes").content == bytes(range(256))
        data = echo(s.post(f"{server}/echo", data=bytes(range(256))))
    assert base64.b64decode(data["body"]) == bytes(range(256))


def test_cookies_are_set_sent_and_deleted(server):
    with Session() as s:
        s.get(f"{server}/set?a=1")
        assert s.cookies["a"] == "1"
        assert arrived(s.get(f"{server}/echo")).get("Cookie") == "a=1"
        del s.cookies["a"]
        assert "Cookie" not in arrived(s.get(f"{server}/echo"))


def test_a_redirect_chain_keeps_every_hops_cookies(server):
    inner = "/redirect?" + urlencode({"to": "/echo", "cookie": "b=2; Path=/"})
    outer = f"{server}/redirect?" + urlencode({"to": inner, "cookie": "a=1; Path=/"})
    with Session() as s:
        r = s.get(outer, allow_redirects=True)
    assert [h.status_code for h in r.history] == [302, 302]
    assert arrived(r)["Cookie"] in ("a=1; b=2", "b=2; a=1")


def test_redirects_wait_to_be_asked(server):
    with Session() as s:
        assert s.get(f"{server}/redirect?to=/echo").status_code == 302


def test_a_303_after_post_becomes_a_get(server):
    with Session() as s:
        r = s.post(f"{server}/redirect?status=303&to=/echo", data="payload", allow_redirects=True)
    assert echo(r)["method"] == "GET" and echo(r)["body"] == ""


def test_a_timeout_applies_even_after_the_client_exists(server):
    with Session() as s:
        s.get(f"{server}/echo")  # the Go client now exists, with a 30 s timeout
        started = time.monotonic()
        with pytest.raises(TLSClientException):
            s.get(f"{server}/slow?s=3", timeout=1)
        assert time.monotonic() - started < 2.5
        assert s.get(f"{server}/slow?s=1", timeout=5).text == "late"


def test_head_and_empty_bodies(server):
    with Session() as s:
        r = s.head(f"{server}/echo")
    assert r.status_code == 200 and r.content == b"" and r.text == ""


def test_python_m_tlsmask_says_ok():
    result = subprocess.run([sys.executable, "-m", "tlsmask"], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "library     OK" in result.stdout


@pytest.mark.parametrize(
    "method, status", [("HEAD", 200), ("GET", 204), ("GET", 304), ("GET", 200)]
)
def test_an_empty_brotli_answer_does_not_fail(server, method, status):
    # tls-client 1.16.0 fails to decode an empty br body; tlsmask asks again without br
    with Session() as s:
        r = s.execute_request(method, f"{server}/empty-br?status={status}")
    assert r.status_code == status and r.content == b""


def test_ending_a_session_that_never_existed_is_a_no_op():
    assert _library.call("destroySession", {"sessionId": "never-made"})["success"] is True


CRASH_SCRIPT = """
import sys
import tlsmask
from tlsmask import _payload

check = _payload.pick_proxy
_payload.pick_proxy = lambda proxy, url: "ftp://127.0.0.1:1"  # past tlsmask's own check
with tlsmask.Session() as s:
    try:
        s.get(sys.argv[1])
    except tlsmask.TLSClientException:
        pass
    _payload.pick_proxy = check
    print(s.get(sys.argv[1]).status_code)
print("survived")
"""


def test_a_client_tls_client_failed_to_build_does_not_crash_the_process(server):
    # tls-client keeps a nil client for it; destroying that one is a Go panic
    result = subprocess.run(
        [sys.executable, "-c", CRASH_SCRIPT, f"{server}/echo"], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr[-2000:]
    assert result.stdout.split() == ["200", "survived"]


def test_host_is_the_first_header_on_the_wire(server):
    with Session() as s:
        names = [name.lower() for name, _ in echo(s.get(f"{server}/echo"))["headers"]]
    assert names[0] == "host"
