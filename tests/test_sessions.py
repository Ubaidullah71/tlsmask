"""Session: the old tls_client API, and the old wrapper's bugs it no longer has."""

from __future__ import annotations

import gc
import threading

import pytest
from fake_library import failure, reply

import tlsmask
from tlsmask import CaseInsensitiveDict, Session, TLSClientException, TLSClientExeption

URL = "https://x.test/path"


def sent(fake, index=-1):
    return fake.requests[index]


def redirect(status, location, **headers):
    return reply(
        status=status, headers={"Location": [location], **{k: [v] for k, v in headers.items()}}
    )


# --- defaults and profiles ------------------------------------------------------


def test_safe_defaults(fake):
    Session().get(URL)
    p = sent(fake)
    assert p["tlsClientIdentifier"] == tlsmask.DEFAULT_PROFILE
    assert p["catchPanics"] is True  # a Go panic used to kill the process
    assert p["followRedirects"] is False
    assert p["withoutCookieJar"] is True
    assert p["isByteResponse"] is True
    assert p["timeoutMilliseconds"] == 30000 and "timeoutSeconds" not in p
    assert p["requestMethod"] == "GET" and p["requestUrl"] == URL


def test_an_unknown_profile_is_refused_with_suggestions(fake):
    with pytest.raises(ValueError, match="chrome_150"):
        Session("chrome_15")
    with pytest.raises(ValueError, match="confirmed_android"):
        Session("confirmed_android_2")
    assert fake.calls == []


def test_a_profile_changed_later_is_checked_too(fake):
    s = Session()
    s.client_identifier = "nope"
    with pytest.raises(ValueError, match="nope"):
        s.get(URL)
    assert fake.requests == []


def test_the_old_positional_signature_still_works(fake):
    s = Session(
        "firefox_148", None, None, None, None, None, None, None, None, None, None, None, None,
        ["accept", "user-agent"], None, True,
    )  # fmt: skip
    assert s.header_order == ["accept", "user-agent"]
    assert s.random_tls_extension_order is True
    s.get(URL)
    assert sent(fake)["withRandomTLSExtensionOrder"] is True
    assert sent(fake)["tlsClientIdentifier"] == "firefox_148"


def test_a_custom_client_is_sent_with_client_identifier_none(fake):
    s = Session(
        client_identifier=None,
        ja3_string="771,4865,0-23,29,0",
        h2_settings={"HEADER_TABLE_SIZE": 65536},
        cert_compression_algo="brotli",
    )
    s.get(URL)
    p = sent(fake)
    assert "tlsClientIdentifier" not in p
    assert p["customTlsClient"] == {
        "ja3String": "771,4865,0-23,29,0",
        "h2Settings": {"HEADER_TABLE_SIZE": 65536},
        "certCompressionAlgos": ["brotli"],
        "alpnProtocols": ["h2", "http/1.1"],
    }


def test_a_custom_client_needs_a_ja3_string():
    with pytest.raises(ValueError, match="ja3_string"):
        Session(client_identifier=None)


def test_custom_settings_next_to_a_profile_warn():
    with pytest.warns(UserWarning, match="client_identifier=None"):
        Session("chrome_150", ja3_string="771,4865,0-23,29,0")


def test_additional_decode_warns_and_is_not_sent(fake):
    with pytest.warns(DeprecationWarning, match="additional_decode"):
        s = Session(additional_decode="gzip")
    s.get(URL)
    assert "additionalDecode" not in sent(fake)


# --- headers --------------------------------------------------------------------


def test_headers_go_out_in_the_order_they_were_set(fake):
    s = Session()
    s.headers = CaseInsensitiveDict({"User-Agent": "UA", "Accept": "*/*"})
    s.get(URL, headers={"X-B": "1", "accept": "text/html"})
    p = sent(fake)
    assert p["headerOrder"] == ["host", "user-agent", "accept", "x-b"]
    assert p["headers"] == {"User-Agent": "UA", "accept": "text/html", "X-B": "1"}


def test_header_order_puts_named_headers_first(fake):
    s = Session(header_order=["accept", "user-agent"])
    s.headers = CaseInsensitiveDict({"User-Agent": "UA", "X-B": "1", "Accept": "*/*"})
    s.get(URL)
    assert sent(fake)["headerOrder"] == ["host", "accept", "user-agent", "x-b"]
    s.get(URL, header_order=["x-b"])
    assert sent(fake)["headerOrder"] == ["host", "x-b", "user-agent", "accept"]


def test_a_header_set_to_none_is_not_sent(fake):
    Session().get(URL, headers={"Accept": None})
    assert "accept" not in {k.lower() for k in sent(fake)["headers"]}


def test_header_values_that_are_not_strings_are_sent_as_text(fake):
    Session().get(URL, headers={"X-Count": 5, "X-Raw": b"caf\xe9"})
    headers = sent(fake)["headers"]
    assert headers["X-Count"] == "5" and headers["X-Raw"] == "café"


# --- bodies ---------------------------------------------------------------------


def test_json_sets_content_type_for_that_request_only(fake):
    s = Session()
    s.post(URL, json={"a": 1, "b": [1, 2]})
    p = sent(fake)
    assert p["requestBody"] == '{"a":1,"b":[1,2]}'
    assert p["headers"]["Content-Type"] == "application/json"
    s.get(URL)
    assert "Content-Type" not in sent(fake)["headers"]
    assert "content-type" not in s.headers


def test_form_data_is_urlencoded(fake):
    Session().post(URL, data={"a": "1", "b": ["2", "3"]})
    p = sent(fake)
    assert p["requestBody"] == "a=1&b=2&b=3"
    assert p["headers"]["Content-Type"] == "application/x-www-form-urlencoded"


def test_bytes_go_as_base64_and_strings_as_they_are(fake):
    s = Session()
    s.post(URL, data=b"\x00\xff")
    assert sent(fake)["isByteRequest"] is True and sent(fake)["requestBody"] == "AP8="
    s.post(URL, data="raw text")
    assert sent(fake)["requestBody"] == "raw text" and "isByteRequest" not in sent(fake)
    assert "Content-Type" not in sent(fake)["headers"]


def test_a_content_type_you_set_is_kept(fake):
    Session().post(URL, json={}, headers={"content-type": "application/vnd.api+json"})
    assert sent(fake)["headers"]["content-type"] == "application/vnd.api+json"


# --- proxies, params, URLs ------------------------------------------------------


def test_an_https_only_proxy_is_used(fake):
    s = Session()
    s.proxies = {"https": "http://u:p@1.2.3.4:8080"}
    s.get("https://x.test/")
    s.get("http://x.test/")
    assert [r["proxyUrl"] for r in fake.requests] == ["http://u:p@1.2.3.4:8080"] * 2


def test_the_proxy_for_the_urls_scheme_wins(fake):
    s = Session()
    s.proxies = {"http": "http://a:1", "https": "http://b:2"}
    s.get("https://x.test/")
    assert sent(fake)["proxyUrl"] == "http://b:2"


def test_a_per_request_proxy_and_no_proxy(fake):
    s = Session()
    s.proxies = {"all": "http://a:1"}
    s.get(URL, proxy="socks5://c:3")
    assert sent(fake)["proxyUrl"] == "socks5://c:3"
    s.proxies = {}
    s.get(URL)
    assert sent(fake)["proxyUrl"] == ""


def test_params_join_a_query_that_is_already_there(fake):
    s = Session()
    s.params = {"a": "1"}
    s.get("https://x.test/p?z=0", params={"b": "2"})
    assert sent(fake)["requestUrl"] == "https://x.test/p?z=0&a=1&b=2"
    s.get("https://x.test/p", params={"a": "2"})
    assert sent(fake)["requestUrl"] == "https://x.test/p?a=2"


def test_non_ascii_urls_are_percent_encoded(fake):
    Session().get("https://bücher.test/straße?q=grüße")
    assert sent(fake)["requestUrl"] == "https://xn--bcher-kva.test/stra%C3%9Fe?q=gr%C3%BC%C3%9Fe"


# --- timeouts and Go clients ------------------------------------------------------


def test_timeouts(fake):
    s = Session()
    s.get(URL, timeout=2.5)
    s.get(URL, timeout_seconds=5)
    s.timeout_seconds = 10
    s.get(URL)
    assert [r["timeoutMilliseconds"] for r in fake.requests] == [2500, 5000, 10000]


def test_a_different_setting_gets_its_own_go_client(fake):
    s = Session()
    s.get(URL)
    s.get(URL, timeout=1)
    s.get(URL)
    s.get(URL, insecure_skip_verify=True)
    s.client_identifier = "firefox_148"
    s.get(URL)
    ids = [r["sessionId"] for r in fake.requests]
    assert ids[0] == ids[2]
    assert len({ids[0], ids[1], ids[3], ids[4]}) == 4


def test_close_destroys_every_go_client_once(fake):
    s = Session()
    s.get(URL)
    s.get(URL, timeout=1)
    s.close()
    s.close()
    destroyed = [p["sessionId"] for name, p in fake.calls if name == "destroySession"]
    assert sorted(destroyed) == sorted({r["sessionId"] for r in fake.requests})
    assert len(fake.freed) == len(fake.calls)  # every answer freed, destroySession's too


def test_old_go_clients_are_dropped_beyond_the_limit(fake):
    s = Session()
    for seconds in range(1, 11):
        s.get(URL, timeout=seconds)
    destroyed = [p["sessionId"] for name, p in fake.calls if name == "destroySession"]
    assert destroyed == [r["sessionId"] for r in fake.requests[:2]]


def test_a_session_closes_as_a_context_manager(fake):
    with Session() as s:
        s.get(URL)
    assert fake.calls[-1][0] == "destroySession"


# --- responses and errors -------------------------------------------------------


def test_a_failed_request_raises_the_librarys_reason(fake):
    fake.replies.append(failure("failed to do request: proxy refused"))
    with pytest.raises(TLSClientExeption, match="proxy refused"):
        Session().get(URL)
    assert fake.freed[0] == "answer-1"  # the failed answer was freed too


def test_the_response(fake):
    fake.replies.append(
        reply(
            body=b'{"ok":true}',
            headers={"Content-Type": ["application/json"], "X-Multi": ["a", "b"]},
            url=URL,
        )
    )
    r = Session().get(URL)
    assert (r.status_code, r.ok, r.protocol, r.url) == (200, True, "HTTP/2.0", URL)
    assert r.json() == {"ok": True}
    assert r.headers["content-type"] == "application/json" and r.headers["x-multi"] == ["a", "b"]
    assert r.history == []


def test_request_is_execute_request(fake):
    Session().request("PATCH", URL, data="x")
    assert sent(fake)["requestMethod"] == "PATCH"


# --- cookies ----------------------------------------------------------------------


def test_cookies_live_only_in_the_session_jar(fake):
    s = Session()
    fake.replies.append(reply(headers={"Set-Cookie": ["a=1; Path=/"]}, url="https://x.test/"))
    r = s.get("https://x.test/")
    assert s.cookies["a"] == "1" and r.cookies.get_dict() == {"a": "1"}
    s.get("https://x.test/")
    assert sent(fake)["headers"]["Cookie"] == "a=1"
    assert sent(fake)["headerOrder"][-1] == "cookie"
    assert sent(fake)["requestCookies"] == []
    del s.cookies["a"]
    s.get("https://x.test/")
    assert "Cookie" not in sent(fake)["headers"]


def test_per_request_cookies_are_sent_but_not_kept(fake):
    s = Session()
    s.get(URL, cookies={"x": "1"})
    assert sent(fake)["headers"]["Cookie"] == "x=1"
    assert "x" not in s.cookies


def test_a_cookie_header_you_set_wins(fake):
    s = Session()
    s.cookies.set("a", "1")
    s.get(URL, headers={"Cookie": "manual=1"})
    assert sent(fake)["headers"]["Cookie"] == "manual=1"


def test_a_plain_dict_assigned_to_cookies_still_works(fake):
    s = Session()
    s.cookies = {"a": "1"}
    s.get(URL)
    assert sent(fake)["headers"]["Cookie"] == "a=1"
    assert s.cookies.get("a") == "1"


# --- redirects --------------------------------------------------------------------


def test_redirects_are_not_followed_by_default(fake):
    fake.replies.append(redirect(302, "/next"))
    r = Session().get(URL)
    assert r.status_code == 302 and len(fake.requests) == 1


def test_a_followed_redirect_keeps_its_cookies(fake):
    fake.replies += [redirect(302, "/next", **{"Set-Cookie": "b=2; Path=/"}), reply(body=b"done")]
    r = Session().get(URL, allow_redirects=True)
    assert r.text == "done" and [h.status_code for h in r.history] == [302]
    assert sent(fake)["requestUrl"] == "https://x.test/next"
    assert sent(fake)["headers"]["Cookie"] == "b=2"
    assert r.url == "https://x.test/next"


@pytest.mark.parametrize(
    "status, method, expected",
    [
        (301, "POST", "GET"),
        (302, "POST", "GET"),
        (303, "PUT", "GET"),
        (303, "HEAD", "HEAD"),
        (302, "PUT", "PUT"),
        (307, "POST", "POST"),
        (308, "POST", "POST"),
    ],
)
def test_redirect_methods_follow_the_browser_rules(fake, status, method, expected):
    fake.replies += [redirect(status, "/next"), reply()]
    Session().execute_request(method, URL, data="body", allow_redirects=True)
    second = sent(fake)
    assert second["requestMethod"] == expected
    assert ("requestBody" in second) == (expected == method)


def test_a_redirect_to_another_host_drops_credentials(fake):
    fake.replies += [redirect(302, "//other.test/p"), reply()]
    Session().get(URL, headers={"Authorization": "Bearer t", "Cookie": "c=1"}, allow_redirects=True)
    headers = {k.lower() for k in sent(fake)["headers"]}
    assert "authorization" not in headers and "cookie" not in headers
    assert sent(fake)["requestUrl"] == "https://other.test/p"


def test_a_same_host_redirect_keeps_authorization(fake):
    fake.replies += [redirect(302, "/p2"), reply()]
    Session().get(URL, headers={"Authorization": "Bearer t"}, allow_redirects=True)
    assert sent(fake)["headers"]["Authorization"] == "Bearer t"


def test_endless_redirects_stop(fake):
    fake.replies += [redirect(302, "/again")] * 31
    with pytest.raises(TLSClientException, match="too many redirects"):
        Session().get(URL, allow_redirects=True)
    assert len(fake.requests) == 31


# --- threads ----------------------------------------------------------------------


def test_one_session_shared_by_many_threads(fake):
    s = Session()
    errors = []

    def work():
        try:
            for _ in range(5):
                s.get(URL)
        except Exception as exc:  # collected for the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(fake.requests) == 100 and len(fake.freed) == 100
    assert len({r["sessionId"] for r in fake.requests}) == 1


# --- retries, redirect credentials and bad input ----------------------------------


def test_an_empty_brotli_answer_is_asked_again_without_br(fake):
    # tls-client 1.16.0 cannot decode an empty brotli body (HEAD, 204, 304)
    fake.replies += [failure("unexpected EOF"), reply(status=204)]
    r = Session().head(URL)
    assert r.status_code == 204
    first, second = fake.requests
    assert first["headers"]["Accept-Encoding"] == "gzip, deflate, br"
    assert second["headers"]["Accept-Encoding"] == "gzip, deflate"
    assert second["sessionId"] == first["sessionId"]


def test_without_an_accept_encoding_the_retry_names_one(fake):
    fake.replies += [failure("unexpected EOF"), reply()]
    Session().get(URL, headers={"Accept-Encoding": None})
    assert sent(fake)["headers"]["Accept-Encoding"] == "gzip, deflate"
    assert "accept-encoding" in sent(fake)["headerOrder"]


def test_a_request_that_is_not_safe_to_repeat_is_never_repeated(fake):
    fake.replies.append(failure("unexpected EOF"))
    with pytest.raises(TLSClientException, match="unexpected EOF"):
        Session().post(URL, data="x")
    assert len(fake.requests) == 1


@pytest.mark.parametrize(
    "location",
    ["http://x.test/next", "https://x.test:8443/next", "https://other.test/next"],
)
def test_credentials_are_dropped_on_a_downgrade_a_port_change_or_a_new_host(fake, location):
    fake.replies += [redirect(302, location), reply()]
    Session().get(URL, headers={"Authorization": "Bearer t", "Cookie": "c=1"}, allow_redirects=True)
    names = {k.lower() for k in sent(fake)["headers"]}
    assert "authorization" not in names and "cookie" not in names


def test_credentials_survive_an_upgrade_to_https(fake):
    fake.replies += [redirect(302, "https://x.test/secure"), reply()]
    Session().get("http://x.test/", headers={"Authorization": "Bearer t"}, allow_redirects=True)
    assert sent(fake)["headers"]["Authorization"] == "Bearer t"


def test_a_url_without_a_scheme_raises_the_librarys_exception(fake):
    with pytest.raises(TLSClientExeption, match="http"):
        Session().get("example.com/x")
    assert fake.requests == []


def test_cookies_survive_a_redirect_on_a_non_ascii_host(fake):
    fake.replies += [
        reply(
            status=302,
            headers={"Location": ["/next"], "Set-Cookie": ["a=1; Path=/"]},
            url="https://xn--bcher-kva.test/start",
        ),
        reply(),
    ]
    Session().get("https://bücher.test/start", allow_redirects=True)
    assert sent(fake)["headers"]["Cookie"] == "a=1"


def test_a_dropped_session_ends_its_go_clients(fake):
    s = Session()
    s.get(URL)
    session_id = sent(fake)["sessionId"]
    del s
    gc.collect()
    assert ("destroySession", {"sessionId": session_id}) in fake.calls


# --- clients tls-client could not build ------------------------------------------


def test_a_client_that_failed_to_build_is_never_touched_again(fake):
    # tls-client keeps a broken entry for it, and ending that entry crashes the process
    fake.replies += [
        failure("failed to build client out of request input: invalid config"),
        reply(),
    ]
    s = Session()
    with pytest.raises(TLSClientException, match="invalid config"):
        s.get(URL)
    s.get(URL)
    broken, working = (r["sessionId"] for r in fake.requests)
    assert broken != working
    s.close()
    destroyed = [p["sessionId"] for name, p in fake.calls if name == "destroySession"]
    assert destroyed == [working]


@pytest.mark.parametrize(
    "given, sent_as",
    [
        ("127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("user:pass@proxy.example:3128", "http://user:pass@proxy.example:3128"),
        ("socks5://127.0.0.1:1080", "socks5://127.0.0.1:1080"),
    ],
)
def test_a_proxy_without_a_scheme_is_http(fake, given, sent_as):
    Session().get(URL, proxy=given)
    assert sent(fake)["proxyUrl"] == sent_as


def test_a_proxy_tls_client_cannot_use_is_refused_before_sending(fake):
    with pytest.raises(TLSClientException, match="ftp"):
        Session().get(URL, proxy="ftp://127.0.0.1:21")
    assert fake.requests == []


@pytest.mark.parametrize(
    "options",
    [
        {"disable_ipv4": True, "disable_ipv6": True},
        {"with_protocol_racing": True, "disable_http3": True},
        {"with_protocol_racing": True, "force_http1": True},
    ],
)
def test_settings_that_contradict_each_other_are_refused(options):
    with pytest.raises(ValueError):
        Session(**options)


def test_per_request_cookies_stay_on_the_first_site(fake):
    fake.replies += [redirect(302, "https://other.test/next"), reply()]
    Session().get(URL, cookies={"sid": "secret"}, allow_redirects=True)
    first, second = fake.requests
    assert first["headers"]["Cookie"] == "sid=secret"
    assert "Cookie" not in second["headers"]


# --- odd input ------------------------------------------------------------------


def test_timeouts_in_the_requests_style(fake):
    s = Session()
    s.get(URL, timeout=(3, 10))  # (connect, read): tls-client has one timeout for both
    s.timeout_seconds = None
    s.get(URL)
    assert [r["timeoutMilliseconds"] for r in fake.requests] == [13000, 30000]


@pytest.mark.parametrize("bad", [0, -1, float("inf"), float("nan"), "5", ()])
def test_a_timeout_that_makes_no_sense_is_refused(fake, bad):
    with pytest.raises(ValueError, match="timeout"):
        Session().get(URL, timeout=bad)
    assert fake.requests == []


def test_a_bytes_url_works(fake):
    Session().get(URL.encode())
    assert sent(fake)["requestUrl"] == URL


def test_host_goes_first_like_a_browser(fake):
    Session().get(URL)
    assert sent(fake)["headerOrder"][0] == "host"
    Session(header_order=["accept", "host"]).get(URL)
    assert sent(fake)["headerOrder"][:2] == ["accept", "host"]  # unless you place it
