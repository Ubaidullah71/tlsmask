from __future__ import annotations

import copy
import pickle

import pytest

from tlsmask.cookies import CookieJar, cookie_header, extract_cookies


def test_dict_style_helpers():
    jar = CookieJar()
    jar.set("a", "1")
    jar["b"] = "2"
    assert jar.get("a") == "1" and jar["b"] == "2"
    assert jar.get("missing", "d") == "d"
    assert jar.get_dict() == {"a": "1", "b": "2"}
    assert sorted(jar.keys()) == ["a", "b"]
    assert sorted(jar.values()) == ["1", "2"]
    assert sorted(jar.items()) == [("a", "1"), ("b", "2")]
    assert "a" in jar and "zzz" not in jar
    del jar["a"]
    assert "a" not in jar
    with pytest.raises(KeyError):
        jar["a"]
    with pytest.raises(KeyError):
        del jar["a"]
    jar.set("b", None)
    assert len(jar) == 0


def test_update_from_a_dict_and_a_jar_and_copies_are_independent():
    jar = CookieJar()
    jar.update({"a": "1"})
    other = CookieJar()
    other.set("b", "2")
    jar.update(other)
    clone = jar.copy()
    clone.set("c", "3")
    assert jar.get_dict() == {"a": "1", "b": "2"}
    assert clone.get_dict() == {"a": "1", "b": "2", "c": "3"}


def test_a_cookie_set_by_hand_goes_to_every_host():
    jar = CookieJar()
    jar.set("t", "v")
    assert cookie_header(jar, "https://a.test/") == "t=v"
    assert cookie_header(jar, "http://127.0.0.1:8080/x") == "t=v"


def test_a_host_only_cookie_stays_on_its_host_and_path():
    jar = CookieJar()
    extract_cookies(jar, "https://a.test/app/login", ["sid=1; Path=/app", "all=2; Path=/"])
    assert cookie_header(jar, "https://a.test/app/home") == "sid=1; all=2"
    assert cookie_header(jar, "https://a.test/other") == "all=2"
    assert cookie_header(jar, "https://b.test/app/home") is None


def test_a_secure_cookie_is_never_sent_over_plain_http():
    jar = CookieJar()
    extract_cookies(jar, "https://a.test/", ["s=1; Secure"])
    assert cookie_header(jar, "https://a.test/") == "s=1"
    assert cookie_header(jar, "http://a.test/") is None


def test_max_age_zero_deletes():
    jar = CookieJar()
    extract_cookies(jar, "https://a.test/", ["a=1"])
    extract_cookies(jar, "https://a.test/", ["a=gone; Max-Age=0"])
    assert "a" not in jar


def test_a_domain_cookie_covers_subdomains():
    jar = CookieJar()
    extract_cookies(jar, "https://www.a.test/", ["d=1; Domain=a.test"])
    assert cookie_header(jar, "https://api.a.test/") == "d=1"


def test_a_jar_survives_pickle_and_deepcopy():
    # saving session.cookies to disk between runs is a common login pattern
    jar = CookieJar()
    extract_cookies(jar, "https://a.test/", ["sid=1; Path=/"])
    for clone in (pickle.loads(pickle.dumps(jar)), copy.deepcopy(jar)):
        assert clone.get_dict() == {"sid": "1"}
        clone.set("more", "2")  # and it still works afterwards
        assert cookie_header(clone, "https://a.test/") in ("sid=1; more=2", "more=2; sid=1")


def test_the_rest_of_the_requests_style_helpers():
    jar = CookieJar()
    jar.set("a", "1", domain="a.test")
    jar.set("b", "2", domain="b.test", path="/x")
    assert jar.setdefault("c", "3") == "3" and jar.setdefault("c", "9") == "3"
    assert jar.pop("c") == "3" and "c" not in jar
    assert jar.pop("missing", None) is None
    with pytest.raises(KeyError):
        jar.pop("missing")
    assert sorted(jar.list_domains()) == ["a.test", "b.test"]
    assert sorted(jar.list_paths()) == ["/", "/x"]
    assert not jar.multiple_domains()
    jar.set("a", "other", domain="b.test")
    assert jar.multiple_domains()
    assert sorted(jar.iterkeys()) == ["a", "a", "b"]
    assert sorted(jar.itervalues()) == ["1", "2", "other"]
    assert ("b", "2") in list(jar.iteritems())
    assert jar.get_policy() is not None


def test_a_password_in_the_url_does_not_end_up_in_the_jar():
    jar = CookieJar()
    extract_cookies(jar, "https://user:secret@a.test/", ["sid=1"])
    assert [cookie.domain for cookie in jar] == ["a.test"]
    assert cookie_header(jar, "https://a.test/") == "sid=1"
    assert cookie_header(jar, "https://user:secret@a.test/") == "sid=1"
