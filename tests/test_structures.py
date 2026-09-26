from __future__ import annotations

from tlsmask.structures import CaseInsensitiveDict


def test_lookup_ignores_case_and_keeps_the_latest_spelling_in_place():
    d = CaseInsensitiveDict({"User-Agent": "a", "Accept": "b"})
    d["user-agent"] = "c"
    assert d["USER-AGENT"] == "c"
    assert list(d) == ["user-agent", "Accept"]
    assert list(d.items()) == [("user-agent", "c"), ("Accept", "b")]


def test_contains_pop_delete_and_equality():
    d = CaseInsensitiveDict(Accept="b")
    assert "accept" in d and 5 not in d
    assert d == {"ACCEPT": "b"}
    assert d.pop("ACCEPT") == "b" and len(d) == 0
    d["X"] = "1"
    del d["x"]
    assert "X" not in d
    assert d.pop("missing", None) is None


def test_copy_is_independent_and_repr_is_a_dict():
    d = CaseInsensitiveDict({"A": "1"})
    c = d.copy()
    c["b"] = "2"
    assert "b" not in d
    assert repr(d) == "{'A': '1'}"
