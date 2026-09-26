from __future__ import annotations

from types import SimpleNamespace

import fetch_binaries
import pytest
import upstream


def pins_for(content: bytes) -> SimpleNamespace:
    return SimpleNamespace(
        LIBRARY_VERSION="9.9.9",
        BINARIES={"linux-amd64": ("tls-client-linux-9.9.9.so", upstream.sha256(content), "tag")},
    )


def test_a_matching_download_is_installed_once(tmp_path):
    calls = []

    def download(version, asset):
        calls.append((version, asset))
        return b"library"

    pins = pins_for(b"library")
    path = fetch_binaries.fetch("linux-amd64", tmp_path, pins, download)
    assert path.read_bytes() == b"library"
    assert calls == [("9.9.9", "tls-client-linux-9.9.9.so")]
    fetch_binaries.fetch("linux-amd64", tmp_path, pins, download)
    assert len(calls) == 1  # already there with the right hash


def test_a_download_that_does_not_match_is_refused_and_leaves_nothing(tmp_path):
    with pytest.raises(SystemExit, match="REFUSED"):
        fetch_binaries.fetch(
            "linux-amd64", tmp_path, pins_for(b"library"), lambda v, a: b"tampered"
        )
    assert list(tmp_path.iterdir()) == []
