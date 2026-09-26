"""Only bogdanfinn's file, at the pinned hash, is loaded, and every answer is freed."""

from __future__ import annotations

import hashlib

import pytest

from tlsmask import TLSClientException, _library, _pins


def test_every_answer_is_freed_by_its_id(fake):
    answer = _library.call("request", {"requestUrl": "https://x.test/"})
    assert answer["status"] == 200
    assert fake.freed == [answer["id"]]


def test_a_bare_string_answer_raises_with_its_text(fake):
    fake.replies.append(b"json: cannot unmarshal string")
    with pytest.raises(TLSClientException, match="cannot unmarshal"):
        _library.call("request", {})
    assert fake.freed == []  # upstream never registered it, so there is nothing to free


@pytest.mark.parametrize(
    "system, machine, bits, musl, target",
    [
        ("win32", "AMD64", 64, False, "windows-amd64"),
        ("win32", "AMD64", 32, False, "windows-386"),
        ("win32", "ARM64", 64, False, None),
        ("darwin", "arm64", 64, False, "darwin-arm64"),
        ("darwin", "x86_64", 64, False, "darwin-amd64"),
        ("linux", "x86_64", 64, False, "linux-amd64"),
        ("linux", "x86_64", 64, True, "musl-amd64"),
        ("linux", "aarch64", 64, False, "linux-arm64"),
        ("linux", "armv7l", 32, False, "linux-armv7"),
        ("linux", "ppc64le", 64, False, None),
        ("freebsd14", "amd64", 64, False, None),
    ],
)
def test_current_target(system, machine, bits, musl, target):
    assert _library.current_target(system, machine, bits, musl) == target


@pytest.fixture()
def bin_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(_library, "BIN_DIR", tmp_path)
    monkeypatch.setattr(_library, "_lib", None)
    monkeypatch.delenv(_library.ENV_VAR, raising=False)
    monkeypatch.setattr(_library, "current_target", lambda: "linux-amd64")
    return tmp_path


def pin(monkeypatch, target: str, content: bytes) -> str:
    asset = f"tls-client-{target}-{_pins.LIBRARY_VERSION}.bin"
    digest = hashlib.sha256(content).hexdigest()
    monkeypatch.setitem(_pins.BINARIES, target, (asset, digest, "tag"))
    return asset


def test_no_library_says_how_to_bring_your_own(bin_dir):
    with pytest.raises(TLSClientException, match="TLSMASK_LIBRARY_PATH"):
        _library._load()
    ok, detail = _library.verify()
    assert not ok and "TLSMASK_LIBRARY_PATH" in detail


def test_a_file_that_is_not_the_pinned_one_is_never_loaded(bin_dir, monkeypatch):
    asset = pin(monkeypatch, "linux-amd64", b"the real library")
    (bin_dir / asset).write_bytes(b"something else")
    with pytest.raises(TLSClientException, match="SHA-256 mismatch"):
        _library._load()
    ok, detail = _library.verify()
    assert not ok and "pinned" in detail


def test_the_pinned_file_verifies(bin_dir, monkeypatch):
    asset = pin(monkeypatch, "linux-amd64", b"the real library")
    (bin_dir / asset).write_bytes(b"the real library")
    ok, detail = _library.verify()
    assert ok and "as pinned" in detail


def test_the_one_shipped_file_is_used_when_the_platform_guess_is_wrong(bin_dir, monkeypatch):
    asset = pin(monkeypatch, "musl-amd64", b"musl build")
    (bin_dir / asset).write_bytes(b"musl build")
    path, expected = _library.locate()
    assert path.name == asset
    assert expected == hashlib.sha256(b"musl build").hexdigest()


def test_the_env_var_names_a_file_used_without_a_hash_check(bin_dir, monkeypatch, tmp_path):
    own = tmp_path / "my-build.so"
    own.write_bytes(b"mine")
    monkeypatch.setenv(_library.ENV_VAR, str(own))
    assert _library.locate() == (own, None)
    ok, detail = _library.verify()
    assert ok and "not hash-checked" in detail


def test_the_env_var_must_name_a_file(bin_dir, monkeypatch, tmp_path):
    monkeypatch.setenv(_library.ENV_VAR, str(tmp_path / "missing.so"))
    with pytest.raises(TLSClientException, match="is not a file"):
        _library.locate()


def test_a_file_that_will_not_load_raises_the_librarys_exception(bin_dir, monkeypatch, tmp_path):
    junk = tmp_path / "not-a-library.so"
    junk.write_bytes(b"not a shared library")
    monkeypatch.setenv(_library.ENV_VAR, str(junk))
    with pytest.raises(TLSClientException, match="could not load"):
        _library._load()


def test_a_glibc_system_with_musl_installed_is_still_glibc(monkeypatch):
    monkeypatch.setattr(_library.glob, "glob", lambda pattern: ["/lib/ld-musl-x86_64.so.1"])
    monkeypatch.setattr(_library.platform, "libc_ver", lambda: ("glibc", "2.39"))
    assert _library.current_target("linux", "x86_64", 64) == "linux-amd64"
    monkeypatch.setattr(_library.platform, "libc_ver", lambda: ("", ""))
    assert _library.current_target("linux", "x86_64", 64) == "musl-amd64"


def test_only_the_functions_tlsmask_binds_can_be_called(fake):
    with pytest.raises(ValueError, match="getCookiesFromSession"):
        _library.call("getCookiesFromSession", {})
    assert fake.calls == []


def test_an_install_built_from_source_says_so(bin_dir):
    # bin_dir: a platform tlsmask has a wheel for, but no library in the install
    with pytest.raises(TLSClientException, match="from source"):
        _library.locate()


def test_alpine_is_told_why_there_is_no_wheel(bin_dir, monkeypatch):
    # tls-client's musl build can't be loaded with dlopen, so there is no Alpine wheel
    monkeypatch.setattr(_library, "current_target", lambda: "musl-amd64")
    with pytest.raises(TLSClientException, match="Alpine"):
        _library.locate()
