from __future__ import annotations

from tlsmask import __main__ as cli
from tlsmask import _library, _pins


def test_a_good_install_says_ok(monkeypatch, capsys):
    monkeypatch.setattr(_library, "verify", lambda: (True, "/x/lib.so (sha256 abc, as pinned)"))
    monkeypatch.setattr(_library, "call", lambda function, payload: {"success": True})
    assert cli.main() == 0
    out = capsys.readouterr().out
    assert f"tls-client  {_pins.LIBRARY_VERSION}" in out
    assert "library     OK: /x/lib.so" in out


def test_a_bad_install_says_why_and_fails(monkeypatch, capsys):
    monkeypatch.setattr(_library, "verify", lambda: (False, "hashes to 00, pinned to ff"))
    assert cli.main() == 1
    assert "library     PROBLEM: hashes to 00" in capsys.readouterr().out


def test_a_file_that_hashes_fine_but_will_not_load_is_a_problem(monkeypatch, capsys, tmp_path):
    junk = tmp_path / "not-a-library.so"
    junk.write_bytes(b"junk")
    monkeypatch.setenv(_library.ENV_VAR, str(junk))
    monkeypatch.setattr(_library, "_lib", None)
    assert cli.main() == 1
    assert "could not be loaded" in capsys.readouterr().out
