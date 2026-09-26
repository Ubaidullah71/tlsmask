"""The update bot: package a new tls-client release, and decide if it may ship alone."""

from __future__ import annotations

import datetime as dt
import json
import struct
from types import SimpleNamespace

import bump
import pytest
import upstream

NOW = dt.datetime(2026, 10, 20, 12, 0, tzinfo=dt.timezone.utc)
PROFILES_GO = """var DefaultClientProfile = Chrome_2

var MappedTLSClients = map[string]ClientProfile{
\t"chrome_1":  Chrome_1,
\t"chrome_2":  Chrome_2,
\t"firefox_1": Firefox_1,
}
"""
TYPES_GO = """type RequestInput struct {
\tSessionId *string `json:"sessionId"`
\tRequestUrl string `json:"requestUrl"`
}
"""
MAIN_GO = "//export request\n//export freeMemory\n"


def macho() -> bytes:
    command = struct.pack("<IIIIII", 0x32, 24, 1, 13 << 16, 0, 0)
    return struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 6, 1, 24, 0, 0) + command


def blob(target: str, glibc: bytes = b"GLIBC_2.17") -> bytes:
    if target.startswith("darwin"):
        return macho() + target.encode()
    if target.startswith("linux"):
        return b"\x7fELF " + glibc + b"\x00" + target.encode()
    return b"MZ" + target.encode()


def make_release(version="1.1.0", days_old=10, *, drop=None, wrong=None, glibc=b"GLIBC_2.17"):
    blobs, assets = {}, []
    for target in upstream.TARGET_ORDER:
        name = upstream.asset_name(target, version)
        blobs[name] = blob(target, glibc)
        digest = "0" * 64 if name == wrong else upstream.sha256(blobs[name])
        if name != drop:
            assets.append({"name": name, "digest": f"sha256:{digest}"})
    release = {
        "tag_name": f"v{version}",
        "published_at": (NOW - dt.timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "html_url": f"https://github.com/bogdanfinn/tls-client/releases/tag/v{version}",
        "assets": assets,
    }
    return release, blobs


@pytest.fixture()
def root(tmp_path):
    (tmp_path / "tests" / "contract").mkdir(parents=True)
    old = upstream.snapshot("1.0.0", TYPES_GO, MAIN_GO)
    (tmp_path / "tests" / "contract" / "types-1.0.0.json").write_text(
        json.dumps(old), encoding="utf-8"
    )
    blocks = "".join(
        f"<!-- {n}:start --><!-- {n}:end -->\n" for n in ("badge", "stats", "profiles")
    )
    (tmp_path / "README.md").write_text(blocks, encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## 1.0.0 - 2026-01-01\n\nOld.\n", encoding="utf-8"
    )
    return tmp_path


PINS = SimpleNamespace(
    LIBRARY_VERSION="1.0.0",
    PROFILES=frozenset({"chrome_1", "firefox_1"}),
    DEFAULT_PROFILE="chrome_1",
)


def run(root, release, blobs, *, profiles_go=PROFILES_GO, types_go=TYPES_GO):
    sources = {
        "profiles/profiles.go": profiles_go,
        "cffi_src/types.go": types_go,
        "cffi_dist/main.go": MAIN_GO,
    }
    return bump.bump(
        release,
        PINS,
        root=root,
        download=lambda version, asset: blobs[asset],
        source=lambda version, path: sources[path],
        releases=lambda: [dict(release, body="new things"), {"tag_name": "v1.0.0", "body": "old"}],
        now=NOW,
    )


def test_a_clean_release_is_packaged_and_safe(root):
    release, blobs = make_release()
    update = run(root, release, blobs)
    assert update.safe, update.reasons
    files = update.files
    assert '__version__ = "1.1.0"' in files["tlsmask/_version.py"]
    assert '"macosx_13_0_arm64"' in files["tlsmask/_pins.py"]
    assert upstream.sha256(blobs["tls-client-windows-64-1.1.0.dll"]) in files["tlsmask/_pins.py"]
    assert 'DEFAULT_PROFILE = "chrome_2"' in files["tlsmask/_pins.py"]
    assert '"chrome_2",' in files["tlsmask/profiles.py"]
    assert files["tests/contract/types-1.0.0.json"] is None
    assert json.loads(files["tests/contract/types-1.1.0.json"])["version"] == "1.1.0"
    assert "**v1.1.0**" in files["README.md"]
    assert files["CHANGELOG.md"].index("## 1.1.0") < files["CHANGELOG.md"].index("## 1.0.0")
    assert "`chrome_2`" in update.report and "new things" in update.report
    bump.write(update, root)
    assert not (root / "tests" / "contract" / "types-1.0.0.json").exists()
    assert (root / "tlsmask" / "_version.py").read_text(encoding="utf-8").endswith('"1.1.0"\n')


def test_a_young_release_waits(root):
    release, blobs = make_release(days_old=3)
    update = run(root, release, blobs)
    assert not update.safe and "3 days ago" in update.reasons[0]


def test_a_removed_profile_waits(root):
    release, blobs = make_release()
    without_firefox = PROFILES_GO.replace('\t"firefox_1": Firefox_1,\n', "")
    update = run(root, release, blobs, profiles_go=without_firefox)
    assert not update.safe and any("firefox_1" in reason for reason in update.reasons)


def test_a_retyped_field_waits_and_an_added_one_does_not(root):
    release, blobs = make_release()
    retyped = TYPES_GO.replace("RequestUrl string", "RequestUrl []string")
    assert not run(root, release, blobs, types_go=retyped).safe
    added = TYPES_GO.replace("}\n", '\tNewThing bool `json:"newThing"`\n}\n')
    update = run(root, release, blobs, types_go=added)
    assert update.safe and "`RequestInput.newThing`" in update.report


def test_a_hash_that_differs_from_githubs_is_refused(root):
    release, blobs = make_release(wrong="tls-client-linux-arm64-1.1.0.so")
    with pytest.raises(bump.BumpError, match="GitHub publishes"):
        run(root, release, blobs)


def test_a_missing_asset_is_refused(root):
    release, blobs = make_release(drop="tls-client-windows-32-1.1.0.dll")
    with pytest.raises(bump.BumpError, match="windows-386"):
        run(root, release, blobs)


def test_a_linux_build_needing_newer_glibc_is_refused(root):
    release, blobs = make_release(glibc=b"GLIBC_2.34")
    with pytest.raises(bump.BumpError, match="GLIBC_2.34"):
        run(root, release, blobs)


def test_an_older_release_is_refused(root):
    release, blobs = make_release(version="0.9.0")
    with pytest.raises(bump.BumpError, match="not newer"):
        run(root, release, blobs)


def test_main_says_up_to_date(monkeypatch, tmp_path):
    current = upstream.pins().LIBRARY_VERSION
    monkeypatch.setattr(upstream, "latest_release", lambda: {"tag_name": f"v{current}"})
    output = tmp_path / "out.txt"
    assert bump.main(["--github-output", str(output)]) == 0
    assert output.read_text(encoding="utf-8").splitlines() == [
        "changed=false",
        "safe=false",
        f"version={current}",
    ]


def test_a_rise_in_the_macos_minimum_waits(root):
    release, blobs = make_release()
    older_macs = SimpleNamespace(
        **vars(PINS),
        BINARIES={
            "darwin-arm64": ("a", "b", "macosx_12_0_arm64"),
            "darwin-amd64": ("a", "b", "macosx_12_0_x86_64"),
        },
    )
    sources = {
        "profiles/profiles.go": PROFILES_GO,
        "cffi_src/types.go": TYPES_GO,
        "cffi_dist/main.go": MAIN_GO,
    }
    update = bump.bump(
        release,
        older_macs,
        root=root,
        download=lambda version, asset: blobs[asset],
        source=lambda version, path: sources[path],
        releases=lambda: [],
        now=NOW,
    )
    assert not update.safe
    assert any("macOS" in reason and "12.0" in reason for reason in update.reasons)
