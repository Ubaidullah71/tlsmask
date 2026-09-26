from __future__ import annotations

import re
import struct

import pytest
import upstream

PROFILES_GO = """package profiles

var DefaultClientProfile = Chrome_2

var MappedTLSClients = map[string]ClientProfile{
\t"chrome_1":  Chrome_1,
\t"chrome_2":  Chrome_2,
\t"mms_ios":   MMSIos,
\t"mms_ios_1": MMSIos,
\t"firefox_1": Firefox_1,
}
"""

TYPES_GO = """package x

type RequestInput struct {
\tCustomTlsClient *CustomTlsClient `json:"customTlsClient"`
\tHeaders map[string]string `json:"headers"`
\t// a comment line
\tSessionId *string `json:"sessionId"`
\tTimeoutSeconds int `json:"timeoutSeconds"`
\tCatchPanics bool `json:"catchPanics"`
}

type Response struct {
\tSessionId string `json:"sessionId,omitempty"`
\tHeaders map[string][]string `json:"headers"`
}

type Timestamp struct {
\ttime.Time
}
"""

MAIN_GO = (
    "//export freeMemory\nfunc freeMemory(id *C.char) {}\n\n//export request\nfunc request() {}\n"
)


def macho(major: int, minor: int) -> bytes:
    command = struct.pack("<IIIIII", 0x32, 24, 1, (major << 16) | (minor << 8), 0, 0)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 6, 1, len(command), 0, 0)
    return header + command


def test_parse_profiles():
    names, default = upstream.parse_profiles(PROFILES_GO)
    assert names == ["chrome_1", "chrome_2", "firefox_1", "mms_ios", "mms_ios_1"]
    assert default == "chrome_2"


def test_parse_types_and_exports():
    structs = upstream.parse_types(TYPES_GO)
    assert structs["RequestInput"] == {
        "customTlsClient": "*CustomTlsClient",
        "headers": "map[string]string",
        "sessionId": "*string",
        "timeoutSeconds": "int",
        "catchPanics": "bool",
    }
    assert structs["Response"] == {"sessionId": "string", "headers": "map[string][]string"}
    assert structs["Timestamp"] == {}
    assert upstream.parse_exports(MAIN_GO) == ["freeMemory", "request"]


@pytest.mark.parametrize(
    "go_type, kind",
    [
        ("string", "string"),
        ("*string", "string"),
        ("bool", "boolean"),
        ("int", "number"),
        ("uint32", "number"),
        ("*time.Duration", "number"),
        ("Timestamp", "number"),
        ("[]string", "array"),
        ("CandidateCipherSuites", "array"),
        ("map[string][]string", "object"),
        ("*CustomTlsClient", "object"),
    ],
)
def test_go_kind(go_type, kind):
    assert upstream.go_kind(go_type) == kind


def test_diff_snapshots():
    old = {"exports": ["a", "b"], "structs": {"S": {"x": "int", "y": "string"}}}
    new = {
        "exports": ["a", "c"],
        "structs": {"S": {"x": "[]int", "z": "bool"}, "T": {"w": "int"}},
    }
    assert upstream.diff_snapshots(old, new) == {
        "added": ["S.z", "T.w"],
        "removed": ["S.y"],
        "retyped": ["S.x: int -> []int"],
        "exports_added": ["c"],
        "exports_removed": ["b"],
    }


def test_wheel_tags_come_from_the_files():
    assert upstream.macos_min(macho(13, 0)) == (13, 0)
    assert upstream.wheel_tag("darwin-arm64", macho(14, 2)) == "macosx_14_2_arm64"
    assert upstream.glibc_max(b"GLIBC_2.2.5\x00GLIBC_2.17\x00") == (2, 17)
    ok = upstream.wheel_tag("linux-arm64", b"GLIBC_2.17")
    assert ok == "manylinux_2_17_aarch64.manylinux2014_aarch64"
    with pytest.raises(ValueError, match="GLIBC_2.34"):
        upstream.wheel_tag("linux-amd64", b"GLIBC_2.34")
    with pytest.raises(ValueError, match="Mach-O"):
        upstream.macos_min(b"MZ not a dylib")


def test_asset_digests():
    release = {
        "assets": [
            {"name": "a.so", "digest": "sha256:" + "a" * 64},
            {"name": "b.so", "digest": None},
        ]
    }
    assert upstream.asset_digests(release) == {"a.so": "a" * 64}


def test_targets_match_the_pins():
    pins = upstream.pins()
    assert upstream.TARGET_ORDER == tuple(pins.BINARIES)
    for target in upstream.TARGET_ORDER:
        asset, _digest, tag = pins.BINARIES[target]
        assert asset == upstream.asset_name(target, pins.LIBRARY_VERSION)
        template = upstream.TARGETS[target][1]
        assert re.fullmatch(re.escape(template).replace(r"\{mac\}", r"\d+_\d+"), tag), tag
