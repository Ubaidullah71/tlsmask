"""bogdanfinn/tls-client's releases, as tlsmask's scripts and tests need them.

Fetchers use only urllib (GITHUB_TOKEN, if set, lifts GitHub's API rate
limit). Scripts never import the tlsmask package; they read the pins by path.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import struct
import urllib.request
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REPO = "bogdanfinn/tls-client"
API = f"https://api.github.com/repos/{REPO}"
RAW = f"https://raw.githubusercontent.com/{REPO}"
DOWNLOAD = f"https://github.com/{REPO}/releases/download/v{{version}}/{{asset}}"


def load_module(path: Path) -> ModuleType:
    """Import one file by its path."""
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader, path
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pins() -> ModuleType:
    return load_module(ROOT / "tlsmask" / "_pins.py")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _get(url: str, accept: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"Accept": accept, "User-Agent": "tlsmask-scripts"}
    )
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def download(version: str, asset: str) -> bytes:
    return _get(DOWNLOAD.format(version=version, asset=asset), "application/octet-stream")


def source(version: str, path: str) -> str:
    return _get(f"{RAW}/v{version}/{path}", "text/plain").decode("utf-8")


def release(version: str) -> dict[str, Any]:
    return json.loads(_get(f"{API}/releases/tags/v{version}", "application/vnd.github+json"))


def latest_release() -> dict[str, Any]:
    """The newest release that is neither a draft nor a prerelease."""
    return json.loads(_get(f"{API}/releases/latest", "application/vnd.github+json"))


def releases() -> list[dict[str, Any]]:
    return json.loads(_get(f"{API}/releases?per_page=100", "application/vnd.github+json"))


# target -> (asset name template, wheel platform tag template). {mac} is
# filled from the dylib's own minimum macOS version.
TARGETS: dict[str, tuple[str, str]] = {
    "windows-amd64": ("tls-client-windows-64-{version}.dll", "win_amd64"),
    "windows-386": ("tls-client-windows-32-{version}.dll", "win32"),
    "darwin-arm64": ("tls-client-darwin-arm64-{version}.dylib", "macosx_{mac}_arm64"),
    "darwin-amd64": ("tls-client-darwin-amd64-{version}.dylib", "macosx_{mac}_x86_64"),
    "linux-amd64": (
        "tls-client-linux-ubuntu-amd64-{version}.so",
        "manylinux_2_17_x86_64.manylinux2014_x86_64",
    ),
    "linux-arm64": (
        "tls-client-linux-arm64-{version}.so",
        "manylinux_2_17_aarch64.manylinux2014_aarch64",
    ),
    "linux-armv7": (
        "tls-client-linux-armv7-{version}.so",
        "manylinux_2_17_armv7l.manylinux2014_armv7l",
    ),
}
# No Alpine (musl) wheel: upstream's musl build can't be loaded with dlopen ("initial-exec
# TLS resolves to dynamic definition"), so Python could never use it.
TARGET_ORDER = tuple(TARGETS)
GLIBC_CEILING = (2, 17)  # every glibc tag above is manylinux_2_17

_STRUCT = re.compile(r"^type (\w+) struct \{\n(.*?)^\}", re.M | re.S)
_FIELD = re.compile(r'^\s*\w+\s+(\S+)\s+`json:"([^",]+)')
_NUMBERS = {
    "int", "int8", "int16", "int32", "int64",
    "uint", "uint8", "uint16", "uint32", "uint64",
    "float32", "float64", "time.Duration", "Timestamp",
}  # fmt: skip


def asset_name(target: str, version: str) -> str:
    return TARGETS[target][0].format(version=version)


def asset_digests(release: dict[str, Any]) -> dict[str, str]:
    """asset name -> SHA-256 hex, as GitHub publishes it for the release."""
    digests = {}
    for asset in release.get("assets", []):
        digest = asset.get("digest") or ""
        if digest.startswith("sha256:"):
            digests[asset["name"]] = digest.split(":", 1)[1]
    return digests


def parse_profiles(go_src: str) -> tuple[list[str], str]:
    """(every MappedTLSClients key, sorted; the name of DefaultClientProfile) from profiles.go."""
    block = re.search(r"MappedTLSClients\s*=\s*map\[string\]ClientProfile\{(.*?)\n\}", go_src, re.S)
    default = re.search(r"DefaultClientProfile\s*=\s*(\w+)", go_src)
    if not block or not default:
        raise ValueError("profiles.go no longer has MappedTLSClients and DefaultClientProfile")
    pairs = re.findall(r'"([^"]+)"\s*:\s*(\w+)', block.group(1))
    names = [name for name, var in pairs if var == default.group(1)]
    if not names:
        raise ValueError(f"no profile name maps to {default.group(1)}")
    chosen = next((name for name in names if name == default.group(1).lower()), names[0])
    return sorted({name for name, _ in pairs}), chosen


def parse_types(go_src: str) -> dict[str, dict[str, str]]:
    """struct -> JSON tag -> Go type, for every struct in a Go file."""
    structs = {}
    for name, body in _STRUCT.findall(go_src):
        fields = {}
        for line in body.splitlines():
            match = _FIELD.match(line)
            if match:
                fields[match.group(2)] = match.group(1)
        structs[name] = fields
    return structs


def parse_exports(go_src: str) -> list[str]:
    return sorted(re.findall(r"^//export (\w+)", go_src, re.M))


def go_kind(go_type: str) -> str:
    """The JSON kind Go's encoding/json reads into `go_type`."""
    bare = go_type.lstrip("*")
    if bare.startswith("[]") or bare == "CandidateCipherSuites":
        return "array"
    if bare.startswith("map["):
        return "object"
    if bare == "string":
        return "string"
    if bare == "bool":
        return "boolean"
    if bare in _NUMBERS:
        return "number"
    return "object"  # a struct


def snapshot(version: str, types_src: str, main_src: str) -> dict[str, Any]:
    return {
        "version": version,
        "exports": parse_exports(main_src),
        "structs": parse_types(types_src),
    }


def snapshot_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def diff_snapshots(old: dict[str, Any], new: dict[str, Any]) -> dict[str, list[str]]:
    added, removed, retyped = [], [], []
    for name in sorted(set(old["structs"]) | set(new["structs"])):
        before = old["structs"].get(name, {})
        after = new["structs"].get(name, {})
        added += [f"{name}.{field}" for field in sorted(set(after) - set(before))]
        removed += [f"{name}.{field}" for field in sorted(set(before) - set(after))]
        retyped += [
            f"{name}.{field}: {before[field]} -> {after[field]}"
            for field in sorted(set(before) & set(after))
            if before[field] != after[field]
        ]
    return {
        "added": added,
        "removed": removed,
        "retyped": retyped,
        "exports_added": sorted(set(new["exports"]) - set(old["exports"])),
        "exports_removed": sorted(set(old["exports"]) - set(new["exports"])),
    }


def macos_min(data: bytes) -> tuple[int, int]:
    """The minimum macOS a 64-bit Mach-O file declares (LC_BUILD_VERSION or LC_VERSION_MIN_MACOSX)."""
    if len(data) < 32 or struct.unpack_from("<I", data, 0)[0] != 0xFEEDFACF:
        raise ValueError("not a 64-bit Mach-O file")
    (count,) = struct.unpack_from("<I", data, 16)
    offset = 32
    for _ in range(count):
        command, size = struct.unpack_from("<II", data, offset)
        if command == 0x32:  # LC_BUILD_VERSION: platform, minos, sdk
            (version,) = struct.unpack_from("<I", data, offset + 12)
            return version >> 16, (version >> 8) & 0xFF
        if command == 0x24:  # LC_VERSION_MIN_MACOSX: version, sdk
            (version,) = struct.unpack_from("<I", data, offset + 8)
            return version >> 16, (version >> 8) & 0xFF
        offset += size
    raise ValueError("the Mach-O file declares no minimum macOS version")


def glibc_max(data: bytes) -> tuple[int, ...]:
    """The newest GLIBC_x.y symbol version an ELF file asks for; () if none."""
    found = [
        tuple(int(part) for part in match.split(b"."))
        for match in re.findall(rb"GLIBC_(\d+(?:\.\d+)+)", data)
    ]
    return max(found, default=())


def wheel_tag(target: str, data: bytes) -> str:
    tag = TARGETS[target][1]
    if target.startswith("darwin-"):
        major, minor = macos_min(data)
        return tag.format(mac=f"{major}_{minor}")
    if target.startswith("linux-"):
        needed = glibc_max(data)
        if needed > GLIBC_CEILING:
            version = ".".join(str(part) for part in needed)
            raise ValueError(f"needs GLIBC_{version}, newer than its manylinux_2_17 tag")
    return tag


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Snapshot a tls-client release's JSON API.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("snapshot").add_argument("version")
    args = parser.parse_args(argv)
    data = snapshot(
        args.version,
        source(args.version, "cffi_src/types.go"),
        source(args.version, "cffi_dist/main.go"),
    )
    path = ROOT / "tests" / "contract" / f"types-{args.version}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(snapshot_json(data).encode("utf-8"))
    print(f"wrote {path.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
