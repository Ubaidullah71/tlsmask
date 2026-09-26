"""Finding, checking and calling bogdanfinn's tls-client library.

The library's C API takes a JSON string and returns one. Each answer carries an
`id` and stays allocated inside Go until `freeMemory(id)` is called, so every
answer is freed here, right after ctypes has copied it into Python bytes.

Only the file shipped inside the wheel is loaded, and only if its SHA-256 is
the one pinned in `_pins.py`. `TLSMASK_LIBRARY_PATH` names another file (for a
platform without a wheel, or your own build), which is used as-is.
"""

from __future__ import annotations

import ctypes
import glob
import hashlib
import json
import os
import platform
import struct
import sys
import threading
from pathlib import Path
from typing import Any

from . import _pins
from .exceptions import TLSClientException

BIN_DIR = Path(__file__).resolve().parent / "bin"
ENV_VAR = "TLSMASK_LIBRARY_PATH"

# The C functions tlsmask calls; tests/test_contract.py checks the pinned
# version still exports each one.
BOUND = ("request", "destroySession", "freeMemory")

_ARCH = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "arm64": "arm64",
    "aarch64": "arm64",
    "armv7l": "armv7",
    "armv8l": "armv7",
}


def _is_musl() -> bool:
    # a glibc distro can have musl installed next to it; only a system without
    # glibc is really musl-based (Alpine)
    if platform.libc_ver()[0] == "glibc":
        return False
    return bool(glob.glob("/lib/ld-musl-*.so.1"))


def current_target(
    system: str | None = None,
    machine: str | None = None,
    bits: int | None = None,
    musl: bool | None = None,
) -> str | None:
    """This interpreter's key in `_pins.BINARIES`, or None if upstream ships no build for it."""
    system = system or sys.platform
    machine = (platform.machine() if machine is None else machine).lower()
    bits = bits or struct.calcsize("P") * 8
    if system in ("win32", "cygwin"):
        if machine in ("arm64", "aarch64"):
            return None  # bogdanfinn publishes no Windows ARM build
        return "windows-amd64" if bits == 64 else "windows-386"
    arch = _ARCH.get(machine)
    if system == "darwin":
        return f"darwin-{arch}" if arch in ("amd64", "arm64") else None
    if system.startswith("linux"):
        if arch == "amd64":
            return "musl-amd64" if (_is_musl() if musl is None else musl) else "linux-amd64"
        if arch == "arm64":
            return "linux-arm64" if bits == 64 else "linux-armv7"
        if arch == "armv7":
            return "linux-armv7"
    return None


def platform_label() -> str:
    return f"{sys.platform}/{platform.machine() or '?'} ({struct.calcsize('P') * 8}-bit Python)"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _bundled() -> tuple[str, Path] | None:
    """(target, file) for the library inside this install, if there is one."""
    target = current_target()
    if target in _pins.BINARIES:
        path = BIN_DIR / _pins.BINARIES[target][0]
        if path.is_file():
            return target, path
    # pip picked the wheel for this machine, so the one file it installed is
    # the right one, even where current_target() guesses wrong.
    for name, (asset, _digest, _tag) in _pins.BINARIES.items():
        path = BIN_DIR / asset
        if path.is_file():
            return name, path
    return None


def locate() -> tuple[Path, str | None]:
    """(library file, the SHA-256 it must have); None means a file the caller chose."""
    override = os.environ.get(ENV_VAR)
    if override:
        path = Path(override)
        if not path.is_file():
            raise TLSClientException(f"{ENV_VAR}={override} is not a file")
        return path, None
    found = _bundled()
    if found is None and current_target() == "musl-amd64":
        raise TLSClientException(
            "tls-client's Alpine (musl) build can't be loaded into Python, so tlsmask has no "
            "wheel for Alpine. Use a glibc-based image (python:3.12-slim, for example), or set "
            f"{ENV_VAR} to a tls-client {_pins.LIBRARY_VERSION} library that loads on your system."
        )
    if found is None and current_target() in _pins.BINARIES:
        raise TLSClientException(
            "this tlsmask install has no tls-client library, which happens when pip builds "
            "tlsmask from source instead of installing its wheel. Reinstall with "
            "`pip install --force-reinstall --only-binary=tlsmask tlsmask`, or set "
            f"{ENV_VAR} to a build of bogdanfinn/tls-client {_pins.LIBRARY_VERSION}."
        )
    if found is None:
        raise TLSClientException(
            f"tlsmask ships no tls-client library for {platform_label()}. Set {ENV_VAR} "
            f"to a build of bogdanfinn/tls-client {_pins.LIBRARY_VERSION} to use your own."
        )
    target, path = found
    return path, _pins.BINARIES[target][1]


def verify() -> tuple[bool, str]:
    """Whether the library is here and is the pinned file, with a line saying why."""
    try:
        path, expected = locate()
    except TLSClientException as exc:
        return False, str(exc)
    if expected is None:
        return True, f"{path} (from {ENV_VAR}, not hash-checked)"
    actual = sha256_of(path)
    if actual != expected:
        return False, (
            f"{path} hashes to {actual}, but tls-client {_pins.LIBRARY_VERSION} "
            f"is pinned to {expected}"
        )
    return True, f"{path} (sha256 {actual}, as pinned)"


_lib: Any = None
_lock = threading.Lock()


def _load() -> Any:
    global _lib
    if _lib is not None:
        return _lib
    with _lock:
        if _lib is not None:
            return _lib
        path, expected = locate()
        # Checked on every load, not only when the wheel was built: a truncated
        # or swapped file must fail here, not somewhere inside a native call.
        if expected is not None and sha256_of(path) != expected:
            raise TLSClientException(
                f"{path.name} is not the file pinned for tls-client {_pins.LIBRARY_VERSION} "
                "(SHA-256 mismatch); reinstall tlsmask"
            )
        try:
            lib = ctypes.CDLL(str(path))
        except OSError as exc:  # a file that is not a library for this machine
            raise TLSClientException(f"could not load {path}: {exc}") from None
        for name in ("request", "destroySession"):
            function = getattr(lib, name)
            function.argtypes = [ctypes.c_char_p]
            function.restype = ctypes.c_void_p  # a C string we copy, then free by its id
        lib.freeMemory.argtypes = [ctypes.c_char_p]
        lib.freeMemory.restype = None  # it returns nothing
        _lib = lib
        return lib


def call(function: str, payload: dict[str, Any]) -> dict[str, Any]:
    """One call into the library: JSON in, JSON out, the answer freed.

    ctypes releases the GIL for the native call, so calls made from different
    threads run in parallel.
    """
    if function not in ("request", "destroySession"):
        # only these two have their return type declared in _load()
        raise ValueError(f"tlsmask does not call tls-client's {function!r}")
    lib = _load()
    pointer = getattr(lib, function)(json.dumps(payload).encode("utf-8"))
    if not pointer:
        raise TLSClientException(f"tls-client's {function} returned nothing")
    raw = ctypes.string_at(pointer)
    try:
        answer = json.loads(raw)
    except ValueError:
        # Upstream's last-resort error path: a bare string it never
        # registered, so there is no id to free.
        raise TLSClientException(raw.decode("utf-8", "replace")) from None
    if isinstance(answer, dict) and answer.get("id"):
        lib.freeMemory(str(answer["id"]).encode("utf-8"))
    return answer
