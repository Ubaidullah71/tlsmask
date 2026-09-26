"""Hatchling build hook: put exactly one of bogdanfinn's library files into a wheel.

TLSMASK_TARGET=<target> (a key of tlsmask/_pins.BINARIES) builds that
platform's wheel from build/bin/<asset>, which scripts/fetch_binaries.py puts
there, after checking its SHA-256 once more. Without it the wheel is pure
(py3-none-any) and needs TLSMASK_LIBRARY_PATH at runtime.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


def _load_pins(root: Path) -> Any:
    spec = importlib.util.spec_from_file_location("tlsmask_pins", root / "tlsmask" / "_pins.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name != "wheel":
            return
        target = os.environ.get("TLSMASK_TARGET", "")
        if not target:
            build_data["tag"] = "py3-none-any"
            return
        root = Path(self.root)
        pins = _load_pins(root)
        if target not in pins.BINARIES:
            raise ValueError(f"TLSMASK_TARGET={target!r} is not one of {sorted(pins.BINARIES)}")
        asset, expected, tag = pins.BINARIES[target]
        source = root / "build" / "bin" / asset
        if not source.is_file():
            raise FileNotFoundError(
                f"{source} is missing; run: python scripts/fetch_binaries.py {target} --dest build/bin"
            )
        actual = hashlib.sha256(source.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"{asset} hashes to {actual}, but {expected} is pinned")
        build_data["force_include"][str(source)] = f"tlsmask/bin/{asset}"
        build_data["tag"] = f"py3-none-{tag}"
        build_data["pure_python"] = False
