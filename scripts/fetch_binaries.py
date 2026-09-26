"""Download the pinned tls-client files, refusing any whose SHA-256 differs.

python scripts/fetch_binaries.py                   # this machine's file -> tlsmask/bin/ (for tests)
python scripts/fetch_binaries.py all               # every target -> build/bin/ (for wheels)
python scripts/fetch_binaries.py linux-amd64 linux-arm64 --dest build/bin
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import upstream


def fetch(
    target: str,
    dest: Path,
    pins: ModuleType,
    download: Callable[[str, str], bytes] = upstream.download,
) -> Path:
    asset, expected, _tag = pins.BINARIES[target]
    path = dest / asset
    if path.is_file() and upstream.sha256(path.read_bytes()) == expected:
        return path
    data = download(pins.LIBRARY_VERSION, asset)
    actual = upstream.sha256(data)
    if actual != expected:
        raise SystemExit(f"REFUSED {asset}: it hashes to {actual}, but {expected} is pinned")
    dest.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".part")
    partial.write_bytes(data)
    partial.replace(path)
    return path


def this_machine() -> str:
    sys.path.insert(0, str(upstream.ROOT))
    from tlsmask._library import current_target

    target = current_target()
    if target is None:
        raise SystemExit("bogdanfinn ships no tls-client build for this machine")
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("targets", nargs="*", help="targets from tlsmask/_pins.py, or 'all'")
    parser.add_argument(
        "--dest", type=Path, help="default: tlsmask/bin (this machine) or build/bin"
    )
    args = parser.parse_args(argv)
    pins = upstream.pins()
    install = not args.targets
    if install:
        targets = [this_machine()]
        dest = args.dest or upstream.ROOT / "tlsmask" / "bin"
    else:
        targets = list(pins.BINARIES) if args.targets == ["all"] else args.targets
        dest = args.dest or upstream.ROOT / "build" / "bin"
    unknown = sorted(set(targets) - set(pins.BINARIES))
    if unknown:
        raise SystemExit(
            f"unknown target(s) {', '.join(unknown)}; choose from {', '.join(pins.BINARIES)}"
        )
    for target in targets:
        path = fetch(target, dest, pins)
        print(f"{target:14} {path.name}  sha256 as pinned")
    if install:  # older versions in tlsmask/bin are dead weight
        keep = {pins.BINARIES[target][0] for target in targets}
        for old in dest.glob("tls-client-*"):
            if old.name not in keep:
                old.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
