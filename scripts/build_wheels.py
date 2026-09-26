"""Build every platform's wheel (one bogdanfinn file each) plus the sdist into dist/.

    python scripts/build_wheels.py                          # all targets + sdist
    python scripts/build_wheels.py --targets windows-amd64 --no-sdist

Also writes dist/SHA256SUMS. Needs hatchling installed (no build isolation).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import fetch_binaries
import upstream


def _hatch(kind: str, out: Path, env: dict[str, str]) -> None:
    subprocess.run(
        [sys.executable, "-m", "hatchling", "build", "-t", kind, "-d", str(out)],
        cwd=upstream.ROOT,
        env=env,
        check=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out", type=Path, default=upstream.ROOT / "dist")
    parser.add_argument("--targets", nargs="*", help="default: every target in tlsmask/_pins.py")
    parser.add_argument("--no-sdist", action="store_true")
    args = parser.parse_args(argv)
    pins = upstream.pins()
    targets = args.targets or list(pins.BINARIES)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("tlsmask-*"):
        old.unlink()
    (out / "SHA256SUMS").unlink(missing_ok=True)

    plain_env = {k: v for k, v in os.environ.items() if k != "TLSMASK_TARGET"}
    for target in targets:
        fetch_binaries.fetch(target, upstream.ROOT / "build" / "bin", pins)
        _hatch("wheel", out, {**plain_env, "TLSMASK_TARGET": target})
    if not args.no_sdist:
        _hatch("sdist", out, plain_env)

    sums = [f"{upstream.sha256(p.read_bytes())}  {p.name}" for p in sorted(out.glob("tlsmask-*"))]
    (out / "SHA256SUMS").write_bytes(("\n".join(sums) + "\n").encode())
    print("\n".join(sums))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
