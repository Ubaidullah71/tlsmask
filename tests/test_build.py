"""The wheels: exactly one of bogdanfinn's files each, the right tags, both licenses."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("hatchling")

ROOT = Path(__file__).resolve().parent.parent
TAG = "manylinux_2_17_x86_64.manylinux2014_x86_64"


@pytest.fixture()
def project(tmp_path):
    for name in ("pyproject.toml", "hatch_build.py", "README.md", "LICENSE", "LICENSE-tls-client"):
        shutil.copy(ROOT / name, tmp_path / name)
    shutil.copytree(
        ROOT / "tlsmask", tmp_path / "tlsmask", ignore=shutil.ignore_patterns("__pycache__", "bin")
    )
    return tmp_path


def pin_fake(project: Path, content: bytes) -> None:
    """Pin linux-amd64 to a fake file whose real bytes are b"real"."""
    (project / "build" / "bin").mkdir(parents=True)
    (project / "build" / "bin" / "tls-client-fake.so").write_bytes(content)
    digest = hashlib.sha256(b"real").hexdigest()
    with (project / "tlsmask" / "_pins.py").open("a", encoding="utf-8") as pins:
        pins.write(f'\nBINARIES["linux-amd64"] = ("tls-client-fake.so", "{digest}", "{TAG}")\n')


def build(project: Path, target: str | None = None) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != "TLSMASK_TARGET"}
    if target:
        env["TLSMASK_TARGET"] = target
    return subprocess.run(
        [sys.executable, "-m", "hatchling", "build", "-t", "wheel", "-d", "dist"],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
    )


def only_wheel(project: Path) -> tuple[Path, zipfile.ZipFile]:
    wheels = list((project / "dist").glob("*.whl"))
    assert len(wheels) == 1, wheels
    return wheels[0], zipfile.ZipFile(wheels[0])


def test_a_platform_wheel_carries_exactly_its_file(project):
    pin_fake(project, b"real")
    result = build(project, "linux-amd64")
    assert result.returncode == 0, result.stdout + result.stderr
    path, wheel = only_wheel(project)
    names = wheel.namelist()
    assert path.name.endswith(f"-py3-none-{TAG}.whl")
    assert [n for n in names if "/bin/" in n] == ["tlsmask/bin/tls-client-fake.so"]
    wheel_info = wheel.read(next(n for n in names if n.endswith(".dist-info/WHEEL"))).decode()
    assert "Root-Is-Purelib: false" in wheel_info
    assert "Tag: py3-none-manylinux2014_x86_64" in wheel_info
    assert "Tag: py3-none-manylinux_2_17_x86_64" in wheel_info
    licenses = {n.rsplit("/", 1)[-1] for n in names if "/licenses/" in n}
    assert licenses == {"LICENSE", "LICENSE-tls-client"}
    metadata = wheel.read(next(n for n in names if n.endswith(".dist-info/METADATA"))).decode()
    assert "License-Expression: MIT AND BSD-3-Clause" in metadata


def test_a_plain_wheel_never_ships_a_binary(project):
    (project / "tlsmask" / "bin").mkdir()
    (project / "tlsmask" / "bin" / "tls-client-dev.dll").write_bytes(b"a developer's copy")
    result = build(project)
    assert result.returncode == 0, result.stdout + result.stderr
    path, wheel = only_wheel(project)
    assert path.name.endswith("-py3-none-any.whl")
    assert not [n for n in wheel.namelist() if "/bin/" in n]


def test_a_file_that_does_not_match_its_pin_is_refused(project):
    pin_fake(project, b"not the pinned bytes")
    result = build(project, "linux-amd64")
    assert result.returncode != 0
    assert "pinned" in result.stdout + result.stderr
