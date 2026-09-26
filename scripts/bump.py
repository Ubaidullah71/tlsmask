"""Move tlsmask to a bogdanfinn/tls-client release: the update bot's logic.

    python scripts/bump.py                          # to the latest release
    python scripts/bump.py --version 1.17.0
    python scripts/bump.py --report report.md --github-output "$GITHUB_OUTPUT"

It downloads every file tlsmask ships and refuses any whose SHA-256 is not the
digest GitHub publishes for it, re-derives each wheel tag from the file itself,
reads the new profile list and JSON API, and rewrites the generated files. It
then decides whether the update may ship without a human; the workflow also
requires every test to pass (.github/workflows/update.yml).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import render
import upstream

MIN_AGE_DAYS = 7


class BumpError(Exception):
    """The release cannot be packaged as it is; a human has to look."""


@dataclass
class Update:
    version: str
    files: dict[str, str | None]  # repo-relative path -> new content; None deletes it
    report: str
    reasons: list[str] = field(default_factory=list)  # why it may not ship by itself

    @property
    def safe(self) -> bool:
        return not self.reasons


def _macos(tag: str) -> tuple[int, int]:
    match = re.search(r"macosx_(\d+)_(\d+)_", tag)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def _version(tag: str) -> tuple[int, ...] | None:
    match = re.fullmatch(r"v?(\d+(?:\.\d+)*)", tag)
    return tuple(int(part) for part in match.group(1).split(".")) if match else None


def bump(
    release: Mapping[str, Any],
    pins: ModuleType,
    *,
    root: Path = upstream.ROOT,
    download: Callable[[str, str], bytes] = upstream.download,
    source: Callable[[str, str], str] = upstream.source,
    releases: Callable[[], list[dict[str, Any]]] = upstream.releases,
    now: dt.datetime | None = None,
) -> Update:
    now = now or dt.datetime.now(dt.timezone.utc)
    version = str(release["tag_name"]).lstrip("v")
    old = pins.LIBRARY_VERSION
    if _version(version) is None or _version(version) <= _version(old):
        raise BumpError(f"v{version} is not newer than the bundled v{old}")

    digests = upstream.asset_digests(release)
    binaries: dict[str, tuple[str, str, str]] = {}
    for target in upstream.TARGET_ORDER:
        asset = upstream.asset_name(target, version)
        if asset not in digests:
            raise BumpError(f"v{version} has no {asset} with a published SHA-256 (target {target})")
        data = download(version, asset)
        actual = upstream.sha256(data)
        if actual != digests[asset]:
            raise BumpError(
                f"{asset} downloaded as {actual}, but GitHub publishes {digests[asset]}"
            )
        try:
            binaries[target] = (asset, actual, upstream.wheel_tag(target, data))
        except ValueError as exc:
            raise BumpError(f"{asset}: {exc}") from None

    profiles, default = upstream.parse_profiles(source(version, "profiles/profiles.go"))
    new_api = upstream.snapshot(
        version, source(version, "cffi_src/types.go"), source(version, "cffi_dist/main.go")
    )
    old_api_path = root / "tests" / "contract" / f"types-{old}.json"
    api = upstream.diff_snapshots(json.loads(old_api_path.read_text(encoding="utf-8")), new_api)
    added = sorted(set(profiles) - set(pins.PROFILES))
    removed = sorted(set(pins.PROFILES) - set(profiles))

    published = dt.datetime.fromisoformat(str(release["published_at"]).replace("Z", "+00:00"))
    age = (now - published).days
    released = published.date().isoformat()

    reasons = []
    if age < MIN_AGE_DAYS:
        reasons.append(
            f"released {age} days ago; it ships by itself once it is {MIN_AGE_DAYS} days old, "
            "in case it gets pulled or patched"
        )
    if removed:
        reasons.append(f"profiles removed: {', '.join(removed)}")
    for target, (_asset, _digest, old_tag) in getattr(pins, "BINARIES", {}).items():
        new_tag = binaries[target][2]
        if target.startswith("darwin-") and _macos(new_tag) > _macos(old_tag):
            reasons.append(
                f"the macOS minimum rises from {'.'.join(map(str, _macos(old_tag)))} to "
                f"{'.'.join(map(str, _macos(new_tag)))}: older Macs would stop getting a wheel"
            )
            break
    if api["removed"]:
        reasons.append(f"JSON fields removed: {', '.join(api['removed'])}")
    if api["retyped"]:
        reasons.append(f"JSON fields retyped: {', '.join(api['retyped'])}")
    if api["exports_removed"]:
        reasons.append(f"C functions removed: {', '.join(api['exports_removed'])}")

    readme = (root / "README.md").read_text(encoding="utf-8")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    entry = render.changelog_entry(
        version, now.date().isoformat(), str(release["html_url"]), added, removed
    )
    files: dict[str, str | None] = {
        "tlsmask/_pins.py": render.render_pins(version, released, binaries, default, profiles),
        "tlsmask/profiles.py": render.render_profiles_module(version, profiles),
        "tlsmask/_version.py": render.render_version(version),
        f"tests/contract/types-{old}.json": None,
        f"tests/contract/types-{version}.json": upstream.snapshot_json(new_api),
        "README.md": render.refresh_readme(readme, version, released, profiles),
        "CHANGELOG.md": render.add_changelog_entry(changelog, entry),
    }

    between = []
    for candidate in releases():
        number = _version(str(candidate.get("tag_name", "")))
        if candidate.get("draft") or candidate.get("prerelease") or number is None:
            continue
        if _version(old) < number <= _version(version):
            between.append((number, str(candidate["tag_name"]), str(candidate.get("body") or "")))
    notes = [(tag, body) for _number, tag, body in sorted(between)]

    report = render.render_report(
        version=version,
        old_version=old,
        url=str(release["html_url"]),
        released=released,
        age_days=age,
        reasons=reasons,
        added=added,
        removed=removed,
        old_default=pins.DEFAULT_PROFILE,
        default=default,
        old_count=len(pins.PROFILES),
        api=api,
        binaries=binaries,
        notes=notes,
    )
    return Update(version, files, report, reasons)


def write(update: Update, root: Path = upstream.ROOT) -> None:
    for relative, content in update.files.items():
        path = root / relative
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content.encode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--version", default="", help="upstream version (default: the latest release)"
    )
    parser.add_argument("--report", type=Path, help="write the pull request description here")
    parser.add_argument(
        "--github-output", type=Path, help="append changed/safe/version for GitHub Actions"
    )
    args = parser.parse_args(argv)

    pins = upstream.pins()
    release = upstream.release(args.version) if args.version else upstream.latest_release()
    version = str(release["tag_name"]).lstrip("v")
    outputs = {"changed": "false", "safe": "false", "version": version}
    if version == pins.LIBRARY_VERSION:
        print(f"up to date: tlsmask bundles tls-client {version}")
    else:
        update = bump(release, pins)
        write(update)
        if args.report:
            args.report.write_bytes(update.report.encode("utf-8"))
        outputs.update(changed="true", safe=str(update.safe).lower())
        print(update.report)
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                handle.write(f"{key}={value}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
