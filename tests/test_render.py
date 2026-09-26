from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import render
import upstream

ROOT = Path(__file__).resolve().parent.parent
PINS = upstream.pins()
SAMPLE = [
    "chrome_120", "chrome_152_PSK", "chrome_150", "firefox_148", "firefox_147_PSK",
    "safari_ios_18_5", "safari_ios_26_0", "safari_16_0", "safari_ipad_15_6",
    "brave_146", "opera_91", "okhttp4_android_13", "okhttp4_android_7",
]  # fmt: skip


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_the_committed_generated_files_are_exactly_what_render_produces():
    pins = render.render_pins(
        PINS.LIBRARY_VERSION,
        PINS.LIBRARY_RELEASED,
        PINS.BINARIES,
        PINS.DEFAULT_PROFILE,
        PINS.PROFILES,
    )
    assert pins == read("tlsmask/_pins.py")
    profiles = render.render_profiles_module(PINS.LIBRARY_VERSION, PINS.PROFILES)
    assert profiles == read("tlsmask/profiles.py")
    version = upstream.load_module(ROOT / "tlsmask" / "_version.py").__version__
    assert render.render_version(version) == read("tlsmask/_version.py")


def test_newest_per_family():
    assert render.newest(SAMPLE, render.CHROME) == "152"
    assert render.newest(SAMPLE, render.FIREFOX) == "148"
    assert render.newest(SAMPLE, render.SAFARI_IOS) == "26.0"
    assert render.newest(["chrome_1"], render.BRAVE) == "none"


def test_families_and_natural_order():
    assert render.family("safari_ios_26_0") == "Safari (iOS & iPadOS)"
    assert render.family("safari_ipad_15_6") == "Safari (iOS & iPadOS)"
    assert render.family("safari_16_0") == "Safari (macOS)"
    assert render.family("okhttp4_android_7") == render.OTHERS
    assert sorted(["okhttp4_android_13", "okhttp4_android_7"], key=render.natural) == [
        "okhttp4_android_7",
        "okhttp4_android_13",
    ]
    assert render.month_year("2026-09-02") == "Sep 2026"


def test_stats_table():
    table = render.render_stats("1.16.0", "2026-09-02", SAMPLE)
    assert "| bogdanfinn/tls-client inside | v1.7.2 | **v1.16.0** |" in table
    assert f"| Browser & app profiles | 51 | **{len(SAMPLE)}** |" in table
    assert "| Newest Chrome | 120 | **152** |" in table
    assert "| Newest iOS Safari | 16.0 | **26.0** |" in table
    assert "| Last updated | Feb 2024 | **Sep 2026** |" in table


def test_profile_table_groups_by_family():
    table = render.render_profile_table("1.16.0", SAMPLE)
    assert f"All {len(SAMPLE)} profiles in tls-client v1.16.0" in table
    assert "| Mobile apps & others | `okhttp4_android_7` `okhttp4_android_13` |" in table
    assert (
        "| Safari (iOS & iPadOS) | `safari_ios_18_5` `safari_ios_26_0` `safari_ipad_15_6` |"
        in table
    )


def test_replace_block():
    text = "a <!-- x:start -->old<!-- x:end --> b"
    assert render.replace_block(text, "x", "new") == "a <!-- x:start -->new<!-- x:end --> b"
    with pytest.raises(ValueError, match="y:start"):
        render.replace_block(text, "y", "new")


def test_changelog():
    log = "# Changelog\n\n## 1.16.0 - 2026-09-26\n\nFirst.\n"
    entry = render.changelog_entry(
        "1.17.0", "2026-10-10", "https://x/v1.17.0", ["chrome_160"], ["chrome_103"]
    )
    log = render.add_changelog_entry(log, entry)
    assert log.startswith("# Changelog\n\n## 1.17.0 - 2026-10-10\n")
    assert log.index("## 1.17.0") < log.index("## 1.16.0")
    section = render.changelog_section(log, "1.17.0")
    assert "`chrome_160`" in section and "`chrome_103`" in section
    assert render.changelog_section(log, "1.16.0") == "First."
    patched = render.add_changelog_entry(log, "## 1.16.0.1 - 2026-10-11\n\nFix.\n")
    assert render.changelog_section(patched, "1.16.0") == "First."
    with pytest.raises(ValueError, match="1.99.0"):
        render.changelog_section(log, "1.99.0")


def test_refresh_rewrites_only_what_changed(tmp_path):
    for relative in ("tlsmask/_pins.py", "tlsmask/profiles.py", "tlsmask/_version.py"):
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / relative, tmp_path / relative)
    blocks = "".join(
        f"<!-- {n}:start --><!-- {n}:end -->\n" for n in ("badge", "stats", "profiles")
    )
    (tmp_path / "README.md").write_bytes(blocks.encode())
    assert render.refresh(tmp_path) == ["README.md"]
    assert render.refresh(tmp_path) == []
    assert f"**v{PINS.LIBRARY_VERSION}**" in (tmp_path / "README.md").read_text(encoding="utf-8")


def test_the_readme_blocks_are_current():
    readme = read("README.md")
    expected = render.refresh_readme(
        readme, PINS.LIBRARY_VERSION, PINS.LIBRARY_RELEASED, PINS.PROFILES
    )
    assert readme == expected, "run: python scripts/render.py refresh"


def test_the_badge_is_html_so_it_renders_next_to_the_comment_markers():
    # GitHub shows Markdown on a line that starts with "<!--" as raw text
    badge = render.render_badge("1.16.0")
    assert badge.startswith(
        '<a href="https://github.com/bogdanfinn/tls-client/releases/tag/v1.16.0">'
    )
    assert '<img src="https://img.shields.io/badge/bundles_tls--client-v1.16.0-0a7cff"' in badge
