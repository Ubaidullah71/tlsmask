"""What tlsmask bundles is consistent with itself."""

from __future__ import annotations

import re
from typing import get_args

import tlsmask
from tlsmask import _pins, profiles

TARGETS = {
    "windows-amd64",
    "windows-386",
    "darwin-arm64",
    "darwin-amd64",
    "linux-amd64",
    "linux-arm64",
    "linux-armv7",
}


def test_every_pinned_file_is_this_version_with_a_real_digest():
    assert set(_pins.BINARIES) == TARGETS
    for asset, digest, tag in _pins.BINARIES.values():
        assert _pins.LIBRARY_VERSION in asset
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        assert tag


def test_the_profile_type_lists_exactly_the_pinned_profiles():
    assert set(get_args(profiles.ClientIdentifier)) == _pins.PROFILES
    assert profiles.ClientIdentifiers is profiles.ClientIdentifier
    assert _pins.DEFAULT_PROFILE in _pins.PROFILES


def test_the_package_version_carries_the_library_version():
    assert tlsmask.__version__.startswith(_pins.LIBRARY_VERSION)
    assert tlsmask.__library_version__ == _pins.LIBRARY_VERSION


def test_the_old_misspelled_exception_is_the_same_class():
    assert tlsmask.TLSClientExeption is tlsmask.TLSClientException
    assert issubclass(tlsmask.TLSClientException, IOError)
    assert issubclass(tlsmask.HTTPError, tlsmask.TLSClientException)
    assert tlsmask.HTTPError("x", response="r").response == "r"
