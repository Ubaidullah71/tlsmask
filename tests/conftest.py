from __future__ import annotations

import gc

import pytest
from fake_library import FakeLibrary

from tlsmask import _library


@pytest.fixture()
def fake(monkeypatch):
    """bogdanfinn's library replaced by a recorder; nothing native is loaded."""
    gc.collect()  # sessions dropped by earlier tests end their Go clients now, not mid-test
    lib = FakeLibrary()
    monkeypatch.setattr(_library, "_lib", lib)
    return lib
