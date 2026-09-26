from __future__ import annotations

import os
import threading

import pytest
from server import Handler, QuietServer

import tlsmask
from tlsmask import _library


@pytest.fixture(scope="session", autouse=True)
def real_library():
    ok, detail = _library.verify()
    if not ok:
        if os.environ.get("TLSMASK_REQUIRE_LIBRARY"):
            pytest.fail(f"the real library is required here: {detail}")
        pytest.skip(f"no tls-client library (run scripts/fetch_binaries.py): {detail}")
    if os.environ.get("TLSMASK_EXPECT_INSTALLED") and "site-packages" not in tlsmask.__file__:
        pytest.fail(f"testing {tlsmask.__file__}, not the installed wheel")


@pytest.fixture(scope="session")
def server():
    httpd = QuietServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
