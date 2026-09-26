"""`python -m tlsmask`: which tls-client this is, and whether its file checks out.

Paste the output into bug reports.
"""

from __future__ import annotations

import sys

from . import _library, _pins
from ._version import __version__
from .exceptions import TLSClientException


def main() -> int:
    ok, detail = _library.verify()
    if ok:
        try:  # a file can hash fine and still not load (another platform, too old a system)
            _library.call("destroySession", {"sessionId": "tlsmask-self-check"})
        except TLSClientException as exc:
            ok, detail = False, f"{detail}, but it could not be loaded: {exc}"
    target = _library.current_target() or "no bundled build"
    print(f"tlsmask     {__version__}")
    print(f"tls-client  {_pins.LIBRARY_VERSION} (github.com/bogdanfinn/tls-client)")
    print(f"platform    {_library.platform_label()} -> {target}")
    print(f"library     {'OK' if ok else 'PROBLEM'}: {detail}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
