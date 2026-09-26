"""tlsmask: talk to websites the way a real browser does, down to the TLS handshake.

A drop-in replacement for the `tls-client` package that runs bogdanfinn's
current tls-client library, bundled and pinned by SHA-256:

    import tlsmask

    with tlsmask.Session("chrome_150") as session:
        print(session.get("https://tls.peet.ws/api/all").json()["tls"]["ja4"])
"""

from ._pins import DEFAULT_PROFILE, PROFILES
from ._pins import LIBRARY_VERSION as __library_version__
from ._version import __version__
from .asyncio import AsyncSession
from .cookies import CookieJar
from .exceptions import HTTPError, TLSClientException, TLSClientExeption
from .profiles import ClientIdentifier, ClientIdentifiers
from .response import Response
from .sessions import Session
from .structures import CaseInsensitiveDict

__all__ = [
    "DEFAULT_PROFILE",
    "PROFILES",
    "AsyncSession",
    "CaseInsensitiveDict",
    "ClientIdentifier",
    "ClientIdentifiers",
    "CookieJar",
    "HTTPError",
    "Response",
    "Session",
    "TLSClientException",
    "TLSClientExeption",
    "__library_version__",
    "__version__",
]
