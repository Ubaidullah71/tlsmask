"""Real fingerprints, checked by public echo services (needs the internet: pytest -m live)."""

from __future__ import annotations

import pytest

from tlsmask import Session, TLSClientException, _library

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not _library.verify()[0], reason="no tls-client library"),
]
# Each service reports the JA4 fingerprint it saw; the second is used when the
# first is down.
ECHOES = [
    ("https://tls.peet.ws/api/all", lambda data: data["tls"]["ja4"]),
    ("https://tls.browserleaks.com/json", lambda data: data["ja4"]),
]
FAMILIES = ["chrome_150", "firefox_148", "safari_ios_26_0"]
CHROME_JA3 = (
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
    "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
)


def ja4(session):
    """(response, the JA4 the echo service saw), from the first service that answers."""
    failures = []
    for url, read in ECHOES:
        try:
            response = session.get(url, timeout=20)
            if response.status_code == 200:
                return response, read(response.json())
            failures.append(f"{url}: {response.status_code}")
        except (TLSClientException, ValueError, KeyError) as exc:
            failures.append(f"{url}: {exc}")
    pytest.skip("no fingerprint echo service reachable: " + "; ".join(failures))


@pytest.mark.parametrize("profile", FAMILIES)
def test_each_family_speaks_http2_with_a_stable_fingerprint(profile):
    with Session(profile) as s:
        first, fingerprint = ja4(s)
        _, again = ja4(s)
    assert first.protocol == "HTTP/2.0"
    assert fingerprint == again


def test_browser_families_do_not_share_a_fingerprint():
    seen = {}
    for profile in FAMILIES:
        with Session(profile) as s:
            seen[profile] = ja4(s)[1]
    assert len(set(seen.values())) == len(FAMILIES), seen


def test_a_custom_fingerprint_without_alpn_settings_still_connects():
    # tls-client 1.16 stalls on an empty ALPN extension; tlsmask fills it in
    custom = Session(
        client_identifier=None,
        ja3_string=CHROME_JA3,
        supported_signature_algorithms=[
            "ECDSAWithP256AndSHA256",
            "PSSWithSHA256",
            "PKCS1WithSHA256",
        ],
        supported_versions=["GREASE", "1.3", "1.2"],
        key_share_curves=["GREASE", "X25519"],
        cert_compression_algos=["brotli"],
    )
    with custom as s:
        response, fingerprint = ja4(s)
    assert response.protocol == "HTTP/2.0"
    assert fingerprint.startswith("t13d")
