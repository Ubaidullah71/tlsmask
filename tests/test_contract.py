"""Every field tlsmask sends exists, with the right JSON kind, in the pinned
tls-client's cffi_src/types.go (snapshot in tests/contract/). This is the test
that would have caught the old wrapper's certCompressionAlgo."""

from __future__ import annotations

import json
from pathlib import Path

import upstream

from tlsmask import _library, _payload
from tlsmask._pins import LIBRARY_VERSION

SNAPSHOT = json.loads(
    (Path(__file__).parent / "contract" / f"types-{LIBRARY_VERSION}.json").read_text(
        encoding="utf-8"
    )
)
STRUCTS = SNAPSHOT["structs"]
NESTED = {
    ("RequestInput", "customTlsClient"): "CustomTlsClient",
    ("RequestInput", "transportOptions"): "TransportOptions",
    ("CustomTlsClient", "headerPriority"): "PriorityParam",
    ("CustomTlsClient", "priorityFrames"): "PriorityFrames",
    ("CustomTlsClient", "ECHCandidateCipherSuites"): "CandidateCipherSuite",
    ("PriorityFrames", "priorityParam"): "PriorityParam",
}
# Every setting tlsmask can send, each with a value of its documented shape.
EVERYTHING = {
    "ja3_string": "771,4865-4866,0-23,29-23,0",
    "h2_settings": {"HEADER_TABLE_SIZE": 65536},
    "h2_settings_order": ["HEADER_TABLE_SIZE"],
    "supported_signature_algorithms": ["ECDSAWithP256AndSHA256"],
    "supported_delegated_credentials_algorithms": ["ECDSAWithP256AndSHA256"],
    "supported_versions": ["1.3"],
    "key_share_curves": ["X25519"],
    "cert_compression_algos": ["brotli"],
    "pseudo_header_order": [":method"],
    "connection_flow": 15663105,
    "priority_frames": [
        {"streamID": 3, "priorityParam": {"streamDep": 0, "exclusive": False, "weight": 200}}
    ],
    "header_priority": {"streamDep": 0, "exclusive": True, "weight": 255},
    "alpn_protocols": ["h2"],
    "alps_protocols": ["h2"],
    "record_size_limit": 16385,
    "ech_candidate_payloads": [128],
    "ech_candidate_cipher_suites": [{"kdfId": "HKDF_SHA256", "aeadId": "AEAD_AES_128_GCM"}],
    "h3_settings": {"QPACK_MAX_TABLE_CAPACITY": 65536},
    "h3_settings_order": ["QPACK_MAX_TABLE_CAPACITY"],
    "h3_pseudo_header_order": [":method"],
    "h3_priority_param": 1,
    "h3_send_grease_frames": True,
    "stream_id": 1,
    "random_tls_extension_order": True,
    "force_http1": False,  # True contradicts protocol racing
    "catch_panics": True,
    "debug": True,
    "certificate_pinning": {"example.com": ["pin"]},
    "disable_http3": False,  # likewise
    "with_protocol_racing": True,
    "disable_ipv4": False,
    "disable_ipv6": True,
    "local_address": "127.0.0.1:0",
    "server_name_overwrite": "example.com",
    "transport_options": {
        "idleConnTimeout": 1000000000,
        "maxIdleConns": 10,
        "disableKeepAlives": False,
    },
}


def kind(value) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (list, tuple)):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise TypeError(value)


def check(obj: dict, struct: str, path: str) -> None:
    fields = STRUCTS[struct]
    for key, value in obj.items():
        assert key in fields, (
            f"{path}.{key} is not a field of {struct} in tls-client {LIBRARY_VERSION}"
        )
        if value is None:
            continue
        expected = upstream.go_kind(fields[key])
        assert kind(value) == expected, (
            f"{path}.{key}: sent a {kind(value)}, upstream reads {fields[key]}"
        )
        nested = NESTED.get((struct, key))
        if nested:
            for item in value if isinstance(value, list) else [value]:
                check(item, nested, f"{path}.{key}")


def payload(identifier):
    client = _payload.client_options(
        {**EVERYTHING, "client_identifier": identifier}, timeout_ms=1000, insecure_skip_verify=True
    )
    return _payload.request_payload(
        session_id="s",
        client=client,
        method="POST",
        url="https://x.test/",
        headers={"a": "b"},
        header_order=["a"],
        body=b"\x00",
        proxy="http://p:1",
        is_rotating_proxy=True,
    )


def test_the_snapshot_is_for_the_pinned_version():
    assert SNAPSHOT["version"] == LIBRARY_VERSION


def test_a_profile_request_uses_only_upstream_fields():
    check(payload("chrome_150"), "RequestInput", "request")


def test_a_custom_client_request_uses_only_upstream_fields():
    check(payload(None), "RequestInput", "request")


def test_the_old_singular_cert_compression_field_is_gone_and_translated():
    assert "certCompressionAlgo" not in STRUCTS["CustomTlsClient"]
    assert STRUCTS["CustomTlsClient"]["certCompressionAlgos"] == "[]string"


def test_every_c_function_we_bind_is_exported():
    assert set(_library.BOUND) <= set(SNAPSHOT["exports"])
