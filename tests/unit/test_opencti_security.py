from __future__ import annotations

import socket
from pathlib import Path

import pytest

from cti_trust_gateway.delivery.config import OpenCTIConfig, OpenCTIConfigError
from cti_trust_gateway.delivery.security import (
    OpenCTISecurityError,
    _normalized_host,
    parse_destination,
    resolve_destination,
    sanitize_message,
)

CONNECTOR_ID = "12345678-1234-4234-8234-123456789abc"


def _config(**changes: object) -> OpenCTIConfig:
    values: dict[str, object] = {
        "url": "https://opencti.example.test",
        "import_connector_id": CONNECTOR_ID,
        "host_allowlist": ("opencti.example.test",),
    }
    values.update(changes)
    return OpenCTIConfig.model_validate(values)


def _dns(*addresses: str) -> list[tuple[object, ...]]:
    return [
        (
            socket.AF_INET6 if ":" in address else socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (address, 443),
        )
        for address in addresses
    ]


def test_environment_config_is_strict_and_secret_safe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("synthetic-ca", encoding="utf-8")
    values = {
        "CTI_GATEWAY_OPENCTI_ENABLED": "true",
        "CTI_GATEWAY_OPENCTI_URL": "https://opencti.example.test",
        "CTI_GATEWAY_OPENCTI_TOKEN": "super-secret-token",
        "CTI_GATEWAY_OPENCTI_IMPORT_CONNECTOR_ID": CONNECTOR_ID,
        "CTI_GATEWAY_OPENCTI_HOST_ALLOWLIST": "opencti.example.test,opencti.example.test",
        "CTI_GATEWAY_OPENCTI_CA_BUNDLE": str(ca),
        "CTI_GATEWAY_OPENCTI_MAX_OBJECTS": "12",
        "CTI_GATEWAY_OPENCTI_MAX_BYTES": "2048",
        "CTI_GATEWAY_OPENCTI_POLL_INTERVAL": "0",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    config = OpenCTIConfig.from_env()
    config.validate_nonsecret()
    config.require_execution_secrets()
    assert config.max_objects == 12
    assert config.host_allowlist == ("opencti.example.test",)
    assert "super-secret-token" not in repr(config)
    assert "super-secret-token" not in config.model_dump_json()
    fingerprint = config.fingerprint("https://opencti.example.test")
    assert fingerprint.ca_bundle_sha256
    assert "token" not in fingerprint.model_dump()


@pytest.mark.parametrize(
    ("name", "value", "code"),
    [
        ("CTI_GATEWAY_OPENCTI_ENABLED", "maybe", "OPENCTI_CONFIG_INVALID_BOOLEAN"),
        ("CTI_GATEWAY_OPENCTI_MAX_OBJECTS", "zero", "OPENCTI_CONFIG_INVALID_INTEGER"),
        ("CTI_GATEWAY_OPENCTI_MAX_OBJECTS", "0", "OPENCTI_CONFIG_INVALID_INTEGER"),
    ],
)
def test_invalid_environment_values_fail_closed(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str, code: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(OpenCTIConfigError, match=code):
        OpenCTIConfig.from_env()


def test_nonsecret_and_execution_requirements() -> None:
    with pytest.raises(OpenCTIConfigError, match="OPENCTI_CONFIG_INCOMPLETE"):
        OpenCTIConfig().validate_nonsecret()
    with pytest.raises(OpenCTIConfigError, match="OPENCTI_CONNECTOR_ID_INVALID"):
        _config(import_connector_id="not-a-uuid").validate_nonsecret()
    with pytest.raises(OpenCTIConfigError, match="OPENCTI_HOST_ALLOWLIST_REQUIRED"):
        _config(host_allowlist=()).validate_nonsecret()
    with pytest.raises(OpenCTIConfigError, match="OPENCTI_DELIVERY_DISABLED"):
        _config().require_execution_secrets()
    with pytest.raises(OpenCTIConfigError, match="OPENCTI_TOKEN_UNAVAILABLE"):
        _config(enabled=True).require_execution_secrets()


@pytest.mark.parametrize(
    ("url", "allowlist", "code"),
    [
        ("ftp://opencti.example.test", ("opencti.example.test",), "OPENCTI_URL_INVALID"),
        (
            "https://user:pass@opencti.example.test",
            ("opencti.example.test",),
            "OPENCTI_URL_INVALID",
        ),
        ("https://opencti.example.test/path", ("opencti.example.test",), "OPENCTI_URL_INVALID"),
        (
            "https://opencti.example.test?next=http://127.0.0.1",
            ("opencti.example.test",),
            "OPENCTI_URL_INVALID",
        ),
        ("https://opencti.example.test", ("different.example",), "OPENCTI_HOST_NOT_ALLOWLISTED"),
        ("http://opencti.example.test", ("opencti.example.test",), "OPENCTI_HTTPS_REQUIRED"),
    ],
)
def test_url_syntax_and_allowlist_are_strict(
    url: str, allowlist: tuple[str, ...], code: str
) -> None:
    with pytest.raises((OpenCTISecurityError, OpenCTIConfigError), match=code):
        parse_destination(_config(url=url, host_allowlist=allowlist))


def test_dns_all_answers_are_verified_and_connected_by_vetted_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: _dns("8.8.8.8", "1.1.1.1"))
    target = resolve_destination(_config())
    assert target.addresses == ("1.1.1.1", "8.8.8.8")

    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: _dns("8.8.8.8", "10.0.0.2"))
    with pytest.raises(OpenCTISecurityError, match="OPENCTI_SSRF_BLOCKED"):
        resolve_destination(_config())
    private = resolve_destination(_config(allow_private=True))
    assert private.addresses == ("10.0.0.2", "8.8.8.8")


@pytest.mark.parametrize(
    "address",
    ["169.254.169.254", "224.0.0.1", "0.0.0.0", "203.0.113.8"],  # noqa: S104
)
def test_metadata_multicast_unspecified_and_reserved_are_always_blocked(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: _dns(address))
    with pytest.raises(OpenCTISecurityError, match="OPENCTI_SSRF_BLOCKED"):
        resolve_destination(_config(allow_private=True, allow_loopback=True))


def test_live_delivery_rejects_plaintext_even_for_opted_in_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: _dns("127.0.0.1"))
    config = _config(
        url="http://127.0.0.1:8000",
        host_allowlist=("127.0.0.1",),
        allow_loopback=True,
    )
    with pytest.raises(OpenCTISecurityError, match="OPENCTI_HTTPS_REQUIRED"):
        resolve_destination(config)
    with pytest.raises(OpenCTISecurityError, match="OPENCTI_HTTPS_REQUIRED"):
        parse_destination(config.model_copy(update={"allow_loopback": False}))


def test_dns_failure_and_sanitized_bounded_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise socket.gaierror("synthetic")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(OpenCTISecurityError, match="OPENCTI_DNS_FAILED"):
        resolve_destination(_config())
    message = sanitize_message("Bearer secret.token\x00" + "x" * 1000)
    assert message.startswith("Bearer [REDACTED]")
    assert "secret.token" not in message
    assert "\x00" not in message
    assert len(message) == 500


def test_invalid_idna_ports_empty_dns_and_public_http_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(OpenCTISecurityError, match="OPENCTI_URL_INVALID"):
        _normalized_host("\ud800")
    with pytest.raises(OpenCTISecurityError, match="OPENCTI_URL_INVALID"):
        parse_destination(_config(url="https://opencti.example.test:not-a-port"))
    with pytest.raises(OpenCTISecurityError, match="OPENCTI_URL_INVALID"):
        parse_destination(_config(url="https://opencti.example.test:70000"))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [])
    with pytest.raises(OpenCTISecurityError, match="OPENCTI_DNS_FAILED"):
        resolve_destination(_config())
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: _dns("8.8.8.8"))
    with pytest.raises(OpenCTISecurityError, match="OPENCTI_HTTPS_REQUIRED"):
        resolve_destination(
            _config(
                url="http://opencti.example.test",
                allow_loopback=True,
            )
        )
