"""Environment-only OpenCTI delivery configuration with secret-safe models."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from cti_trust_gateway.core.canonical import canonical_sha256
from cti_trust_gateway.domain.models import DeliveryOptions, DestinationFingerprint

_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class OpenCTIConfigError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _boolean(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    if value.casefold() in {"true", "1", "yes"}:
        return True
    if value.casefold() in {"false", "0", "no"}:
        return False
    raise OpenCTIConfigError("OPENCTI_CONFIG_INVALID_BOOLEAN")


def _integer(name: str, default: int, *, minimum: int, maximum: int) -> int:
    value = os.environ.get(name)
    try:
        parsed = int(value) if value is not None else default
    except ValueError as exc:
        raise OpenCTIConfigError("OPENCTI_CONFIG_INVALID_INTEGER") from exc
    if not minimum <= parsed <= maximum:
        raise OpenCTIConfigError("OPENCTI_CONFIG_INVALID_INTEGER")
    return parsed


def _csv(name: str) -> tuple[str, ...]:
    return tuple(
        sorted({item.strip() for item in os.environ.get(name, "").split(",") if item.strip()})
    )


class OpenCTIConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    enabled: bool = False
    url: str = ""
    token: SecretStr | None = None
    import_connector_id: str = ""
    import_connector_name: str = "ImportFileStix"
    expected_version: str = "7.260715.0"
    host_allowlist: tuple[str, ...] = ()
    ca_bundle: Path | None = None
    allow_private: bool = False
    allow_loopback: bool = False
    max_objects: int = Field(default=1000, gt=0, le=10000)
    max_bytes: int = Field(default=5 * 1024 * 1024, gt=0, le=100 * 1024 * 1024)
    connect_timeout_seconds: int = Field(default=10, gt=0, le=120)
    read_timeout_seconds: int = Field(default=30, gt=0, le=300)
    max_response_bytes: int = Field(default=1024 * 1024, gt=0, le=10 * 1024 * 1024)
    poll_attempts: int = Field(default=10, gt=0, le=100)
    poll_interval_seconds: int = Field(default=2, ge=0, le=60)
    plan_ttl_seconds: int = Field(default=900, gt=0, le=86400)

    @classmethod
    def from_env(cls) -> OpenCTIConfig:
        token_value = os.environ.get("CTI_GATEWAY_OPENCTI_TOKEN")
        ca_value = os.environ.get("CTI_GATEWAY_OPENCTI_CA_BUNDLE")
        return cls(
            enabled=_boolean("CTI_GATEWAY_OPENCTI_ENABLED"),
            url=os.environ.get("CTI_GATEWAY_OPENCTI_URL", "").strip(),
            token=SecretStr(token_value) if token_value else None,
            import_connector_id=os.environ.get(
                "CTI_GATEWAY_OPENCTI_IMPORT_CONNECTOR_ID", ""
            ).strip(),
            import_connector_name=os.environ.get(
                "CTI_GATEWAY_OPENCTI_IMPORT_CONNECTOR_NAME", "ImportFileStix"
            ).strip(),
            expected_version=os.environ.get(
                "CTI_GATEWAY_OPENCTI_EXPECTED_VERSION", "7.260715.0"
            ).strip(),
            host_allowlist=_csv("CTI_GATEWAY_OPENCTI_HOST_ALLOWLIST"),
            ca_bundle=Path(ca_value) if ca_value else None,
            allow_private=_boolean("CTI_GATEWAY_OPENCTI_ALLOW_PRIVATE"),
            allow_loopback=_boolean("CTI_GATEWAY_OPENCTI_ALLOW_LOOPBACK"),
            max_objects=_integer("CTI_GATEWAY_OPENCTI_MAX_OBJECTS", 1000, minimum=1, maximum=10000),
            max_bytes=_integer(
                "CTI_GATEWAY_OPENCTI_MAX_BYTES",
                5 * 1024 * 1024,
                minimum=1,
                maximum=100 * 1024 * 1024,
            ),
            connect_timeout_seconds=_integer(
                "CTI_GATEWAY_OPENCTI_CONNECT_TIMEOUT", 10, minimum=1, maximum=120
            ),
            read_timeout_seconds=_integer(
                "CTI_GATEWAY_OPENCTI_READ_TIMEOUT", 30, minimum=1, maximum=300
            ),
            max_response_bytes=_integer(
                "CTI_GATEWAY_OPENCTI_MAX_RESPONSE_BYTES",
                1024 * 1024,
                minimum=1,
                maximum=10 * 1024 * 1024,
            ),
            poll_attempts=_integer("CTI_GATEWAY_OPENCTI_POLL_ATTEMPTS", 10, minimum=1, maximum=100),
            poll_interval_seconds=_integer(
                "CTI_GATEWAY_OPENCTI_POLL_INTERVAL", 2, minimum=0, maximum=60
            ),
            plan_ttl_seconds=_integer(
                "CTI_GATEWAY_OPENCTI_PLAN_TTL", 900, minimum=1, maximum=86400
            ),
        )

    def validate_nonsecret(self) -> None:
        if (
            not self.url
            or not _VERSION_RE.fullmatch(self.expected_version)
            or not self.import_connector_id
            or not self.import_connector_name
        ):
            raise OpenCTIConfigError("OPENCTI_CONFIG_INCOMPLETE")
        try:
            parsed = UUID(self.import_connector_id)
        except ValueError as exc:
            raise OpenCTIConfigError("OPENCTI_CONNECTOR_ID_INVALID") from exc
        if parsed.version != 4:
            raise OpenCTIConfigError("OPENCTI_CONNECTOR_ID_INVALID")
        if not self.host_allowlist:
            raise OpenCTIConfigError("OPENCTI_HOST_ALLOWLIST_REQUIRED")
        if self.ca_bundle is not None and (
            not self.ca_bundle.is_file() or self.ca_bundle.is_symlink()
        ):
            raise OpenCTIConfigError("OPENCTI_CA_BUNDLE_UNAVAILABLE")
        if self.ca_bundle is not None and self.ca_bundle.stat().st_size > 1024 * 1024:
            raise OpenCTIConfigError("OPENCTI_CA_BUNDLE_TOO_LARGE")

    def require_execution_secrets(self) -> None:
        if not self.enabled:
            raise OpenCTIConfigError("OPENCTI_DELIVERY_DISABLED")
        if self.token is None or self.token.get_secret_value() in {"", "ChangeMe"}:
            raise OpenCTIConfigError("OPENCTI_TOKEN_UNAVAILABLE")

    def fingerprint(self, normalized_origin: str) -> DestinationFingerprint:
        self.validate_nonsecret()
        ca_bytes = self.read_ca_bundle()
        ca_digest = hashlib.sha256(ca_bytes).hexdigest() if ca_bytes is not None else None
        return DestinationFingerprint(
            origin=normalized_origin,
            expected_version=self.expected_version,
            import_connector_id=self.import_connector_id,
            import_connector_name=self.import_connector_name,
            allowlist_sha256=canonical_sha256(self.host_allowlist),
            ca_bundle_sha256=ca_digest,
        )

    def read_ca_bundle(self) -> bytes | None:
        """Read a bounded, regular CA bundle for a connection trust snapshot."""
        if self.ca_bundle is None:
            return None
        if not self.ca_bundle.is_file() or self.ca_bundle.is_symlink():
            raise OpenCTIConfigError("OPENCTI_CA_BUNDLE_UNAVAILABLE")
        try:
            value = self.ca_bundle.read_bytes()
        except OSError as exc:
            raise OpenCTIConfigError("OPENCTI_CA_BUNDLE_UNAVAILABLE") from exc
        if len(value) > 1024 * 1024:
            raise OpenCTIConfigError("OPENCTI_CA_BUNDLE_TOO_LARGE")
        return value

    def delivery_options(self) -> DeliveryOptions:
        return DeliveryOptions(
            allow_private=self.allow_private,
            allow_loopback=self.allow_loopback,
            max_objects=self.max_objects,
            max_bytes=self.max_bytes,
            connect_timeout_seconds=self.connect_timeout_seconds,
            read_timeout_seconds=self.read_timeout_seconds,
            max_response_bytes=self.max_response_bytes,
            poll_attempts=self.poll_attempts,
            poll_interval_seconds=self.poll_interval_seconds,
            plan_ttl_seconds=self.plan_ttl_seconds,
        )
