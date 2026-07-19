"""Fail-closed loader for the immutable OpenCTI compatibility profile."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from cti_trust_gateway.core.canonical import canonical_sha256
from cti_trust_gateway.domain.models import FrozenDict

PROFILE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "opencti" / "profiles" / "opencti-7.260715.0.yml"
)
OPENCTI_PROFILE_SHA256 = "d3bb230c922ec7fbbc7cc4c915382ac6717de91e59821c8d8215c069979dce3f"


class ProfileUnavailable(RuntimeError):
    pass


class ProfileIntegrityError(RuntimeError):
    pass


class ProfileMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    schema_version: str
    vendor: str
    product: str
    platform_version: str
    pycti_version: str
    opencti_commit: str
    connectors_commit: str
    opencti_repository: str
    connectors_repository: str
    reviewed_on: str
    disclaimer: str
    profile_sha256: str


class ProfileLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    max_objects: int = Field(gt=0, le=10000)
    max_bytes: int = Field(gt=0, le=100 * 1024 * 1024)
    max_dependency_depth: int = Field(gt=0, le=100)


class TypeRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    properties: tuple[str, ...]
    control_only: bool = False


class CustomTypeRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    extension_definition_id: str
    created_by_ref: str
    name: str
    version: str
    extension_type: str
    extension_properties: tuple[str, ...]


class OpenCTIProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    metadata: ProfileMetadata
    limits: ProfileLimits
    common_properties: tuple[str, ...]
    observable_common_properties: tuple[str, ...]
    types: dict[str, TypeRule]
    relationships: dict[str, tuple[str, ...]]
    custom_types: dict[str, CustomTypeRule]
    allowed_extension_definitions: tuple[str, ...]
    tlp_red_ids: tuple[str, ...]

    @field_validator("types", "relationships", "custom_types", mode="after")
    @classmethod
    def _freeze_mappings(cls, value: dict[str, object]) -> dict[str, object]:
        return FrozenDict(value)

    def allowed_properties(self, object_type: str) -> frozenset[str]:
        rule = self.types[object_type]
        properties = set(self.common_properties) | set(rule.properties)
        if object_type in {
            "autonomous-system",
            "domain-name",
            "email-addr",
            "file",
            "ipv4-addr",
            "ipv6-addr",
            "mac-addr",
            "url",
            "windows-registry-key",
        }:
            properties.update(self.observable_common_properties)
        return frozenset(properties)


def _profile_digest(raw: dict[str, object]) -> str:
    normalized = dict(raw)
    metadata_value = normalized.get("metadata")
    if not isinstance(metadata_value, dict):
        raise ProfileIntegrityError("OPENCTI_PROFILE_INTEGRITY")
    metadata = dict(metadata_value)
    metadata.pop("profile_sha256", None)
    normalized["metadata"] = metadata
    return canonical_sha256(normalized)


def load_opencti_profile(path: Path | None = None) -> OpenCTIProfile:
    selected = path or PROFILE_PATH
    if not selected.is_file() or selected.is_symlink():
        raise ProfileUnavailable("OPENCTI_PROFILE_UNAVAILABLE")
    data = selected.read_bytes()
    if len(data) > 256 * 1024:
        raise ProfileIntegrityError("OPENCTI_PROFILE_INTEGRITY")
    try:
        raw = yaml.safe_load(data)
        if not isinstance(raw, dict):
            raise TypeError("profile root must be a mapping")
        profile = OpenCTIProfile.model_validate(raw)
    except (OSError, UnicodeDecodeError, TypeError, yaml.YAMLError, ValidationError) as exc:
        raise ProfileIntegrityError("OPENCTI_PROFILE_INTEGRITY") from exc
    actual = _profile_digest(raw)
    if profile.metadata.profile_sha256 != actual or actual != OPENCTI_PROFILE_SHA256:
        raise ProfileIntegrityError("OPENCTI_PROFILE_INTEGRITY")
    return profile
