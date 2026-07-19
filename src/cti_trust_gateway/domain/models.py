"""Typed domain objects shared by every gateway boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FrozenDict(dict[str, Any]):
    """JSON-serializable mapping that rejects mutation after construction."""

    def _immutable(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FROZEN_MAPPING")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable  # type: ignore[assignment]
    setdefault = _immutable
    update = _immutable


def utc_now() -> datetime:
    return datetime.now(UTC)


class Verdict(StrEnum):
    PASS = "PASS"
    REVIEW = "REVIEW"
    REJECT = "REJECT"
    QUARANTINE = "QUARANTINE"
    ABSTAIN = "ABSTAIN"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(StrEnum):
    DOCUMENT_SECURITY = "document_security"
    STIX_STRUCTURE = "stix_structure"
    OBSERVABLE_INTEGRITY = "observable_integrity"
    ATTACK_MAPPING = "attack_mapping"
    ENTITY_GROUNDING = "entity_grounding"
    RELATIONSHIP_GROUNDING = "relationship_grounding"
    CONFIDENCE_CALIBRATION = "confidence_calibration"
    BILINGUAL_CONSISTENCY = "bilingual_consistency"
    POLICY_VIOLATION = "policy_violation"
    VALIDATION_CAPABILITY = "validation_capability"


class ValidationStatus(StrEnum):
    EXECUTED = "EXECUTED"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class DeliveryStatus(StrEnum):
    PREPARED = "PREPARED"
    BLOCKED = "BLOCKED"
    SUBMITTED = "SUBMITTED"
    PROCESSING = "PROCESSING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    NOOP = "NOOP"


class ValidationCapability(BaseModel):
    """Evidence that a mandatory validator actually ran with identified inputs."""

    model_config = ConfigDict(extra="forbid")
    name: str
    version: str
    stix_version: str = "2.1"
    schema_source: str
    schema_version: str
    schema_sha256: str | None = None
    status: ValidationStatus
    mandatory: bool = True
    errors: list[str] = Field(default_factory=list)


class EvidenceSpan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document_id: str
    page: int | None = None
    start: int
    end: int
    text: str
    match_type: Literal["exact", "case_insensitive", "normalized", "fuzzy", "near_match"]
    suspicious: bool = False


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    rule_id: str
    category: FindingCategory
    severity: Severity
    title: str
    explanation: str
    recommended_action: str
    claim_id: str | None = None
    object_ids: list[str] = Field(default_factory=list)
    page: int | None = None
    evidence: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SourceDocument(BaseModel):
    id: str
    filename: str
    media_type: str
    sha256: str
    size_bytes: int
    language: Literal["en", "ar", "mixed", "unknown"]
    text: str
    pages: list[str]
    page_offsets: list[tuple[int, int]]
    metadata: dict[str, Any] = Field(default_factory=dict)


class CandidateBundle(BaseModel):
    id: str
    raw: dict[str, Any]
    object_count: int
    is_valid: bool
    validation: ValidationCapability


class Claim(BaseModel):
    id: str
    kind: Literal["observable", "entity", "relationship", "attack", "vulnerability", "confidence"]
    statement: str
    value: str | None = None
    value_type: str | None = None
    reference_name: str | None = None
    source_entity: str | None = None
    target_entity: str | None = None
    relationship_type: str | None = None
    object_ids: list[str]
    deterministic: bool = True
    evidence: list[EvidenceSpan] = Field(default_factory=list)
    status: Literal["SUPPORTED", "CONTRADICTED", "PARTIAL", "NOT_FOUND", "UNKNOWN"] = "UNKNOWN"


class PolicyEvaluation(BaseModel):
    policy_name: str
    fired_rules: list[str]
    reasons: list[str]
    review_finding_ids: list[str]
    verdict: Verdict


class ReviewDecision(BaseModel):
    id: str
    case_id: str
    finding_id: str | None = None
    object_id: str | None = None
    action: Literal["accept", "edit", "reject"]
    comment: str = ""
    edited_value: str | None = None
    analyst: str = "local-analyst"
    analysis_snapshot_sha256: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class AuditEvent(BaseModel):
    id: str
    case_id: str
    event_type: str
    actor: str
    timestamp: datetime = Field(default_factory=utc_now)
    payload: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str | None = None
    event_hash: str


class AnalysisCase(BaseModel):
    id: str
    created_at: datetime = Field(default_factory=utc_now)
    source: SourceDocument
    candidate: CandidateBundle
    claims: list[Claim]
    findings: list[Finding]
    policy: PolicyEvaluation
    verdict: Verdict
    evidence_coverage: float
    metadata: dict[str, Any] = Field(default_factory=dict)
    reviews: list[ReviewDecision] = Field(default_factory=list)
    audit: list[AuditEvent] = Field(default_factory=list)


class EvidenceManifest(BaseModel):
    schema_version: str = "1.0"
    case_id: str
    source_sha256: str
    candidate_sha256: str
    verdict: Verdict
    generated_at: datetime = Field(default_factory=utc_now)
    evidence_coverage: float
    claims: list[Claim]
    findings: list[Finding]
    policy: PolicyEvaluation
    validation: ValidationCapability
    disclaimer: str = "Verified only against the supplied source document."


class ExportResult(BaseModel):
    case_id: str
    exported_object_ids: list[str]
    excluded_object_ids: list[str]
    bundle: dict[str, Any]
    artifact_paths: dict[str, str] = Field(default_factory=dict)


class CompatibilityFinding(BaseModel):
    """Stable, machine-readable OpenCTI compatibility result."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    code: str
    message: str
    severity: Severity = Severity.HIGH
    object_id: str | None = None
    property_name: str | None = None
    dependency_id: str | None = None


class CompatibilityReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    profile_id: str
    profile_sha256: str
    compatible: bool
    checked_object_ids: tuple[str, ...]
    findings: tuple[CompatibilityFinding, ...] = ()


class DeliveryGates(BaseModel):
    """Four independent authorities required before any live delivery."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    valid_stix: bool
    opencti_compatible: bool
    evidence_verified: bool
    delivery_authorized: bool
    reasons: tuple[str, ...] = ()


class ApprovedArtifact(BaseModel):
    """Immutable, exact delivery bytes derived from one persisted review snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    case_id: str
    source_sha256: str
    candidate_sha256: str
    validation_sha256: str
    policy_sha256: str
    review_snapshot_sha256: str
    profile_id: str
    profile_sha256: str
    artifact_sha256: str
    graph_sha256: str
    size_bytes: int
    canonical_bundle: str
    included_object_ids: tuple[str, ...]
    excluded_object_ids: tuple[str, ...]
    exclusion_reasons: dict[str, tuple[str, ...]]
    marking_ids: tuple[str, ...]
    generated_report_id: str
    compatibility: CompatibilityReport
    gates: DeliveryGates

    @field_validator("exclusion_reasons", mode="after")
    @classmethod
    def _freeze_exclusion_reasons(
        cls, value: dict[str, tuple[str, ...]]
    ) -> dict[str, tuple[str, ...]]:
        return FrozenDict(value)

    def bundle_bytes(self) -> bytes:
        return self.canonical_bundle.encode("utf-8")


class DestinationFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["opencti-draft"] = "opencti-draft"
    origin: str
    expected_version: str
    import_connector_id: str
    import_connector_name: str
    allowlist_sha256: str
    ca_bundle_sha256: str | None = None


class DeliveryOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    allow_private: bool
    allow_loopback: bool
    max_objects: int
    max_bytes: int
    connect_timeout_seconds: int
    read_timeout_seconds: int
    max_response_bytes: int
    poll_attempts: int
    poll_interval_seconds: int
    plan_ttl_seconds: int


class DestinationCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    origin: str
    platform_version: str
    connector_id: str
    connector_name: str
    connector_type: str
    connector_scope: tuple[str, ...]
    connector_active: bool
    marking_id_map: dict[str, str]
    fingerprint_sha256: str
    probed_at: datetime = Field(default_factory=utc_now)

    @field_validator("marking_id_map", mode="after")
    @classmethod
    def _freeze_markings(cls, value: dict[str, str]) -> dict[str, str]:
        return FrozenDict(value)


class DeliveryOperation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    ordinal: int
    kind: Literal["create-draft", "upload-bundle", "poll-work"]
    request_sha256: str
    description: str


class DeliveryPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    logical_key: str
    case_id: str
    mode: Literal["opencti-draft"] = "opencti-draft"
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    source_sha256: str
    candidate_sha256: str
    validation_sha256: str
    policy_sha256: str
    review_snapshot_sha256: str
    profile_id: str
    profile_sha256: str
    artifact_id: str
    artifact_sha256: str
    graph_sha256: str
    artifact_size_bytes: int
    included_object_ids: tuple[str, ...]
    excluded_object_ids: tuple[str, ...]
    exclusion_reasons: dict[str, tuple[str, ...]]
    marking_ids: tuple[str, ...]
    destination: DestinationFingerprint
    options: DeliveryOptions
    operations: tuple[DeliveryOperation, ...]
    blockers: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    status: DeliveryStatus
    plan_sha256: str
    gates: DeliveryGates

    @field_validator("exclusion_reasons", mode="after")
    @classmethod
    def _freeze_plan_exclusion_reasons(
        cls, value: dict[str, tuple[str, ...]]
    ) -> dict[str, tuple[str, ...]]:
        return FrozenDict(value)


class DeliveryAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    plan_id: str
    status: DeliveryStatus
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    draft_id: str | None = None
    remote_file_id: str | None = None
    work_id: str | None = None
    message: str = ""


class DeliveryReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    plan_id: str
    attempt_id: str
    status: DeliveryStatus
    draft_id: str | None = None
    remote_file_id: str | None = None
    work_id: str | None = None
    message: str = ""
