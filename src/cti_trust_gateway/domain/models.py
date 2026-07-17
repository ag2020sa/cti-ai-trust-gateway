"""Typed domain objects shared by every gateway boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


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
