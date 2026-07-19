"""Build immutable approved-only bytes from a persisted analysis snapshot."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from cti_trust_gateway.compatibility.checker import (
    check_opencti_compatibility,
    object_references,
)
from cti_trust_gateway.compatibility.profile import OpenCTIProfile
from cti_trust_gateway.core.canonical import (
    canonical_bytes,
    canonical_sha256,
    normalize_stix,
    sha256_bytes,
)
from cti_trust_gateway.core.snapshots import analysis_snapshot_sha256, review_snapshot_sha256
from cti_trust_gateway.domain.models import (
    AnalysisCase,
    ApprovedArtifact,
    CompatibilityReport,
    DeliveryGates,
    ValidationStatus,
    Verdict,
)
from cti_trust_gateway.storage.repository import Repository
from cti_trust_gateway.validators.stix import SCHEMA_SHA256

CONTROL_TYPES = {"marking-definition", "extension-definition"}
HARD_SEVERITIES = {"high", "critical"}
ADMINISTRATIVE_PROPERTIES = {
    "type",
    "spec_version",
    "id",
    "created_by_ref",
    "created",
    "modified",
    "revoked",
    "lang",
    "object_marking_refs",
    "granular_markings",
}
MODELED_ASSERTION_PROPERTIES: dict[str, set[str]] = {
    "attack-pattern": {"name", "x_mitre_id"},
    "identity": {"name", "identity_class", "sectors", "roles"},
    "location": {"name", "country", "region", "x_opencti_location_type"},
    "intrusion-set": {"name"},
    "malware": {"name", "malware_types", "is_family"},
    "vulnerability": {"name"},
    "tool": {"name", "tool_types", "tool_version"},
    "channel": {"name", "channel_types", "extensions"},
    "relationship": {"relationship_type", "source_ref", "target_ref", "start_time", "stop_time"},
    "autonomous-system": {"number", "name", "rir"},
    "domain-name": {"value", "resolves_to_refs"},
    "email-addr": {"value", "display_name", "belongs_to_ref"},
    "file": {
        "hashes",
        "size",
        "name",
        "name_enc",
        "magic_number",
        "mime_type",
        "ctime",
        "mtime",
        "atime",
        "parent_directory_ref",
        "contains_refs",
        "content_ref",
    },
    "ipv4-addr": {"value", "resolves_to_refs", "belongs_to_refs"},
    "ipv6-addr": {"value", "resolves_to_refs", "belongs_to_refs"},
    "mac-addr": {"value"},
    "url": {"value"},
    "windows-registry-key": {"key", "values", "modified", "creator_user_ref", "number_of_subkeys"},
}


@dataclass(frozen=True)
class ArtifactAssessment:
    case_id: str
    artifact: ApprovedArtifact | None
    compatibility: CompatibilityReport
    blockers: tuple[str, ...]
    excluded_object_ids: tuple[str, ...]
    exclusion_reasons: dict[str, tuple[str, ...]]
    review_snapshot_sha256: str
    gates: DeliveryGates


def _span_integrity(case: AnalysisCase) -> bool:
    text = case.source.text
    for claim in case.claims:
        for span in claim.evidence:
            if span.document_id != case.source.id:
                return False
            if not (0 <= span.start < span.end <= len(text)):
                return False
            if text[span.start : span.end] != span.text:
                return False
            expected_page: int | None = None
            for index, (start, end) in enumerate(case.source.page_offsets):
                if start <= span.start <= end:
                    expected_page = index + 1
                    break
            if span.page != expected_page:
                return False
    return True


def _gateway_report(
    case: AnalysisCase,
    object_refs: list[str],
    marking_ids: list[str],
    snapshot_sha256: str,
    approved_graph_sha256: str,
    profile: OpenCTIProfile,
) -> dict[str, Any]:
    stable_name = "|".join(
        (
            str(case.metadata.get("candidate_sha256", "")),
            snapshot_sha256,
            profile.metadata.profile_sha256,
        )
    )
    report_id = f"report--{uuid5(NAMESPACE_URL, stable_name)}"
    timestamp = "2026-01-01T00:00:00Z"
    report: dict[str, Any] = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": timestamp,
        "modified": timestamp,
        "published": timestamp,
        "name": "CTI Trust Gateway approved-source provenance",
        "description": (
            "Gateway provenance only. Verified against the supplied source snapshot; this is not "
            "a claim of global truth. OpenCTI Draft requires separate manual approval. "
            f"verdict={case.verdict.value}; evidence_coverage={case.evidence_coverage:.4f}; "
            f"source_sha256={case.source.sha256}; "
            f"candidate_sha256={case.metadata.get('candidate_sha256', '')}; "
            f"review_snapshot_sha256={snapshot_sha256}; "
            f"approved_graph_sha256={approved_graph_sha256}."
        ),
        "report_types": ["threat-report"],
        "object_refs": object_refs,
    }
    if marking_ids:
        report["object_marking_refs"] = marking_ids
    return report


class ApprovedArtifactBuilder:
    def __init__(self, repository: Repository, profile: OpenCTIProfile) -> None:
        self.repository = repository
        self.profile = profile

    def build(self, case_id: str) -> ArtifactAssessment:
        case = self.repository.get(case_id)
        if case is None:
            raise KeyError(case_id)
        objects = [obj for obj in case.candidate.raw.get("objects", []) if isinstance(obj, dict)]
        by_id: dict[str, dict[str, Any]] = {}
        duplicate_conflicts: set[str] = set()
        for obj in objects:
            object_id = obj.get("id")
            if not isinstance(object_id, str):
                continue
            if object_id in by_id and canonical_bytes(by_id[object_id]) != canonical_bytes(obj):
                duplicate_conflicts.add(object_id)
                continue
            by_id.setdefault(object_id, obj)
        full_compatibility = check_opencti_compatibility(objects, self.profile)
        snapshot_sha256 = review_snapshot_sha256(case)
        blockers = self._snapshot_blockers(case)
        if duplicate_conflicts:
            blockers.append("OPENCTI_DUPLICATE_ID_CONFLICT")
        reasons: dict[str, list[str]] = {object_id: [] for object_id in by_id}

        for compatibility_finding in full_compatibility.findings:
            if compatibility_finding.object_id in reasons:
                reasons[compatibility_finding.object_id].append(compatibility_finding.code)
            elif compatibility_finding.object_id is None:
                blockers.append(compatibility_finding.code)

        hard_objects: set[str] = set()
        for case_finding in case.findings:
            if case_finding.severity.value not in HARD_SEVERITIES:
                continue
            if not case_finding.object_ids:
                blockers.append("HARD_SECURITY_FINDING")
            hard_objects.update(
                object_id for object_id in case_finding.object_ids if object_id in by_id
            )
        for object_id in hard_objects:
            reasons[object_id].append("HARD_FINDING_NON_OVERRIDABLE")

        decisions: dict[str, str] = {}
        for review in case.reviews:
            if review.object_id:
                decisions[review.object_id] = review.action
        claims_by_owner: dict[str, list[str]] = {object_id: [] for object_id in by_id}
        for claim in case.claims:
            owned_ids = claim.object_ids[:1] if claim.kind == "relationship" else claim.object_ids
            for object_id in owned_ids:
                if object_id in claims_by_owner:
                    claims_by_owner[object_id].append(claim.status)

        selected: set[str] = set()
        for object_id, obj in by_id.items():
            if reasons[object_id]:
                continue
            if decisions.get(object_id) == "reject":
                reasons[object_id].append("ANALYST_REJECTED")
                continue
            if str(obj.get("type")) in CONTROL_TYPES:
                continue
            object_type = str(obj.get("type"))
            if object_type == "report":
                reasons[object_id].append("CANDIDATE_REPORT_REWRITTEN")
                continue
            allowed_assertions = MODELED_ASSERTION_PROPERTIES.get(object_type, set())
            unmodeled = set(obj) - ADMINISTRATIVE_PROPERTIES - allowed_assertions
            if unmodeled:
                reasons[object_id].append("UNMODELED_ASSERTION_PROPERTY")
                continue
            statuses = claims_by_owner[object_id]
            if case.verdict == Verdict.PASS:
                if statuses and all(status == "SUPPORTED" for status in statuses):
                    selected.add(object_id)
                else:
                    reasons[object_id].append(
                        "NO_MODELED_ASSERTION" if not statuses else "MIXED_OR_UNSUPPORTED_CLAIMS"
                    )
            elif case.verdict in {Verdict.REVIEW, Verdict.ABSTAIN}:
                fully_supported = statuses and all(status == "SUPPORTED" for status in statuses)
                wholly_reviewable = statuses and all(
                    status in {"UNKNOWN", "PARTIAL", "NOT_FOUND"} for status in statuses
                )
                if fully_supported or (decisions.get(object_id) == "accept" and wholly_reviewable):
                    selected.add(object_id)
                else:
                    reasons[object_id].append(
                        "EXPLICIT_ACCEPTANCE_REQUIRED"
                        if decisions.get(object_id) != "accept"
                        else "MIXED_OR_UNSUPPORTED_CLAIMS"
                    )
            else:
                reasons[object_id].append("VERDICT_BLOCKED")

        self._close_dependencies(selected, by_id, reasons)
        approved_refs = sorted(
            object_id
            for object_id in selected
            if str(by_id[object_id].get("type")) not in CONTROL_TYPES
        )
        if not approved_refs:
            blockers.append("OPENCTI_EMPTY_APPROVED_SET")

        marking_ids = sorted(
            {
                ref
                for object_id in selected
                for ref in by_id[object_id].get("object_marking_refs", [])
                if isinstance(ref, str)
            }
        )
        graph_sha256 = canonical_sha256(
            {
                object_id: sorted(object_references(obj))
                for object_id, obj in sorted(by_id.items())
                if object_id in selected
            }
        )
        report = _gateway_report(
            case,
            approved_refs,
            marking_ids,
            snapshot_sha256,
            graph_sha256,
            self.profile,
        )
        artifact_objects = [normalize_stix(by_id[object_id]) for object_id in sorted(selected)]
        if approved_refs:
            artifact_objects.append(report)
        selected_compatibility = check_opencti_compatibility(artifact_objects, self.profile)
        if not selected_compatibility.compatible:
            blockers.extend(finding.code for finding in selected_compatibility.findings)

        exclusions = {
            object_id: tuple(sorted(set(values or ["NOT_APPROVED"])))
            for object_id, values in reasons.items()
            if object_id not in selected
        }
        blocker_tuple = tuple(sorted(set(blockers)))
        gates = DeliveryGates(
            valid_stix=(
                case.candidate.is_valid
                and case.candidate.validation.status == ValidationStatus.EXECUTED
                and case.candidate.validation.schema_sha256 == SCHEMA_SHA256
            ),
            opencti_compatible=selected_compatibility.compatible,
            evidence_verified=bool(approved_refs),
            delivery_authorized=not blocker_tuple,
            reasons=blocker_tuple,
        )
        if blocker_tuple:
            return ArtifactAssessment(
                case_id=case.id,
                artifact=None,
                compatibility=full_compatibility,
                blockers=blocker_tuple,
                excluded_object_ids=tuple(sorted(exclusions)),
                exclusion_reasons=exclusions,
                review_snapshot_sha256=snapshot_sha256,
                gates=gates,
            )

        bundle = normalize_stix(
            {"type": "bundle", "id": case.candidate.id, "objects": artifact_objects}
        )
        bundle_bytes = canonical_bytes(bundle)
        artifact_sha256 = sha256_bytes(bundle_bytes)
        artifact = ApprovedArtifact(
            id=f"artifact--{artifact_sha256}",
            case_id=case.id,
            source_sha256=case.source.sha256,
            candidate_sha256=str(case.metadata["candidate_sha256"]),
            validation_sha256=str(case.candidate.validation.schema_sha256),
            policy_sha256=str(case.metadata["policy_sha256"]),
            review_snapshot_sha256=snapshot_sha256,
            profile_id=self.profile.metadata.id,
            profile_sha256=self.profile.metadata.profile_sha256,
            artifact_sha256=artifact_sha256,
            graph_sha256=graph_sha256,
            size_bytes=len(bundle_bytes),
            canonical_bundle=bundle_bytes.decode("utf-8"),
            included_object_ids=tuple([*sorted(selected), str(report["id"])]),
            excluded_object_ids=tuple(sorted(exclusions)),
            exclusion_reasons=exclusions,
            marking_ids=tuple(marking_ids),
            generated_report_id=str(report["id"]),
            compatibility=selected_compatibility,
            gates=gates,
        )
        return ArtifactAssessment(
            case_id=case.id,
            artifact=artifact,
            compatibility=full_compatibility,
            blockers=(),
            excluded_object_ids=artifact.excluded_object_ids,
            exclusion_reasons=exclusions,
            review_snapshot_sha256=snapshot_sha256,
            gates=gates,
        )

    def _snapshot_blockers(self, case: AnalysisCase) -> list[str]:
        blockers: list[str] = []
        if case.verdict in {Verdict.REJECT, Verdict.QUARANTINE}:
            blockers.append("VERDICT_BLOCKED")
        if (
            not case.candidate.is_valid
            or case.candidate.validation.status != ValidationStatus.EXECUTED
        ):
            blockers.append("STIX_VALIDATION_NOT_EXECUTED")
        if case.candidate.validation.schema_sha256 != SCHEMA_SHA256:
            blockers.append("STIX_VALIDATION_INTEGRITY")
        if not self.repository.verify_audit_chain(case):
            blockers.append("AUDIT_INTEGRITY_FAILURE")
        if not _span_integrity(case):
            blockers.append("EVIDENCE_SPAN_INTEGRITY")
        expected_candidate = case.metadata.get("candidate_canonical_sha256")
        if expected_candidate != canonical_sha256(normalize_stix(case.candidate.raw)):
            blockers.append("CANDIDATE_INTEGRITY_FAILURE")
        if not isinstance(case.metadata.get("policy_sha256"), str):
            blockers.append("POLICY_INTEGRITY_FAILURE")
        expected_analysis = case.metadata.get("analysis_snapshot_sha256")
        if expected_analysis != analysis_snapshot_sha256(case):
            blockers.append("ANALYSIS_SNAPSHOT_INTEGRITY_FAILURE")
        if (
            not case.audit
            or case.audit[0].event_type != "case.analyzed"
            or case.audit[0].payload.get("analysis_snapshot_sha256") != expected_analysis
        ):
            blockers.append("ANALYSIS_SNAPSHOT_INTEGRITY_FAILURE")
        if any(review.case_id != case.id for review in case.reviews):
            blockers.append("REVIEW_SNAPSHOT_MISMATCH")
        if any(review.analysis_snapshot_sha256 != expected_analysis for review in case.reviews):
            blockers.append("REVIEW_SNAPSHOT_MISMATCH")
        return blockers

    @staticmethod
    def _close_dependencies(
        selected: set[str],
        by_id: dict[str, dict[str, Any]],
        reasons: dict[str, list[str]],
    ) -> None:
        changed = True
        while changed:
            changed = False
            for object_id in sorted(tuple(selected)):
                obj = by_id[object_id]
                dependencies = object_references(obj)
                missing = [dependency for dependency in dependencies if dependency not in by_id]
                if missing:
                    selected.remove(object_id)
                    reasons[object_id].append("MISSING_DEPENDENCY")
                    changed = True
                    continue
                blocked = []
                for dependency in sorted(dependencies):
                    dependency_type = str(by_id[dependency].get("type"))
                    if dependency_type in CONTROL_TYPES and not reasons[dependency]:
                        if dependency not in selected:
                            selected.add(dependency)
                            changed = True
                    elif dependency not in selected:
                        blocked.append(dependency)
                if blocked and object_id in selected:
                    selected.remove(object_id)
                    reasons[object_id].append("UNAPPROVED_DEPENDENCY")
                    changed = True
