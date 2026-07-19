"""Single auditable orchestration path used by API, CLI, and tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from cti_trust_gateway.core.canonical import canonical_bytes, normalize_stix, sha256_bytes
from cti_trust_gateway.core.claims import extract_claims
from cti_trust_gateway.core.snapshots import analysis_snapshot_sha256
from cti_trust_gateway.domain.models import (
    AnalysisCase,
    EvidenceManifest,
    Finding,
    FindingCategory,
    Severity,
    ValidationStatus,
)
from cti_trust_gateway.evidence.engine import (
    bilingual_consistency_findings,
    evidence_coverage,
    verify_claims,
)
from cti_trust_gateway.parsers.document import parse_document
from cti_trust_gateway.policies.engine import evaluate_policy, load_policy
from cti_trust_gateway.providers.semantic import (
    DeterministicSemanticVerifier,
    SemanticProviderError,
    SemanticVerifierProvider,
)
from cti_trust_gateway.scanners.document_security import scan_document
from cti_trust_gateway.storage.repository import Repository
from cti_trust_gateway.validators.stix import parse_candidate, validate_candidate


class GatewayService:
    def __init__(
        self,
        repository: Repository,
        *,
        default_policy: Path,
        semantic_provider: SemanticVerifierProvider | None = None,
        max_upload_size: int = 10 * 1024 * 1024,
    ) -> None:
        self.repository = repository
        self.default_policy = default_policy
        self.semantic_provider = semantic_provider or DeterministicSemanticVerifier()
        self.max_upload_size = max_upload_size

    def analyze(
        self,
        source_data: bytes,
        source_filename: str,
        candidate_data: bytes | str | dict[str, Any],
        *,
        source_metadata: dict[str, Any] | None = None,
        tlp: str | None = None,
        policy_path: Path | None = None,
    ) -> AnalysisCase:
        if isinstance(candidate_data, bytes) and len(candidate_data) > self.max_upload_size:
            raise ValueError(f"Candidate exceeds the {self.max_upload_size}-byte upload limit")
        if (
            isinstance(candidate_data, str)
            and len(candidate_data.encode("utf-8")) > self.max_upload_size
        ):
            raise ValueError(f"Candidate exceeds the {self.max_upload_size}-byte upload limit")
        if isinstance(candidate_data, dict):
            candidate_size = len(json.dumps(candidate_data, ensure_ascii=False).encode("utf-8"))
            if candidate_size > self.max_upload_size:
                raise ValueError(f"Candidate exceeds the {self.max_upload_size}-byte upload limit")
        source = parse_document(
            source_data,
            source_filename,
            max_size=self.max_upload_size,
            source_metadata=source_metadata,
        )
        raw = parse_candidate(candidate_data)
        candidate, stix_findings = validate_candidate(raw)
        if candidate.validation.status == ValidationStatus.SKIPPED:
            candidate.is_valid = False
            stix_findings.append(
                Finding(
                    id=f"finding--{uuid4()}",
                    rule_id="STIX-VALIDATION-SKIPPED",
                    category=FindingCategory.VALIDATION_CAPABILITY,
                    severity=Severity.HIGH,
                    title="Mandatory STIX validation was skipped",
                    explanation="A mandatory validation capability did not execute.",
                    recommended_action="Restore validation and rerun the complete analysis.",
                )
            )
        claims = extract_claims(raw)
        findings = scan_document(source) + stix_findings + verify_claims(source, claims)
        findings.extend(bilingual_consistency_findings(source, claims))
        findings.extend(self._semantic_findings(source, claims, findings))
        if (
            tlp
            and tlp.upper() == "TLP:RED"
            and source_metadata
            and source_metadata.get("export_requested")
        ):
            findings.append(
                Finding(
                    id=f"finding--{uuid4()}",
                    rule_id="POLICY-TLP-001",
                    category=FindingCategory.POLICY_VIOLATION,
                    severity=Severity.HIGH,
                    title="TLP handling conflict",
                    explanation="Export was requested for TLP:RED material.",
                    recommended_action="Keep the case in the restricted local handling boundary.",
                )
            )
        selected_policy = policy_path or self.default_policy
        policy = evaluate_policy(findings, load_policy(selected_policy))
        if (
            candidate.validation.status != ValidationStatus.EXECUTED
            and policy.verdict.value == "PASS"
        ):
            raise RuntimeError("Invariant violation: PASS without executed mandatory validation")
        candidate_input = (
            candidate_data
            if isinstance(candidate_data, bytes)
            else candidate_data.encode("utf-8")
            if isinstance(candidate_data, str)
            else canonical_bytes(candidate_data)
        )
        case = AnalysisCase(
            id=f"case--{uuid4()}",
            source=source,
            candidate=candidate,
            claims=claims,
            findings=findings,
            policy=policy,
            verdict=policy.verdict,
            evidence_coverage=evidence_coverage(claims),
            metadata={
                "tlp": tlp,
                "candidate_raw_sha256": sha256_bytes(candidate_input),
                "candidate_sha256": sha256_bytes(canonical_bytes(normalize_stix(raw))),
                "candidate_canonical_sha256": sha256_bytes(canonical_bytes(normalize_stix(raw))),
                "policy_sha256": hashlib.sha256(selected_policy.read_bytes()).hexdigest(),
            },
        )
        case.metadata["analysis_snapshot_sha256"] = analysis_snapshot_sha256(case)
        case.audit.append(
            self.repository.make_event(
                case,
                "case.analyzed",
                "gateway",
                {
                    "verdict": case.verdict.value,
                    "source_sha256": source.sha256,
                    "analysis_snapshot_sha256": case.metadata["analysis_snapshot_sha256"],
                },
            )
        )
        self.repository.save(case)
        return case

    def _semantic_findings(
        self,
        source: Any,
        claims: list[Any],
        existing: list[Finding],
    ) -> list[Finding]:
        output: list[Finding] = []
        relationship_findings = {
            finding.claim_id: finding
            for finding in existing
            if finding.rule_id == "EVIDENCE-REL-001"
        }
        for claim in claims:
            if claim.kind != "relationship":
                continue
            try:
                result = self.semantic_provider.verify(source, claim)
            except SemanticProviderError as exc:
                base = relationship_findings.get(claim.id)
                if base in existing:
                    existing.remove(base)
                claim.status = "UNKNOWN"
                output.append(
                    Finding(
                        id=f"finding--{uuid4()}",
                        rule_id="SEMANTIC-ERROR",
                        category=FindingCategory.RELATIONSHIP_GROUNDING,
                        severity=Severity.MEDIUM,
                        title="Semantic verifier failed",
                        explanation=str(exc),
                        recommended_action="Abstain and retry locally; do not authorize export.",
                        claim_id=claim.id,
                        object_ids=claim.object_ids,
                    )
                )
                continue
            if result is None:
                continue
            claim.status = result.status
            base = relationship_findings.get(claim.id)
            if result.status == "SUPPORTED" and base in existing:
                existing.remove(base)
                continue
            rule = f"SEMANTIC-{result.status}"
            severity = Severity.HIGH if result.status == "CONTRADICTED" else Severity.MEDIUM
            output.append(
                Finding(
                    id=f"finding--{uuid4()}",
                    rule_id=rule,
                    category=FindingCategory.RELATIONSHIP_GROUNDING,
                    severity=severity,
                    title=f"Semantic verifier returned {result.status}",
                    explanation=result.rationale,
                    recommended_action="Reject contradictions; review partial or missing support.",
                    claim_id=claim.id,
                    object_ids=claim.object_ids,
                    metadata={"evidence_span_refs": result.evidence_span_refs},
                )
            )
        return output

    @staticmethod
    def manifest(case: AnalysisCase) -> EvidenceManifest:
        return EvidenceManifest(
            case_id=case.id,
            source_sha256=case.source.sha256,
            candidate_sha256=str(case.metadata["candidate_sha256"]),
            verdict=case.verdict,
            evidence_coverage=case.evidence_coverage,
            claims=case.claims,
            findings=case.findings,
            policy=case.policy,
            validation=case.candidate.validation,
        )
