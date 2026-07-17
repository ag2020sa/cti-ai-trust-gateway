"""Evidence-scoped STIX and JSON artifact export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cti_trust_gateway.core.service import GatewayService
from cti_trust_gateway.domain.models import AnalysisCase, ExportResult, ValidationStatus, Verdict


def build_export(case: AnalysisCase) -> ExportResult:
    objects = case.candidate.raw.get("objects", [])
    by_id = {
        candidate_id: obj
        for obj in objects
        if isinstance(obj, dict) and isinstance((candidate_id := obj.get("id")), str)
    }
    if (
        case.verdict in {Verdict.REJECT, Verdict.QUARANTINE}
        or not case.candidate.is_valid
        or case.candidate.validation.status != ValidationStatus.EXECUTED
    ):
        return ExportResult(
            case_id=case.id,
            exported_object_ids=[],
            excluded_object_ids=list(by_id),
            bundle={
                "type": "bundle",
                "id": case.candidate.id,
                "objects": [],
                "x_cti_gateway_disclaimer": (
                    "Export blocked by verdict or mandatory validation state."
                ),
            },
        )

    decisions = {review.object_id: review.action for review in case.reviews if review.object_id}
    rejected_by_finding = {
        object_id
        for finding in case.findings
        if finding.severity.value in {"high", "critical"}
        for object_id in finding.object_ids
    }
    approved: set[str] = set()
    for claim in case.claims:
        for object_id in claim.object_ids:
            decision = decisions.get(object_id)
            if decision == "reject":
                continue
            if (decision == "accept" and object_id not in rejected_by_finding) or (
                claim.status == "SUPPORTED" and object_id not in rejected_by_finding
            ):
                approved.add(object_id)

    exported: list[dict[str, Any]] = []
    excluded: list[str] = []
    for object_id, obj in by_id.items():
        include = object_id in approved
        if obj.get("type") == "relationship":
            relationship_claims = [
                claim
                for claim in case.claims
                if object_id in claim.object_ids and claim.kind == "relationship"
            ]
            relationship_authorized = (
                any(claim.status == "SUPPORTED" for claim in relationship_claims)
                or decisions.get(object_id) == "accept"
            )
            include = (
                include
                and relationship_authorized
                and obj.get("source_ref") in approved
                and obj.get("target_ref") in approved
            )
        if include:
            copied = dict(obj)
            copied["x_cti_gateway_verdict"] = case.verdict.value
            copied["x_cti_gateway_evidence_coverage"] = case.evidence_coverage
            copied["x_cti_gateway_review_state"] = decisions.get(object_id, "policy-approved")
            exported.append(copied)
        else:
            excluded.append(str(object_id))
    bundle = {
        "type": "bundle",
        "id": case.candidate.id,
        "objects": exported,
        "x_cti_gateway_disclaimer": "Verified only against the supplied source document.",
    }
    return ExportResult(
        case_id=case.id,
        exported_object_ids=[str(obj["id"]) for obj in exported],
        excluded_object_ids=excluded,
        bundle=bundle,
    )


def write_artifacts(case: AnalysisCase, output_dir: Path) -> ExportResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    result = build_export(case)
    manifest = GatewayService.manifest(case)
    artifacts = {
        "stix": output_dir / "verified-stix.json",
        "findings": output_dir / "findings.json",
        "manifest": output_dir / "evidence-manifest.json",
        "audit": output_dir / "audit.json",
    }
    artifacts["stix"].write_text(
        json.dumps(result.bundle, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    artifacts["findings"].write_text(
        json.dumps(
            [item.model_dump(mode="json") for item in case.findings], ensure_ascii=False, indent=2
        ),
        encoding="utf-8",
    )
    artifacts["manifest"].write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    artifacts["audit"].write_text(
        json.dumps(
            [item.model_dump(mode="json") for item in case.audit], ensure_ascii=False, indent=2
        ),
        encoding="utf-8",
    )
    result.artifact_paths = {key: str(path.resolve()) for key, path in artifacts.items()}
    return result
