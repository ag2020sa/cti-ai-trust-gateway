"""Stable semantic digests for persisted analysis and review authority."""

from __future__ import annotations

from typing import Any

from cti_trust_gateway.core.canonical import canonical_sha256, normalize_stix
from cti_trust_gateway.domain.models import AnalysisCase


def _without_generated_ids(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_generated_ids(item)
            for key, item in value.items()
            if key not in {"id", "case_id", "created_at", "document_id", "finding_id", "claim_id"}
        }
    if isinstance(value, list):
        return [_without_generated_ids(item) for item in value]
    return value


def analysis_snapshot_sha256(case: AnalysisCase) -> str:
    """Bind every analysis input/result while excluding locally generated identifiers and time."""

    metadata = {
        key: value
        for key, value in case.metadata.items()
        if key not in {"analysis_snapshot_sha256", "candidate_raw_sha256"}
    }
    return canonical_sha256(
        normalize_stix(
            _without_generated_ids(
                {
                    "source": case.source.model_dump(mode="json"),
                    "candidate": case.candidate.model_dump(mode="json"),
                    "claims": [claim.model_dump(mode="json") for claim in case.claims],
                    "findings": [finding.model_dump(mode="json") for finding in case.findings],
                    "policy": case.policy.model_dump(mode="json"),
                    "verdict": case.verdict.value,
                    "evidence_coverage": case.evidence_coverage,
                    "metadata": metadata,
                }
            )
        )
    )


def review_snapshot_sha256(case: AnalysisCase) -> str:
    analysis_sha = analysis_snapshot_sha256(case)
    semantic_reviews = [
        {
            "object_id": review.object_id,
            "action": review.action,
            "comment": review.comment,
            "edited_value": review.edited_value,
            "analyst": review.analyst,
            "analysis_snapshot_sha256": review.analysis_snapshot_sha256,
        }
        for review in case.reviews
    ]
    return canonical_sha256(
        {
            "analysis_snapshot_sha256": analysis_sha,
            "verdict": case.verdict.value,
            "reviews": sorted(semantic_reviews, key=canonical_sha256),
        }
    )
