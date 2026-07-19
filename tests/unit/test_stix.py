from __future__ import annotations

import pytest

from cti_trust_gateway.core.claims import extract_claims
from cti_trust_gateway.validators.stix import CandidateError, parse_candidate, validate_candidate
from tests.conftest import make_bundle, sid


def test_parse_rejects_non_json_and_non_bundle() -> None:
    with pytest.raises(CandidateError):
        parse_candidate(b"nope")
    with pytest.raises(CandidateError):
        parse_candidate({"type": "indicator"})


def test_duplicate_and_dangling_relationship() -> None:
    object_id = sid("ipv4-addr", "same")
    relationship_id = sid("relationship", "dangling")
    raw = parse_candidate(
        make_bundle(
            [
                {"type": "ipv4-addr", "id": object_id, "value": "192.0.2.1"},
                {"type": "ipv4-addr", "id": object_id, "value": "192.0.2.1"},
                {
                    "type": "relationship",
                    "id": relationship_id,
                    "relationship_type": "uses",
                    "source_ref": object_id,
                    "target_ref": sid("malware", "missing"),
                },
            ]
        )
    )
    candidate, findings = validate_candidate(raw)
    assert not candidate.is_valid
    rules = {finding.rule_id for finding in findings}
    assert "STIX-REL-DANGLING-001" in rules
    assert "STIX-DUPLICATE-CONFLICT-001" not in rules


def test_claim_extraction_for_indicator_attack_and_relationship() -> None:
    actor = sid("intrusion-set", "actor")
    malware = sid("malware", "malware")
    claims = extract_claims(
        {
            "objects": [
                {
                    "type": "indicator",
                    "id": sid("indicator", "ip"),
                    "pattern": "[ipv4-addr:value = '203.0.113.9']",
                },
                {
                    "type": "attack-pattern",
                    "id": sid("attack-pattern", "attack"),
                    "name": "PowerShell",
                    "external_references": [{"external_id": "T1059.001"}],
                },
                {"type": "intrusion-set", "id": actor, "name": "CedarFox"},
                {"type": "malware", "id": malware, "name": "GlassRAT"},
                {
                    "type": "relationship",
                    "id": sid("relationship", "uses"),
                    "relationship_type": "uses",
                    "source_ref": actor,
                    "target_ref": malware,
                },
            ]
        }
    )
    assert {claim.kind for claim in claims} >= {"observable", "attack", "relationship"}
    relationship = next(claim for claim in claims if claim.kind == "relationship")
    assert len(relationship.object_ids) == 3
