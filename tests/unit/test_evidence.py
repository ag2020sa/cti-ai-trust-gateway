from __future__ import annotations

from cti_trust_gateway.domain.models import Claim
from cti_trust_gateway.evidence.engine import (
    evidence_coverage,
    locate_value,
    normalize_search,
    validate_observable,
    verify_claims,
)
from cti_trust_gateway.parsers.document import parse_document


def claim(kind: str, value: str, *, deterministic: bool = True) -> Claim:
    return Claim(
        id="claim--1",
        kind=kind,  # type: ignore[arg-type]
        statement=value,
        value=value,
        object_ids=["ipv4-addr--00000000-0000-4000-8000-000000000001"],
        deterministic=deterministic,
    )


def test_exact_and_case_insensitive_offsets() -> None:
    document = parse_document(b"Prefix CedarFox suffix", "source.txt")
    exact = locate_value(document, "CedarFox", entity=True)[0]
    folded = locate_value(document, "cedarfox", entity=True)[0]
    assert document.text[exact.start : exact.end] == "CedarFox"
    assert exact.page == 1 and folded.match_type == "case_insensitive"


def test_unicode_normalization_for_search_only() -> None:
    original = "APT\u200b28"
    assert normalize_search(original) == "APT28"


def test_mutated_ioc_is_rejected_with_source_value() -> None:
    document = parse_document(b"Observed 203.0.113.53.", "source.txt")
    candidate = claim("observable", "203.0.113.58")
    findings = verify_claims(document, [candidate])
    assert findings[0].rule_id == "EVIDENCE-IOC-002"
    assert findings[0].metadata["source_value"] == "203.0.113.53"
    assert candidate.status == "NOT_FOUND"


def test_relationship_cooccurrence_never_passes() -> None:
    document = parse_document(b"CedarFox and GlassRAT appear in an appendix.", "source.txt")
    relationship = Claim(
        id="claim--rel",
        kind="relationship",
        statement="CedarFox uses GlassRAT",
        source_entity="CedarFox",
        target_entity="GlassRAT",
        relationship_type="uses",
        object_ids=["relationship--1"],
        deterministic=False,
    )
    findings = verify_claims(document, [relationship])
    assert relationship.status == "UNKNOWN"
    assert findings[0].rule_id == "EVIDENCE-REL-001"


def test_unknown_actor_contradicts_named_relationship() -> None:
    document = parse_document(
        b"The responsible actor is unknown. CVE-2026-1234 may be exploited.", "source.txt"
    )
    relationship = Claim(
        id="claim--rel",
        kind="relationship",
        statement="APT28 exploits CVE",
        source_entity="APT28",
        target_entity="CVE-2026-1234",
        relationship_type="exploits",
        object_ids=["relationship--1"],
        deterministic=False,
    )
    findings = verify_claims(document, [relationship])
    assert relationship.status == "CONTRADICTED"
    assert findings[0].rule_id == "EVIDENCE-REL-CONTRADICTED"


def test_coverage_and_observable_shapes() -> None:
    supported = claim("observable", "192.0.2.1")
    supported.status = "SUPPORTED"
    missing = claim("entity", "Actor")
    assert evidence_coverage([supported, missing]) == 0.5
    assert all(
        validate_observable(value)
        for value in ["192.0.2.1", "CVE-2026-1234", "T1059.001", "example.org"]
    )
    assert not validate_observable("not an observable")


def test_invalid_cve_format_is_rejected() -> None:
    document = parse_document(b"Possible vulnerability was discussed.", "source.txt")
    malformed = claim("vulnerability", "CVE-26-XYZ")
    findings = verify_claims(document, [malformed])
    assert malformed.status == "CONTRADICTED"
    assert findings[0].rule_id == "OBSERVABLE-FORMAT-001"
