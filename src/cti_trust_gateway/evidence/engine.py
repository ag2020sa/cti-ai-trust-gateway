"""Evidence location and deterministic claim verification."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from difflib import SequenceMatcher
from typing import Literal
from uuid import uuid4

from cti_trust_gateway.domain.models import (
    Claim,
    EvidenceSpan,
    Finding,
    FindingCategory,
    Severity,
    SourceDocument,
)

IOCISH_RE = re.compile(
    r"(?:https?://[^\s<>\]\[\"']+|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|"
    r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?)"
)
ATTACK_TECHNIQUES = {
    "T1059.001": ("PowerShell", False),
    "T1190": ("Exploit Public-Facing Application", False),
    "T1566.001": ("Spearphishing Attachment", False),
    "T1064": ("Scripting", True),
}


def normalize_search(text: str) -> str:
    return "".join(
        char for char in unicodedata.normalize("NFKC", text) if unicodedata.category(char) != "Cf"
    )


def _page(document: SourceDocument, offset: int) -> int | None:
    for index, (start, end) in enumerate(document.page_offsets):
        if start <= offset <= end:
            return index + 1
    return None


def _span(
    document: SourceDocument,
    start: int,
    end: int,
    match_type: Literal["exact", "case_insensitive", "normalized", "fuzzy", "near_match"],
) -> EvidenceSpan:
    return EvidenceSpan(
        document_id=document.id,
        page=_page(document, start),
        start=start,
        end=end,
        text=document.text[start:end],
        match_type=match_type,
    )


def locate_value(
    document: SourceDocument, value: str, *, entity: bool = False
) -> list[EvidenceSpan]:
    if not value:
        return []
    spans: list[EvidenceSpan] = []
    boundary_chars = r"\w-" if not entity else r"\w"
    pattern = rf"(?<![{boundary_chars}]){re.escape(value)}(?![{boundary_chars}])"
    for match in re.finditer(pattern, document.text):
        line_prefix = document.text[document.text.rfind("\n", 0, match.start()) + 1 : match.start()]
        if entity and re.match(r"\s*(?:references?|bibliography)\s*:\s*$", line_prefix, re.I):
            continue
        spans.append(_span(document, match.start(), match.end(), "exact"))
    if spans or not entity:
        return spans
    for folded_match in re.finditer(pattern, document.text, re.I):
        line_prefix = document.text[
            document.text.rfind("\n", 0, folded_match.start()) + 1 : folded_match.start()
        ]
        if re.match(r"\s*(?:references?|bibliography)\s*:\s*$", line_prefix, re.I):
            continue
        return [_span(document, folded_match.start(), folded_match.end(), "case_insensitive")]
    if re.search(
        rf"(?im)^\s*(?:references?|bibliography)\s*:[^\n]*{re.escape(value)}",
        document.text,
    ):
        return []
    normalized_doc = normalize_search(document.text)
    normalized_value = normalize_search(value)
    normalized_index = normalized_doc.casefold().find(normalized_value.casefold())
    if normalized_index >= 0:
        return [_span(document, normalized_index, normalized_index + len(value), "normalized")]
    best: tuple[float, re.Match[str] | None] = (0.0, None)
    for match in re.finditer(r"[\w.-]+(?:\s+[\w.-]+){0,4}", document.text, re.UNICODE):
        ratio = SequenceMatcher(None, match.group(0).casefold(), value.casefold()).ratio()
        if ratio > best[0]:
            best = (ratio, match)
    if best[0] >= 0.84 and best[1] is not None:
        return [_span(document, best[1].start(), best[1].end(), "fuzzy")]
    return []


def _near_ioc(document: SourceDocument, value: str) -> str | None:
    best_score = 0.0
    best_value: str | None = None
    candidates: list[str] = IOCISH_RE.findall(document.text)
    candidates.extend(
        re.findall(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f:]{2,}(?![0-9A-Fa-f:])", document.text)
    )
    try:
        expected_ip = ipaddress.ip_address(value)
    except ValueError:
        expected_ip = None
    for found in candidates:
        if expected_ip is not None:
            try:
                if ipaddress.ip_address(found) == expected_ip:
                    return found
            except ValueError:
                pass
        score = SequenceMatcher(None, found.casefold(), value.casefold()).ratio()
        if score > best_score:
            best_score, best_value = score, found
    threshold = 0.78 if len(value) < 12 else 0.9
    return best_value if best_score >= threshold else None


def _category(claim: Claim) -> FindingCategory:
    if claim.kind == "attack":
        return FindingCategory.ATTACK_MAPPING
    if claim.kind == "relationship":
        return FindingCategory.RELATIONSHIP_GROUNDING
    if claim.kind == "confidence":
        return FindingCategory.CONFIDENCE_CALIBRATION
    if claim.kind == "entity":
        return FindingCategory.ENTITY_GROUNDING
    return FindingCategory.OBSERVABLE_INTEGRITY


def verify_claims(document: SourceDocument, claims: list[Claim]) -> list[Finding]:
    findings: list[Finding] = []
    for claim in claims:
        if claim.kind == "relationship":
            source_spans = locate_value(document, claim.source_entity or "", entity=True)
            target_spans = locate_value(document, claim.target_entity or "", entity=True)
            claim.evidence = source_spans + target_spans
            unknown_actor = bool(
                re.search(
                    r"(?:responsible\s+actor|actor|attribution)\s+(?:is\s+)?(?:unknown|unconfirmed)|"
                    r"الجهة\s+المسؤولة\s+غير\s+معروفة",
                    document.text,
                    re.I,
                )
            )
            explicit_negation = bool(
                re.search(
                    r"\b(?:did\s+not|does\s+not|not|never|no\s+evidence\s+(?:that|of))\b"
                    r"[^.\n]{0,100}\b(?:use[sd]?|exploit(?:ed|s)?|attribute[sd]?)\b|"
                    r"\b(?:لم|لا|ليس)\b[^.\n]{0,100}\b(?:يستخدم|استغل|نسب)\b",
                    document.text,
                    re.I,
                )
            )
            contradicted = (
                (unknown_actor and not source_spans) or explicit_negation
            ) and claim.relationship_type in {"attributed-to", "exploits", "uses"}
            claim.status = "CONTRADICTED" if contradicted else "UNKNOWN"
            findings.append(
                Finding(
                    id=f"finding--{uuid4()}",
                    rule_id="EVIDENCE-REL-CONTRADICTED" if contradicted else "EVIDENCE-REL-001",
                    category=FindingCategory.RELATIONSHIP_GROUNDING,
                    severity=Severity.HIGH if contradicted else Severity.MEDIUM,
                    title="Source contradicts actor relationship"
                    if contradicted
                    else "Relationship lacks deterministic proof",
                    explanation=(
                        "The source explicitly says the actor is unknown, while the candidate assigns "
                        "a named actor relationship."
                        if contradicted
                        else "Both endpoint mentions are evidence of co-occurrence only; the relationship "
                        "requires semantic verification or analyst review."
                    ),
                    recommended_action="Reject unsupported attribution and dependent relationships."
                    if contradicted
                    else "Review the cited context or configure a semantic verifier.",
                    claim_id=claim.id,
                    object_ids=claim.object_ids,
                    evidence=" | ".join(span.text for span in claim.evidence[:2]) or None,
                )
            )
            continue
        if claim.kind == "attack" and re.fullmatch(r"T\d{4}(?:\.\d{3})?", claim.value or ""):
            attack_record = ATTACK_TECHNIQUES.get(claim.value or "")
            if attack_record is None:
                findings.append(
                    Finding(
                        id=f"finding--{uuid4()}",
                        rule_id="ATTACK-REFERENCE-UNKNOWN",
                        category=FindingCategory.ATTACK_MAPPING,
                        severity=Severity.MEDIUM,
                        title="ATT&CK reference is not in the pinned offline set",
                        explanation=(
                            f"{claim.value!r} could not be verified against the pinned reference subset."
                        ),
                        recommended_action="Verify the ID against current ATT&CK data before export.",
                        claim_id=claim.id,
                        object_ids=claim.object_ids,
                    )
                )
            else:
                expected_name, deprecated = attack_record
                if (
                    claim.reference_name
                    and claim.reference_name.casefold() != expected_name.casefold()
                ):
                    claim.status = "CONTRADICTED"
                    findings.append(
                        Finding(
                            id=f"finding--{uuid4()}",
                            rule_id="ATTACK-NAME-001",
                            category=FindingCategory.ATTACK_MAPPING,
                            severity=Severity.HIGH,
                            title="ATT&CK ID and technique name disagree",
                            explanation=(
                                f"{claim.value} is {expected_name!r}, not {claim.reference_name!r}."
                            ),
                            recommended_action="Correct the mapping and rerun analysis.",
                            claim_id=claim.id,
                            object_ids=claim.object_ids,
                        )
                    )
                    continue
                if deprecated:
                    findings.append(
                        Finding(
                            id=f"finding--{uuid4()}",
                            rule_id="ATTACK-REFERENCE-DEPRECATED",
                            category=FindingCategory.ATTACK_MAPPING,
                            severity=Severity.MEDIUM,
                            title="Deprecated ATT&CK reference",
                            explanation=(
                                f"{claim.value} is marked deprecated in the pinned reference subset."
                            ),
                            recommended_action="Map to a current technique and rerun analysis.",
                            claim_id=claim.id,
                            object_ids=claim.object_ids,
                        )
                    )
        if claim.kind in {"observable", "vulnerability", "attack"} and not validate_observable(
            claim.value or "", claim.value_type
        ):
            claim.status = "CONTRADICTED"
            findings.append(
                Finding(
                    id=f"finding--{uuid4()}",
                    rule_id="OBSERVABLE-FORMAT-001",
                    category=_category(claim),
                    severity=Severity.HIGH,
                    title="Candidate identifier has an invalid format",
                    explanation=f"{claim.value!r} is not a valid CVE or ATT&CK identifier.",
                    recommended_action="Reject the malformed identifier and regenerate the object.",
                    claim_id=claim.id,
                    object_ids=claim.object_ids,
                    metadata={"candidate_value": claim.value},
                )
            )
            continue
        if claim.kind == "confidence":
            confidence = int(claim.value or 0)
            claim.status = "UNKNOWN"
            if confidence >= 80:
                findings.append(
                    Finding(
                        id=f"finding--{uuid4()}",
                        rule_id="CONFIDENCE-001",
                        category=FindingCategory.CONFIDENCE_CALIBRATION,
                        severity=Severity.MEDIUM,
                        title="High confidence is not grounded",
                        explanation=f"Candidate confidence {confidence} is not independently supported.",
                        recommended_action="Calibrate confidence against evidence and analyst judgment.",
                        claim_id=claim.id,
                        object_ids=claim.object_ids,
                    )
                )
            continue
        spans = locate_value(document, claim.value or "", entity=claim.kind == "entity")
        claim.evidence = spans
        if spans:
            claim.status = "SUPPORTED"
            continue
        claim.status = "NOT_FOUND"
        near = (
            _near_ioc(document, claim.value or "")
            if claim.kind in {"observable", "attack", "vulnerability"}
            else None
        )
        corrupted = near is not None and near != claim.value
        findings.append(
            Finding(
                id=f"finding--{uuid4()}",
                rule_id="EVIDENCE-IOC-002" if corrupted else "EVIDENCE-NOTFOUND-001",
                category=_category(claim),
                severity=Severity.HIGH if corrupted or claim.kind != "entity" else Severity.MEDIUM,
                title="Candidate value differs from source"
                if corrupted
                else "Claim is not grounded",
                explanation=(
                    f"Candidate value {claim.value!r} was not found exactly. Closest source value: {near!r}."
                    if corrupted
                    else f"No acceptable evidence was found for {claim.value!r}."
                ),
                recommended_action="Reject the corrupted value; use the exact source value."
                if corrupted
                else "Review or reject this unsupported claim.",
                claim_id=claim.id,
                object_ids=claim.object_ids,
                evidence=near,
                metadata={"candidate_value": claim.value, "source_value": near},
            )
        )
    return findings


def bilingual_consistency_findings(document: SourceDocument, claims: list[Claim]) -> list[Finding]:
    if document.language != "mixed":
        return []
    unknown_signal = bool(
        re.search(
            r"actor\s+is\s+unknown|attribution\s+is\s+unknown|الجهة\s+المسؤولة\s+غير\s+معروفة",
            document.text,
            re.I,
        )
    )
    attribution_signal = bool(
        re.search(r"نُ?سب[^.\n]{0,50}(?:APT|مجموعة)|attributed\s+to", document.text, re.I)
    )
    if not (unknown_signal and attribution_signal):
        return []
    return [
        Finding(
            id=f"finding--{uuid4()}",
            rule_id="BILINGUAL-ATTRIBUTION-001",
            category=FindingCategory.BILINGUAL_CONSISTENCY,
            severity=Severity.MEDIUM,
            title="Arabic and English attribution statements may conflict",
            explanation="One language says the actor is unknown while another appears to attribute activity.",
            recommended_action="Have a bilingual analyst reconcile the statements before export.",
            object_ids=[object_id for claim in claims for object_id in claim.object_ids],
        )
    ]


def evidence_coverage(claims: list[Claim]) -> float:
    relevant = [claim for claim in claims if claim.kind != "confidence"]
    if not relevant:
        return 0.0
    supported = sum(claim.status == "SUPPORTED" for claim in relevant)
    return round(supported / len(relevant), 4)


def validate_observable(value: str, value_type: str | None = None) -> bool:
    if value_type and value_type.startswith("hash:"):
        algorithm = value_type.split(":", 1)[1].upper().replace("-", "")
        expected = {"MD5": 32, "SHA1": 40, "SHA256": 64, "SHA512": 128}.get(algorithm)
        return bool(expected and len(value) == expected and re.fullmatch(r"[A-Fa-f0-9]+", value))
    if value_type in {"ipv4-addr", "ipv6-addr"}:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return False
        return parsed.version == (4 if value_type == "ipv4-addr" else 6)
    if value_type == "autonomous-system-number":
        return value.isdigit() and 0 <= int(value) <= 4_294_967_295
    if value_type == "email-addr":
        return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value))
    if value_type == "mac-addr":
        return bool(re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value))
    if value_type == "windows-registry-key":
        return bool(value and "\x00" not in value)
    if value_type == "file-name":
        return bool(value and "\x00" not in value and len(value) <= 255)
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", value, re.I):
        return True
    if re.fullmatch(r"T\d{4}(?:\.\d{3})?", value):
        return True
    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value):
        return True
    return bool(re.fullmatch(r"https?://\S+|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}", value))
