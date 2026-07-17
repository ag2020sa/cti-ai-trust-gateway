"""Explainable best-effort checks for untrusted CTI documents."""

from __future__ import annotations

import re
import unicodedata
from typing import Any
from uuid import uuid4

from cti_trust_gateway.domain.models import Finding, FindingCategory, Severity, SourceDocument

INSTRUCTION_RULES: dict[str, tuple[re.Pattern[str], Severity, str]] = {
    "DOC-INJECT-001": (
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
        Severity.CRITICAL,
        "Instruction attempts to override prior instructions",
    ),
    "DOC-INJECT-002": (
        re.compile(r"(?:you are now|act as|redefine your role|system prompt)", re.I),
        Severity.HIGH,
        "Text attempts to redefine an AI system's role",
    ),
    "DOC-INJECT-003": (
        re.compile(
            r"(?:hide|fabricate|invent)\s+(?:the\s+)?(?:finding|evidence|attribution)s?", re.I
        ),
        Severity.CRITICAL,
        "Text requests hiding or fabricating intelligence findings",
    ),
    "DOC-INJECT-AR-001": (
        re.compile(r"(?:تجاهل|تخط)[^\n]{0,30}(?:التعليمات|الأوامر)"),
        Severity.CRITICAL,
        "Arabic text appears to request ignoring instructions",
    ),
}


def _finding(
    rule_id: str,
    severity: Severity,
    explanation: str,
    evidence: str | None,
    page: int | None,
    **metadata: Any,
) -> Finding:
    return Finding(
        id=f"finding--{uuid4()}",
        rule_id=rule_id,
        category=FindingCategory.DOCUMENT_SECURITY,
        severity=severity,
        title="Suspicious document content",
        explanation=explanation,
        recommended_action="Review the original rendering; quarantine if the content is untrusted.",
        evidence=evidence,
        page=page,
        metadata=metadata,
    )


def _page_for_offset(document: SourceDocument, offset: int) -> int | None:
    for index, (start, end) in enumerate(document.page_offsets):
        if start <= offset <= end:
            return index + 1
    return None


def scan_document(document: SourceDocument) -> list[Finding]:
    findings: list[Finding] = []
    hidden_metadata = document.metadata.get("suspicious_hidden_text")
    if isinstance(hidden_metadata, str) and hidden_metadata.strip():
        findings.append(
            _finding(
                "DOC-HIDDEN-META-001",
                Severity.CRITICAL,
                "Source metadata declares suspicious hidden text not present in the visible layer",
                hidden_metadata[:240],
                None,
            )
        )
    for rule_id, (pattern, severity, explanation) in INSTRUCTION_RULES.items():
        for match in pattern.finditer(document.text):
            context = document.text[max(0, match.start() - 120) : match.end() + 120]
            benign_discussion = bool(
                re.search(
                    r"\b(?:example|discussion|quoted|training|detection rule|phrase)\b",
                    context,
                    re.I,
                )
                and re.search(r"\bnot\s+an\s+instruction\b", context, re.I)
            )
            findings.append(
                _finding(
                    rule_id,
                    Severity.LOW if benign_discussion else severity,
                    "Quoted security discussion; retained as a low-severity heuristic match"
                    if benign_discussion
                    else explanation,
                    match.group(0)[:240],
                    _page_for_offset(document, match.start()),
                    offset=match.start(),
                )
            )

    controls = [
        (index, char, unicodedata.name(char, "UNKNOWN"))
        for index, char in enumerate(document.text)
        if unicodedata.category(char) == "Cf" and char not in {"\u200e", "\u200f"}
    ]
    if controls:
        severity = Severity.HIGH if len(controls) > 10 else Severity.MEDIUM
        findings.append(
            _finding(
                "DOC-UNICODE-001",
                severity,
                f"Found {len(controls)} invisible or formatting control characters",
                ", ".join(name for _, _, name in controls[:8]),
                _page_for_offset(document, controls[0][0]),
                count=len(controls),
            )
        )

    spans = document.metadata.get("pdf_spans", [])
    tiny = [
        span for span in spans if span.get("text", "").strip() and float(span.get("size", 99)) < 3
    ]
    if tiny:
        findings.append(
            _finding(
                "PDF-HIDDEN-001",
                Severity.HIGH,
                "PDF contains text smaller than 3 points",
                tiny[0]["text"][:240],
                tiny[0]["page"],
                count=len(tiny),
            )
        )
    pale = [
        span
        for span in spans
        if span.get("text", "").strip() and int(span.get("color", 0)) >= 0xEEEEEE
    ]
    if pale:
        findings.append(
            _finding(
                "PDF-HIDDEN-002",
                Severity.HIGH,
                "PDF contains near-white text that may be hidden on a white background",
                pale[0]["text"][:240],
                pale[0]["page"],
                count=len(pale),
            )
        )
    outside = []
    for span in spans:
        x0, y0, x1, y1 = span.get("bbox", (0, 0, 0, 0))
        px0, py0, px1, py1 = span.get("page_rect", (0, 0, 0, 0))
        if span.get("text", "").strip() and (x1 < px0 or y1 < py0 or x0 > px1 or y0 > py1):
            outside.append(span)
    if outside:
        findings.append(
            _finding(
                "PDF-HIDDEN-003",
                Severity.HIGH,
                "PDF contains text outside normal page boundaries",
                outside[0]["text"][:240],
                outside[0]["page"],
                count=len(outside),
            )
        )
    if len(document.pages) > 1:
        normalized = [re.sub(r"\s+", " ", page).strip() for page in document.pages]
        duplicates = len(normalized) - len(set(normalized))
        if duplicates and any(normalized):
            findings.append(
                _finding(
                    "PDF-LAYER-001",
                    Severity.MEDIUM,
                    "Duplicate page text may indicate a repeated hidden text layer",
                    None,
                    None,
                    duplicate_pages=duplicates,
                )
            )
    return findings
