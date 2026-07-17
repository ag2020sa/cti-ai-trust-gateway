from __future__ import annotations

import fitz
import pytest

from cti_trust_gateway.parsers.document import DocumentError, detect_language, parse_document


@pytest.mark.parametrize(
    ("text", "expected"),
    [("English text", "en"), ("نص عربي", "ar"), ("English نص", "mixed"), ("123", "unknown")],
)
def test_language_detection(text: str, expected: str) -> None:
    assert detect_language(text) == expected


def test_text_hash_offsets_and_original_evidence() -> None:
    parsed = parse_document("مرحباً IOC 192.0.2.1".encode(), "report.md")
    assert parsed.sha256
    assert parsed.pages == [parsed.text]
    assert parsed.page_offsets == [(0, len(parsed.text))]
    assert parsed.language == "mixed"


@pytest.mark.parametrize("filename", ["../report.txt", "report.exe", ""])
def test_rejects_unsafe_or_unsupported_names(filename: str) -> None:
    with pytest.raises(DocumentError):
        parse_document(b"data", filename)


def test_upload_limit() -> None:
    with pytest.raises(DocumentError, match="upload limit"):
        parse_document(b"12345", "report.txt", max_size=4)


def test_pdf_pages_and_spans() -> None:
    pdf = fitz.open()
    page = pdf.new_page()
    page.insert_text((72, 72), "IOC 203.0.113.5", fontsize=2)
    data = pdf.tobytes()
    pdf.close()
    parsed = parse_document(data, "report.pdf")
    assert parsed.pages
    assert parsed.metadata["pdf_spans"]
