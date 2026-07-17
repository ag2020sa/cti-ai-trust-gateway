"""Safe, non-executing TXT, Markdown, and PDF ingestion."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

import fitz

from cti_trust_gateway.domain.models import SourceDocument

ARABIC_RE = re.compile(r"[\u0600-\u06ff]")
LATIN_RE = re.compile(r"[A-Za-z]")
SUPPORTED_SUFFIXES = {".txt": "text/plain", ".md": "text/markdown", ".pdf": "application/pdf"}
MAX_PDF_PAGES = 200
MAX_EXTRACTED_CHARACTERS = 2_000_000


class DocumentError(ValueError):
    """Raised when a document is unsafe or unsupported."""


def detect_language(text: str) -> str:
    arabic = len(ARABIC_RE.findall(text))
    latin = len(LATIN_RE.findall(text))
    if arabic and latin:
        return "mixed"
    if arabic:
        return "ar"
    if latin:
        return "en"
    return "unknown"


def _safe_name(name: str) -> str:
    candidate = Path(name).name
    if candidate != name or not candidate or candidate in {".", ".."}:
        raise DocumentError("Invalid filename")
    return candidate


def parse_document(
    data: bytes,
    filename: str,
    *,
    max_size: int = 10 * 1024 * 1024,
    source_metadata: dict[str, Any] | None = None,
) -> SourceDocument:
    filename = _safe_name(filename)
    if not data:
        raise DocumentError("Source document is empty")
    if len(data) > max_size:
        raise DocumentError(f"Document exceeds the {max_size}-byte upload limit")
    suffix = Path(filename).suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        raise DocumentError("Only .txt, .md, and .pdf documents are supported")

    metadata: dict[str, Any] = dict(source_metadata or {})
    pages: list[str] = []
    pdf_spans: list[dict[str, Any]] = []
    if suffix == ".pdf":
        try:
            with fitz.open(stream=data, filetype="pdf") as document:
                if document.page_count > MAX_PDF_PAGES:
                    raise DocumentError(f"PDF exceeds the {MAX_PDF_PAGES}-page limit")
                metadata["pdf_metadata"] = {k: v for k, v in document.metadata.items() if v}
                extracted_characters = 0
                for page_no, page in enumerate(document):
                    page_text = page.get_text("text", sort=True)
                    extracted_characters += len(page_text)
                    if extracted_characters > MAX_EXTRACTED_CHARACTERS:
                        raise DocumentError(
                            f"PDF exceeds the {MAX_EXTRACTED_CHARACTERS}-character text limit"
                        )
                    pages.append(page_text)
                    for block in page.get_text("dict").get("blocks", []):
                        for line in block.get("lines", []):
                            for span in line.get("spans", []):
                                pdf_spans.append(
                                    {
                                        "page": page_no + 1,
                                        "text": span.get("text", ""),
                                        "size": span.get("size", 0),
                                        "color": span.get("color", 0),
                                        "bbox": span.get("bbox", (0, 0, 0, 0)),
                                        "page_rect": tuple(page.rect),
                                    }
                                )
        except DocumentError:
            raise
        except Exception as exc:
            raise DocumentError("Unable to parse PDF safely") from exc
        metadata["pdf_spans"] = pdf_spans
    else:
        try:
            pages = [data.decode("utf-8-sig")]
        except UnicodeDecodeError as exc:
            raise DocumentError("Text documents must be valid UTF-8") from exc

    offsets: list[tuple[int, int]] = []
    combined_parts: list[str] = []
    cursor = 0
    for index, page in enumerate(pages):
        if index:
            combined_parts.append("\n\f\n")
            cursor += 3
        start = cursor
        combined_parts.append(page)
        cursor += len(page)
        offsets.append((start, cursor))
    text = "".join(combined_parts)
    if not text.strip():
        raise DocumentError("Source document contains no extractable text")
    return SourceDocument(
        id=f"document--{uuid4()}",
        filename=filename,
        media_type=SUPPORTED_SUFFIXES[suffix],
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        language=detect_language(text),
        text=text,
        pages=pages,
        page_offsets=offsets,
        metadata=metadata,
    )
