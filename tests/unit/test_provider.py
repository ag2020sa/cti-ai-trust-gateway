from __future__ import annotations

from cti_trust_gateway.domain.models import Claim
from cti_trust_gateway.parsers.document import parse_document
from cti_trust_gateway.providers.semantic import (
    DeterministicSemanticVerifier,
    FakeSemanticVerifier,
    OpenAICompatibleSemanticVerifier,
    SemanticResult,
)


def relationship() -> Claim:
    return Claim(
        id="claim--semantic",
        kind="relationship",
        statement="A uses B",
        source_entity="A",
        target_entity="B",
        object_ids=["relationship--1"],
        deterministic=False,
    )


def test_default_provider_never_calls_network() -> None:
    document = parse_document(b"A and B", "source.txt")
    assert DeterministicSemanticVerifier().verify(document, relationship()) is None


def test_fake_and_disabled_openai_provider(monkeypatch: object) -> None:
    document = parse_document(b"A uses B", "source.txt")
    result = SemanticResult(status="SUPPORTED", evidence_span_refs=["0:8"], rationale="explicit")
    assert (
        FakeSemanticVerifier({"claim--semantic": result}).verify(document, relationship()) == result
    )
    assert OpenAICompatibleSemanticVerifier().verify(document, relationship()) is None
