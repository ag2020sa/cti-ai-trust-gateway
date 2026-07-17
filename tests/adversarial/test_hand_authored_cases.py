from __future__ import annotations

import pytest

from cti_trust_gateway.core.service import GatewayService
from cti_trust_gateway.exporters.exporter import build_export
from tests.adversarial.cases import CASES, bundle


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_hand_authored_expected_verdict_and_export(service: GatewayService, case: object) -> None:
    specification = case  # keeps the test oracle visibly separate from production code
    analyzed = service.analyze(
        specification.source.encode("utf-8"),
        f"{specification.name}.txt",
        bundle(specification.objects, specification.name),
        source_metadata=specification.source_metadata,
    )
    assert analyzed.verdict == specification.expected, specification.reason
    exported = build_export(analyzed)
    if analyzed.verdict.value in {"REJECT", "QUARANTINE"}:
        assert exported.bundle["objects"] == [], specification.reason


def test_catalog_is_independent_and_has_at_least_fifty_cases() -> None:
    assert len(CASES) >= 50
    assert len({case.name for case in CASES}) == len(CASES)
    assert {case.category for case in CASES} == {
        "observable",
        "grounding",
        "attack-cve",
        "stix",
        "arabic",
        "document",
        "policy",
    }
