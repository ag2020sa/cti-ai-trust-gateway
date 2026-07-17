from __future__ import annotations

import json
from pathlib import Path

from cti_trust_gateway.core.service import GatewayService
from cti_trust_gateway.domain.models import ValidationStatus, Verdict
from cti_trust_gateway.exporters.exporter import build_export

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "offline"


def test_offline_fixture_provenance_and_structure() -> None:
    readme = (FIXTURES / "README.md").read_text(encoding="utf-8")
    assert "MITRE Corporation" in readme
    assert "not endorsed or certified by the NVD" in readme
    attack = json.loads((FIXTURES / "mitre-attack-subset.json").read_text(encoding="utf-8"))
    vulnerability = json.loads((FIXTURES / "vulnerability-subset.json").read_text(encoding="utf-8"))
    assert len(attack["techniques"]) == 4
    assert vulnerability["vulnerabilities"][0]["cveID"] == "CVE-2021-44228"


def test_oasis_based_fixture_runs_fully_offline(service: GatewayService) -> None:
    candidate = (FIXTURES / "oasis-indicator.json").read_bytes()
    source = (FIXTURES / "report-en.txt").read_bytes()
    case = service.analyze(source, "report-en.txt", candidate)
    assert case.verdict == Verdict.PASS
    assert case.candidate.validation.status == ValidationStatus.EXECUTED
    assert len(build_export(case).bundle["objects"]) == 1


def test_original_arabic_and_mixed_reports_preserve_exact_ioc(service: GatewayService) -> None:
    candidate = json.dumps(
        {
            "type": "bundle",
            "id": "bundle--448b251b-3ec9-4510-8ee8-d28b7ff59115",
            "objects": [
                {
                    "type": "ipv4-addr",
                    "spec_version": "2.1",
                    "id": "ipv4-addr--f75bcfe5-595e-41a7-a519-1b714279ec9d",
                    "value": "203.0.113.9",
                }
            ],
        }
    ).encode()
    for filename in ("report-ar.txt", "report-mixed.txt"):
        case = service.analyze((FIXTURES / filename).read_bytes(), filename, candidate)
        assert case.verdict == Verdict.PASS
        assert case.claims[0].status == "SUPPORTED"
