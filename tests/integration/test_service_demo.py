from __future__ import annotations

from cti_trust_gateway.demo import run_demo
from cti_trust_gateway.domain.models import Verdict
from cti_trust_gateway.exporters.exporter import build_export


def test_golden_demo_verdicts_and_safe_export(service: object) -> None:
    cases = run_demo(service)  # type: ignore[arg-type]
    assert {name: case.verdict for name, case in cases.items()} == {
        "pass": Verdict.PASS,
        "reject": Verdict.REJECT,
        "quarantine": Verdict.QUARANTINE,
        "abstain": Verdict.ABSTAIN,
        "review": Verdict.REVIEW,
    }
    rejected = cases["reject"]
    exported = build_export(rejected)
    assert all("203.0.113.58" not in str(obj) for obj in exported.bundle["objects"])
    assert all(obj.get("type") != "relationship" for obj in exported.bundle["objects"])
    assert "EVIDENCE-IOC-002" in {finding.rule_id for finding in rejected.findings}
    assert "EVIDENCE-REL-CONTRADICTED" in {finding.rule_id for finding in rejected.findings}
