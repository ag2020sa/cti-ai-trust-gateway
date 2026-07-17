from __future__ import annotations

from pathlib import Path

from cti_trust_gateway.domain.models import Finding, FindingCategory, Severity, Verdict
from cti_trust_gateway.policies.engine import evaluate_policy, load_policy


def finding(rule: str, category: FindingCategory, severity: Severity) -> Finding:
    return Finding(
        id=f"finding--{rule}",
        rule_id=rule,
        category=category,
        severity=severity,
        title=rule,
        explanation=rule,
        recommended_action="review",
    )


def test_policy_pass_and_precedence() -> None:
    policy = load_policy(Path(__file__).resolve().parents[2] / "policies" / "default.yml")
    assert evaluate_policy([], policy).verdict is Verdict.PASS
    findings = [
        finding("CONFIDENCE-001", FindingCategory.CONFIDENCE_CALIBRATION, Severity.MEDIUM),
        finding("EVIDENCE-IOC-002", FindingCategory.OBSERVABLE_INTEGRITY, Severity.HIGH),
        finding("DOC-INJECT-001", FindingCategory.DOCUMENT_SECURITY, Severity.CRITICAL),
    ]
    result = evaluate_policy(findings, policy)
    assert result.verdict is Verdict.QUARANTINE
    assert len(result.fired_rules) == 3
