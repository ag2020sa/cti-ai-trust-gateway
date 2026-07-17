"""Understandable YAML policy evaluation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from cti_trust_gateway.domain.models import Finding, PolicyEvaluation, Verdict

PRECEDENCE = {
    Verdict.PASS: 0,
    Verdict.ABSTAIN: 1,
    Verdict.REVIEW: 2,
    Verdict.REJECT: 3,
    Verdict.QUARANTINE: 4,
}


def load_policy(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        policy = yaml.safe_load(handle)
    if not isinstance(policy, dict) or not isinstance(policy.get("rules"), list):
        raise ValueError("Policy must contain a rules list")
    return policy


def _matches(rule: dict[str, Any], finding: Finding) -> bool:
    when = rule.get("when", {})
    checks = {
        "category": finding.category.value,
        "severity": finding.severity.value,
        "rule_id": finding.rule_id,
    }
    return all(checks.get(key) == value for key, value in when.items())


def evaluate_policy(findings: list[Finding], policy: dict[str, Any]) -> PolicyEvaluation:
    verdict = Verdict.PASS
    fired: list[str] = []
    reasons: list[str] = []
    review_ids: list[str] = []
    for rule in policy["rules"]:
        matches = [finding for finding in findings if _matches(rule, finding)]
        if not matches:
            continue
        outcome = Verdict(rule["verdict"])
        fired.append(str(rule["id"]))
        reasons.append(str(rule.get("reason", rule["id"])))
        if outcome in {Verdict.REVIEW, Verdict.ABSTAIN}:
            review_ids.extend(finding.id for finding in matches)
        if PRECEDENCE[outcome] > PRECEDENCE[verdict]:
            verdict = outcome
    return PolicyEvaluation(
        policy_name=str(policy.get("name", "unnamed")),
        fired_rules=fired,
        reasons=reasons or ["All mandatory checks passed."],
        review_finding_ids=list(dict.fromkeys(review_ids)),
        verdict=verdict,
    )
