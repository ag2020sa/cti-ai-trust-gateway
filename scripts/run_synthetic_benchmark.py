"""Execute the generated mutation corpus and compare declared expectations."""

from __future__ import annotations

import json
from pathlib import Path

from cti_trust_gateway.core.service import GatewayService
from cti_trust_gateway.storage.repository import Repository

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    manifest_path = ROOT / "data" / "synthetic" / "generated" / "manifest.json"
    records = json.loads(manifest_path.read_text(encoding="utf-8"))
    service = GatewayService(
        Repository("sqlite:///data/runtime/benchmark.db"),
        default_policy=ROOT / "policies" / "default.yml",
    )
    failures: list[str] = []
    executed = 0
    for record in records:
        if "mutation_category" not in record:
            continue
        executed += 1
        case = service.analyze(
            Path(record["report"]).read_bytes(),
            Path(record["report"]).name,
            Path(record["candidate"]).read_bytes(),
            source_metadata=record.get("source_metadata"),
        )
        actual_categories = {finding.category.value for finding in case.findings}
        expected_categories = set(record["expected_finding_categories"])
        if case.verdict.value != record["expected_verdict"]:
            failures.append(
                f"{record['id']}: verdict {case.verdict.value} != {record['expected_verdict']}"
            )
        if not expected_categories <= actual_categories:
            failures.append(
                f"{record['id']}: categories {sorted(expected_categories - actual_categories)} missing"
            )
    print(f"Executed {executed} deterministic mutations; failures={len(failures)}")
    if failures:
        raise SystemExit("\n".join(failures[:20]))


if __name__ == "__main__":
    main()
