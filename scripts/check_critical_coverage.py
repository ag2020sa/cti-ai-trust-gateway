"""Enforce branch-aware coverage for the OpenCTI critical path."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any

FULL_MODULE_SUFFIXES = (
    "compatibility/checker.py",
    "compatibility/profile.py",
    "core/canonical.py",
    "core/snapshots.py",
    "delivery/artifact.py",
    "delivery/config.py",
    "delivery/security.py",
    "delivery/service.py",
    "delivery/transport.py",
)
REPOSITORY_SUFFIX = "storage/repository.py"
REPOSITORY_CLASSES = {"DeliveryPlanRecord", "DeliveryAttemptRecord"}
REPOSITORY_FUNCTIONS = {
    "save_delivery_plan",
    "_save_delivery_plan_locked",
    "get_delivery_plan",
    "list_delivery_plans",
    "reserve_delivery_attempt",
    "update_delivery_attempt",
    "get_delivery_attempt",
    "list_delivery_attempts",
    "_plan_from_record",
    "_attempt_from_record",
    "_sanitize_message",
    "_validate_remote_id",
}
PER_FILE_MINIMUM = 90.0
AGGREGATE_MINIMUM = 95.0


def _entry(files: dict[str, Any], suffix: str) -> tuple[str, dict[str, Any]]:
    matches = [
        (name, value) for name, value in files.items() if name.replace("\\", "/").endswith(suffix)
    ]
    if len(matches) != 1:
        raise ValueError(f"missing-or-ambiguous:{suffix}")
    return matches[0]


def _counts(entry: dict[str, Any]) -> tuple[int, int]:
    summary = entry["summary"]
    covered = int(summary["covered_lines"]) + int(summary["covered_branches"])
    total = int(summary["num_statements"]) + int(summary["num_branches"])
    return covered, total


def _repository_counts(path: Path, entry: dict[str, Any]) -> tuple[int, int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    ranges: list[range] = []
    for node in ast.walk(tree):
        wanted = (
            isinstance(node, ast.ClassDef)
            and node.name in REPOSITORY_CLASSES
            or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in REPOSITORY_FUNCTIONS
        )
        if wanted:
            ranges.append(range(node.lineno, node.end_lineno + 1))
    relevant = {line for selected in ranges for line in selected}
    executed_lines = set(entry.get("executed_lines", [])) & relevant
    missing_lines = set(entry.get("missing_lines", [])) & relevant
    executed_branches = [
        branch for branch in entry.get("executed_branches", []) if branch[0] in relevant
    ]
    missing_branches = [
        branch for branch in entry.get("missing_branches", []) if branch[0] in relevant
    ]
    return (
        len(executed_lines) + len(executed_branches),
        len(executed_lines) + len(missing_lines) + len(executed_branches) + len(missing_branches),
    )


def _percent(covered: int, total: int) -> float:
    return 100.0 if total == 0 else covered * 100.0 / total


def main() -> None:
    report_path = Path(sys.argv[1] if len(sys.argv) > 1 else "critical-coverage.json")
    document = json.loads(report_path.read_text(encoding="utf-8"))
    files = document.get("files", {})
    failures: list[str] = []
    results: list[tuple[str, int, int]] = []
    for suffix in FULL_MODULE_SUFFIXES:
        try:
            _, entry = _entry(files, suffix)
        except ValueError as exc:
            failures.append(str(exc))
            continue
        results.append((suffix, *_counts(entry)))
    try:
        repository_name, repository_entry = _entry(files, REPOSITORY_SUFFIX)
        source_path = Path(repository_name)
        if not source_path.is_file():
            source_path = Path.cwd() / repository_name
        results.append(
            (
                f"{REPOSITORY_SUFFIX}:delivery-paths",
                *_repository_counts(source_path, repository_entry),
            )
        )
    except (OSError, ValueError) as exc:
        failures.append(str(exc))

    for name, covered, total in results:
        percent = _percent(covered, total)
        print(f"{name} statements+branches={covered}/{total} percent={percent:.2f}")
        if percent < PER_FILE_MINIMUM:
            failures.append(f"below-{PER_FILE_MINIMUM:.0f}:{name}:{percent:.2f}")
    aggregate_covered = sum(item[1] for item in results)
    aggregate_total = sum(item[2] for item in results)
    aggregate = _percent(aggregate_covered, aggregate_total)
    if aggregate < AGGREGATE_MINIMUM:
        failures.append(f"aggregate-below-{AGGREGATE_MINIMUM:.0f}:{aggregate:.2f}")
    if failures:
        raise SystemExit("critical coverage failed: " + ", ".join(failures))
    print(
        f"critical_coverage_ok aggregate={aggregate:.2f} files={len(results)} "
        f"per_file_min={min(_percent(c, t) for _, c, t in results):.2f}"
    )


if __name__ == "__main__":
    main()
