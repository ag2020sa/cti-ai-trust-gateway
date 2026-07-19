from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cti_trust_gateway.compatibility.checker import (
    check_opencti_compatibility,
    object_references,
)
from cti_trust_gateway.compatibility.profile import (
    PROFILE_PATH,
    ProfileIntegrityError,
    ProfileLimits,
    ProfileUnavailable,
    load_opencti_profile,
)


def test_pinned_profile_and_all_synthetic_contract_cases() -> None:
    fixture_path = Path(__file__).parents[1] / "fixtures" / "opencti_phase1" / "cases.json"
    registry = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert registry["provenance"] == {
        "license": "Apache-2.0",
        "origin": "Original synthetic fixtures created for CTI AI Trust Gateway",
        "opencti_commit": "148ceb414d1338d7c10ff79f0302d0a03dae332f",
        "pycti_version": "7.260715.0",
        "connectors_commit": "b70a94b526574a040953cba73b3c76ec3ead6f21",
    }
    assert len(registry["cases"]) >= 18
    assert {item["language"] for item in registry["cases"]} == {"en", "ar", "mixed"}
    profile = load_opencti_profile()
    assert profile.metadata.platform_version == "7.260715.0"
    assert profile.metadata.pycti_version == "7.260715.0"
    for fixture in registry["cases"]:
        report = check_opencti_compatibility(fixture["bundle"], profile)
        actual_codes = {finding.code for finding in report.findings}
        expected_codes = set(fixture["expected_codes"])
        assert actual_codes == expected_codes, fixture["id"]
        assert report.compatible == (not expected_codes)


@pytest.mark.parametrize(
    ("payload", "expected_code"),
    [
        (
            [
                {"type": "ipv4-addr", "id": "same", "value": "203.0.113.1"},
                {"type": "ipv4-addr", "id": "same", "value": "203.0.113.2"},
            ],
            "OPENCTI_DUPLICATE_ID_CONFLICT",
        ),
        ([{"type": "unknown", "id": "x"}], "OPENCTI_UNSUPPORTED_TYPE"),
        (
            [{"type": "url", "id": "u", "value": "https://example.test", "x_hidden": 1}],
            "OPENCTI_UNSUPPORTED_CUSTOM_PROPERTY",
        ),
    ],
)
def test_stable_profile_codes(payload: list[dict[str, Any]], expected_code: str) -> None:
    report = check_opencti_compatibility(payload, load_opencti_profile())
    assert expected_code in {finding.code for finding in report.findings}


def test_profile_limits_and_marking_conflicts() -> None:
    profile = load_opencti_profile().model_copy(
        update={"limits": ProfileLimits(max_objects=1, max_bytes=1, max_dependency_depth=1)}
    )
    objects = [
        {
            "type": "marking-definition",
            "id": "marking-definition--green",
            "definition_type": "tlp",
            "definition": {"tlp": "green"},
        },
        {
            "type": "marking-definition",
            "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
            "definition_type": "tlp",
            "definition": {"tlp": "red"},
        },
        {
            "type": "ipv4-addr",
            "id": "ipv4-addr--marked",
            "value": "203.0.113.1",
            "object_marking_refs": [
                "marking-definition--green",
                "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
            ],
        },
    ]
    codes = {item.code for item in check_opencti_compatibility(objects, profile).findings}
    assert {
        "OPENCTI_LIMIT_EXCEEDED",
        "OPENCTI_MARKING_CONFLICT",
        "OPENCTI_TLP_RED_BLOCKED",
    }.issubset(codes)


def test_reference_extraction_includes_control_extensions() -> None:
    refs = object_references(
        {
            "created_by_ref": "identity--one",
            "object_refs": ["ipv4-addr--one", 7],
            "extensions": {"extension-definition--one": {"enabled": True}},
            "external_references": [{"source_name": "not-a-dependency"}],
        }
    )
    assert refs == {
        "identity--one",
        "ipv4-addr--one",
        "extension-definition--one",
    }


def test_profile_loader_fails_closed_for_missing_corrupt_and_unsafe_yaml(
    tmp_path: Path,
) -> None:
    with pytest.raises(ProfileUnavailable, match="OPENCTI_PROFILE_UNAVAILABLE"):
        load_opencti_profile(tmp_path / "missing.yml")
    corrupt = tmp_path / "corrupt.yml"
    corrupt.write_bytes(PROFILE_PATH.read_bytes().replace(b"max_objects: 1000", b"max_objects: 2"))
    with pytest.raises(ProfileIntegrityError, match="OPENCTI_PROFILE_INTEGRITY"):
        load_opencti_profile(corrupt)
    unsafe = tmp_path / "unsafe.yml"
    unsafe.write_text("!!python/object/apply:os.system ['echo unsafe']", encoding="utf-8")
    with pytest.raises(ProfileIntegrityError, match="OPENCTI_PROFILE_INTEGRITY"):
        load_opencti_profile(unsafe)
