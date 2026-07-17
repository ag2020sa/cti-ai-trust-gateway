"""Defensive STIX 2.1 validation with useful, claim-addressable findings."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from uuid import uuid4

import stix2
from stix2validator import ValidationOptions, validate_string

from cti_trust_gateway.domain.models import (
    CandidateBundle,
    Finding,
    FindingCategory,
    Severity,
    ValidationCapability,
    ValidationStatus,
)

SCHEMA_COMMIT = "c4f8d589acf2bdb3783655c89e0ffb6e150006ae"
SCHEMA_SHA256 = "43c2bf45bbaeeb44e5852553abffdebeaaa1584111d92d8a8d3a3101d8bd220f"
BUNDLED_SCHEMA_DIR = Path(__file__).parents[1] / "data" / "stix2.1" / "schemas"

SUPPORTED_TYPES = {
    "indicator",
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "url",
    "file",
    "vulnerability",
    "attack-pattern",
    "malware",
    "tool",
    "intrusion-set",
    "campaign",
    "report",
    "relationship",
}
ID_RE = re.compile(r"^(?P<type>[a-z0-9-]+)--[0-9a-fA-F-]{36}$")
ALLOWED_RELATIONSHIPS = {
    "uses",
    "targets",
    "indicates",
    "exploits",
    "attributed-to",
    "related-to",
    "derived-from",
    "mitigates",
    "variant-of",
    "delivers",
    "drops",
    "downloads",
    "communicates-with",
    "consists-of",
    "investigates",
    "based-on",
}
RELATIONSHIP_ENDPOINT_TYPES = {
    "uses": (
        {"intrusion-set", "campaign", "malware", "tool"},
        {"malware", "tool", "attack-pattern"},
    ),
    "exploits": ({"intrusion-set", "malware", "tool"}, {"vulnerability"}),
    "indicates": ({"indicator"}, SUPPORTED_TYPES - {"indicator", "relationship"}),
}


class CandidateError(ValueError):
    pass


def _check_json_shape(raw: Any, *, max_depth: int = 64, max_nodes: int = 50_000) -> None:
    stack: list[tuple[Any, int]] = [(raw, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if depth > max_depth:
            raise CandidateError(f"Candidate JSON exceeds the maximum depth of {max_depth}")
        if nodes > max_nodes:
            raise CandidateError(f"Candidate JSON exceeds the maximum node count of {max_nodes}")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)


def _finding(rule: str, explanation: str, object_ids: list[str] | None = None) -> Finding:
    return Finding(
        id=f"finding--{uuid4()}",
        rule_id=rule,
        category=FindingCategory.STIX_STRUCTURE,
        severity=Severity.HIGH,
        title="Invalid candidate STIX",
        explanation=explanation,
        recommended_action="Correct or regenerate the candidate bundle before export.",
        object_ids=object_ids or [],
    )


def _capability_finding(rule: str, explanation: str) -> Finding:
    return Finding(
        id=f"finding--{uuid4()}",
        rule_id=rule,
        category=FindingCategory.VALIDATION_CAPABILITY,
        severity=Severity.HIGH,
        title="Mandatory STIX validation did not execute",
        explanation=explanation,
        recommended_action="Restore the pinned validator schemas and rerun analysis.",
    )


def _schema_hash(schema_dir: Path) -> str:
    digest = sha256()
    files = sorted(
        schema_dir.rglob("*.json"), key=lambda item: item.relative_to(schema_dir).as_posix()
    )
    if not files:
        raise FileNotFoundError(f"No JSON schemas found under {schema_dir}")
    for path in files:
        relative = path.relative_to(schema_dir).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        payload = path.read_bytes()
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _assert_schema_coverage(schema_dir: Path, raw: dict[str, Any]) -> None:
    available = {path.name for path in schema_dir.rglob("*.json")}
    required = {"bundle.json", "core.json", "cyber-observable-core.json"}
    for obj in raw.get("objects", []):
        if isinstance(obj, dict) and isinstance(obj.get("type"), str):
            required.add(f"{obj['type']}.json")
    missing = sorted(required - available)
    if missing:
        raise FileNotFoundError("Required pinned schemas are missing: " + ", ".join(missing))


def _validator_version() -> str:
    try:
        return version("stix2-validator")
    except PackageNotFoundError:
        return "unavailable"


def _schema_location() -> tuple[Path, str, str]:
    override = os.environ.get("CTI_GATEWAY_STIX_SCHEMA_DIR")
    if override:
        return Path(override).resolve(), "environment override", "operator-supplied"
    return BUNDLED_SCHEMA_DIR.resolve(), "bundled OASIS schemas", SCHEMA_COMMIT


def _run_schema_validation(raw: dict[str, Any]) -> tuple[ValidationCapability, list[Finding]]:
    schema_dir, source, schema_version = _schema_location()
    base = {
        "name": "cti-stix-validator",
        "version": _validator_version(),
        "stix_version": "2.1",
        "schema_source": source,
        "schema_version": schema_version,
        "mandatory": True,
    }
    try:
        schema_digest = _schema_hash(schema_dir)
        _assert_schema_coverage(schema_dir, raw)
        if source == "bundled OASIS schemas" and schema_digest != SCHEMA_SHA256:
            raise ValueError(
                f"Bundled schema integrity mismatch: expected {SCHEMA_SHA256}, got {schema_digest}"
            )
    except (OSError, ValueError) as exc:
        message = f"Pinned STIX schema backend is unavailable: {exc}"
        capability = ValidationCapability(
            **base,
            schema_sha256=None,
            status=ValidationStatus.UNAVAILABLE,
            errors=[message],
        )
        return capability, [_capability_finding("STIX-VALIDATION-UNAVAILABLE", message)]
    try:
        result = validate_string(
            json.dumps(raw),
            ValidationOptions(version="2.1", strict_properties=False, schema_dir=str(schema_dir)),
        )
    except Exception as exc:
        message = f"Mandatory STIX validator failed: {type(exc).__name__}: {exc}"
        capability = ValidationCapability(
            **base,
            schema_sha256=schema_digest,
            status=ValidationStatus.ERROR,
            errors=[message],
        )
        return capability, [_capability_finding("STIX-VALIDATION-ERROR", message)]
    # Some stix2-validator wheels omit their declared built-in schema data. The
    # same pinned OASIS schemas are explicitly supplied above, so discard only
    # that package-data diagnostic after coverage and integrity checks succeed.
    package_data_error = "Cannot locate a schema for the object's type, nor the base schema"
    errors = [str(error) for error in result.errors if package_data_error not in str(error)]
    capability = ValidationCapability(
        **base,
        schema_sha256=schema_digest,
        status=ValidationStatus.EXECUTED,
        errors=errors[:20],
    )
    findings: list[Finding] = []
    if errors:
        findings.append(
            _finding(
                "STIX-SCHEMA-001",
                "STIX 2.1 schema validation failed: " + " | ".join(errors[:5]),
            )
        )
    return capability, findings


def parse_candidate(data: bytes | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(data, dict):
        raw = data
    else:
        if not data:
            raise CandidateError("Candidate is empty")
        try:
            raw = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
            raise CandidateError("Candidate is not valid UTF-8 JSON") from exc
    _check_json_shape(raw)
    if not isinstance(raw, dict) or raw.get("type") != "bundle":
        raise CandidateError("Candidate must be a STIX bundle object")
    if raw.get("spec_version", "2.1") != "2.1":
        raise CandidateError("Only STIX 2.1 bundles are supported")
    if not isinstance(raw.get("objects"), list):
        raise CandidateError("STIX bundle must contain an objects array")
    return raw


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def validate_candidate(raw: dict[str, Any]) -> tuple[CandidateBundle, list[Finding]]:
    validation, findings = _run_schema_validation(raw)
    objects = raw.get("objects", [])
    ids: set[str] = set()
    aliases: dict[str, str] = {}
    object_by_id: dict[str, dict[str, Any]] = {}

    for index, obj in enumerate(objects):
        if not isinstance(obj, dict):
            findings.append(
                _finding("STIX-OBJECT-001", f"Object at index {index} is not JSON object")
            )
            continue
        object_type = obj.get("type")
        object_id = obj.get("id", "")
        if object_type not in SUPPORTED_TYPES:
            findings.append(
                _finding("STIX-TYPE-001", f"Unsupported or missing type: {object_type!r}")
            )
        match = ID_RE.fullmatch(object_id) if isinstance(object_id, str) else None
        if not match or match.group("type") != object_type:
            findings.append(_finding("STIX-ID-001", f"Invalid STIX identifier: {object_id!r}"))
        elif object_id in ids:
            findings.append(
                _finding("STIX-DUPLICATE-001", f"Duplicate object id: {object_id}", [object_id])
            )
        else:
            ids.add(object_id)
            object_by_id[object_id] = obj
        for field in ("created", "modified", "valid_from", "valid_until"):
            if field in obj and not _valid_timestamp(obj[field]):
                findings.append(
                    _finding("STIX-TIME-001", f"Invalid {field} on {object_id}", [object_id])
                )
        for alias in obj.get("aliases", []):
            normalized = str(alias).casefold().strip()
            if normalized in aliases and aliases[normalized] != object_id:
                findings.append(
                    _finding(
                        "STIX-ALIAS-001",
                        f"Alias {alias!r} is duplicated across distinct objects",
                        [aliases[normalized], object_id],
                    )
                )
            aliases[normalized] = object_id

        required: dict[str, tuple[str, ...]] = {
            "indicator": ("pattern", "pattern_type", "valid_from"),
            "relationship": ("relationship_type", "source_ref", "target_ref"),
            "ipv4-addr": ("value",),
            "ipv6-addr": ("value",),
            "domain-name": ("value",),
            "url": ("value",),
            "file": ("hashes",),
            "vulnerability": ("name",),
            "attack-pattern": ("name",),
            "malware": ("name",),
            "tool": ("name",),
            "intrusion-set": ("name",),
            "campaign": ("name",),
            "report": ("name", "published", "object_refs"),
        }
        missing = [field for field in required.get(str(object_type), ()) if field not in obj]
        if missing:
            findings.append(
                _finding(
                    "STIX-REQUIRED-001",
                    f"{object_id} is missing: {', '.join(missing)}",
                    [object_id],
                )
            )
        if object_type == "indicator" and "pattern" in obj:
            try:
                stix2.parse(obj, allow_custom=True)
            except Exception as exc:
                findings.append(
                    _finding(
                        "STIX-PATTERN-001",
                        f"Invalid indicator pattern on {object_id}: {exc}",
                        [object_id],
                    )
                )
        elif object_type in SUPPORTED_TYPES:
            try:
                stix2.parse(obj, allow_custom=True)
            except Exception as exc:
                findings.append(
                    _finding(
                        "STIX-OBJECT-SCHEMA-001",
                        f"Invalid {object_type} object {object_id}: {exc}",
                        [object_id],
                    )
                )

    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "relationship":
            continue
        object_id = str(obj.get("id", ""))
        source = obj.get("source_ref")
        target = obj.get("target_ref")
        missing_refs = [ref for ref in (source, target) if ref not in object_by_id]
        if missing_refs:
            findings.append(
                _finding(
                    "STIX-REL-DANGLING-001",
                    f"Relationship {object_id} references missing objects: {missing_refs}",
                    [object_id],
                )
            )
        relationship_type = obj.get("relationship_type")
        if relationship_type not in ALLOWED_RELATIONSHIPS:
            findings.append(
                _finding(
                    "STIX-REL-TYPE-001",
                    f"Unrecognized relationship type: {relationship_type!r}",
                    [object_id],
                )
            )
        elif relationship_type in RELATIONSHIP_ENDPOINT_TYPES and not missing_refs:
            source_types, target_types = RELATIONSHIP_ENDPOINT_TYPES[relationship_type]
            source_type = object_by_id[str(source)].get("type")
            target_type = object_by_id[str(target)].get("type")
            if source_type not in source_types or target_type not in target_types:
                findings.append(
                    _finding(
                        "STIX-REL-ENDPOINT-001",
                        f"Invalid endpoints for {relationship_type}: {source_type} -> {target_type}",
                        [object_id],
                    )
                )

    candidate = CandidateBundle(
        id=str(raw.get("id", "bundle--unknown")),
        raw=raw,
        object_count=len(objects),
        is_valid=validation.status == ValidationStatus.EXECUTED and not findings,
        validation=validation,
    )
    return candidate, findings
