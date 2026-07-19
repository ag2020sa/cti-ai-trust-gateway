"""Deterministic JSON and digest helpers for immutable delivery snapshots."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

_SET_LIKE_STIX_PROPERTIES = frozenset(
    {
        "aliases",
        "architecture_execution_envs",
        "capabilities",
        "claims",
        "connector_scope",
        "extension_properties",
        "extension_types",
        "external_references",
        "evidence",
        "findings",
        "goals",
        "granular_markings",
        "implementation_languages",
        "kill_chain_phases",
        "labels",
        "malware_types",
        "object_marking_refs",
        "object_ids",
        "object_refs",
        "objects",
        "report_types",
        "roles",
        "sectors",
        "secondary_motivations",
        "tool_types",
    }
)


def _assert_json_value(value: Any) -> None:
    """Reject Python values that have no interoperable JSON representation."""

    stack = [value]
    while stack:
        current = stack.pop()
        if current is None or isinstance(current, (str, bool, int)):
            if isinstance(current, str):
                current.encode("utf-8", errors="strict")
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError("CANONICAL_JSON_NON_FINITE_NUMBER")
            continue
        if isinstance(current, dict):
            if any(not isinstance(key, str) for key in current):
                raise TypeError("CANONICAL_JSON_NON_STRING_KEY")
            stack.extend(current.keys())
            stack.extend(current.values())
            continue
        if isinstance(current, (list, tuple)):
            stack.extend(current)
            continue
        raise TypeError(f"CANONICAL_JSON_UNSUPPORTED_TYPE:{type(current).__name__}")


def canonical_json(value: Any) -> str:
    _assert_json_value(value)
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def normalize_stix(value: Any, *, property_name: str | None = None) -> Any:
    """Normalize only STIX properties whose array order has set semantics.

    Array order is preserved everywhere else. Duplicate set members are removed by their
    canonical JSON representation, making equivalent bundles stable without erasing ordered data.
    """

    if isinstance(value, dict):
        return {key: normalize_stix(item, property_name=key) for key, item in sorted(value.items())}
    if isinstance(value, list):
        normalized = [normalize_stix(item) for item in value]
        if property_name in _SET_LIKE_STIX_PROPERTIES or (
            property_name is not None and property_name.endswith("_refs")
        ):
            by_bytes = {canonical_bytes(item): item for item in normalized}
            return [by_bytes[key] for key in sorted(by_bytes)]
        return normalized
    return value
