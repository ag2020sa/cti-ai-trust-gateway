"""Deterministic OpenCTI profile compatibility and dependency checks."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from cti_trust_gateway.compatibility.profile import OpenCTIProfile
from cti_trust_gateway.core.canonical import canonical_bytes
from cti_trust_gateway.domain.models import CompatibilityFinding, CompatibilityReport


def _finding(
    code: str,
    message: str,
    *,
    object_id: str | None = None,
    property_name: str | None = None,
    dependency_id: str | None = None,
) -> CompatibilityFinding:
    return CompatibilityFinding(
        code=code,
        message=message,
        object_id=object_id,
        property_name=property_name,
        dependency_id=dependency_id,
    )


def object_references(obj: dict[str, Any]) -> frozenset[str]:
    refs: set[str] = set()
    for key, value in obj.items():
        if key.endswith("_ref") and isinstance(value, str):
            refs.add(value)
        elif key.endswith("_refs") and isinstance(value, list):
            refs.update(item for item in value if isinstance(item, str))
    extensions = obj.get("extensions")
    if isinstance(extensions, dict):
        for key, value in extensions.items():
            if not key.startswith("extension-definition--"):
                continue
            embedded = (
                isinstance(value, dict)
                and value.get("type") == "extension-definition"
                and value.get("id") == key
            )
            if not embedded:
                refs.add(key)
    return frozenset(refs)


def _semantic_type(obj: dict[str, Any]) -> str:
    object_type = str(obj.get("type", ""))
    if object_type == "identity":
        identity_class = str(obj.get("identity_class", ""))
        if identity_class == "class":
            return "identity:sector"
        if identity_class in {"individual", "organization"}:
            return f"identity:{identity_class}"
    if object_type == "location":
        location_type = str(obj.get("x_opencti_location_type", "")).casefold()
        if location_type in {"country", "region"}:
            return f"location:{location_type}"
    return object_type


def _cycle_findings(graph: dict[str, frozenset[str]], max_depth: int) -> list[CompatibilityFinding]:
    findings: list[CompatibilityFinding] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str, depth: int) -> None:
        if depth > max_depth:
            findings.append(
                _finding(
                    "OPENCTI_LIMIT_EXCEEDED",
                    "Dependency depth exceeds the profile limit",
                    object_id=node,
                )
            )
            return
        if node in visiting:
            findings.append(
                _finding("OPENCTI_DEPENDENCY_CYCLE", "Dependency cycle detected", object_id=node)
            )
            return
        if node in visited:
            return
        visiting.add(node)
        for dependency in sorted(graph.get(node, ())):
            if dependency in graph:
                visit(dependency, depth + 1)
        visiting.remove(node)
        visited.add(node)

    for object_id in sorted(graph):
        visit(object_id, 0)
    return findings


def _tlp_value(obj: dict[str, Any], red_ids: Iterable[str]) -> str | None:
    object_id = obj.get("id")
    if isinstance(object_id, str) and object_id in red_ids:
        return "red"
    definition = obj.get("definition")
    if obj.get("definition_type") == "tlp" and isinstance(definition, dict):
        value = definition.get("tlp")
        return str(value).lower() if value is not None else None
    return None


def check_opencti_compatibility(
    objects: list[dict[str, Any]], profile: OpenCTIProfile
) -> CompatibilityReport:
    findings: list[CompatibilityFinding] = []
    object_ids = tuple(str(obj.get("id", "")) for obj in objects)
    if len(objects) > profile.limits.max_objects:
        findings.append(
            _finding("OPENCTI_LIMIT_EXCEEDED", "Object count exceeds the profile limit")
        )
    try:
        object_bytes = canonical_bytes(objects)
    except (TypeError, ValueError, UnicodeError):
        object_bytes = b""
        findings.append(
            _finding("OPENCTI_CANONICALIZATION_FAILED", "Objects are not interoperable JSON")
        )
    if len(object_bytes) > profile.limits.max_bytes:
        findings.append(_finding("OPENCTI_LIMIT_EXCEEDED", "Object bytes exceed the profile limit"))

    by_id: dict[str, dict[str, Any]] = {}
    for obj in objects:
        object_id = str(obj.get("id", ""))
        object_type = str(obj.get("type", ""))
        if not object_id:
            findings.append(
                _finding(
                    "OPENCTI_UNSUPPORTED_PROPERTY",
                    "Missing object identifier",
                    object_id=object_id or None,
                )
            )
        elif object_id in by_id:
            if canonical_bytes(by_id[object_id]) != canonical_bytes(obj):
                findings.append(
                    _finding(
                        "OPENCTI_DUPLICATE_ID_CONFLICT",
                        "Conflicting objects share an identifier",
                        object_id=object_id,
                    )
                )
        else:
            by_id[object_id] = obj
        if object_type not in profile.types:
            findings.append(
                _finding(
                    "OPENCTI_UNSUPPORTED_TYPE",
                    f"Unsupported object type: {object_type}",
                    object_id=object_id,
                )
            )
            continue
        if obj.get("spec_version") not in {None, "2.1"}:
            findings.append(
                _finding(
                    "OPENCTI_VERSION_MISMATCH",
                    "Only STIX 2.1 objects are profiled",
                    object_id=object_id,
                    property_name="spec_version",
                )
            )
        allowed = profile.allowed_properties(object_type)
        for property_name in sorted(set(obj) - allowed):
            code = (
                "OPENCTI_UNSUPPORTED_CUSTOM_PROPERTY"
                if property_name.startswith("x_")
                else "OPENCTI_UNSUPPORTED_PROPERTY"
            )
            findings.append(
                _finding(
                    code,
                    f"Property is not profiled: {property_name}",
                    object_id=object_id,
                    property_name=property_name,
                )
            )
        extensions = obj.get("extensions")
        if isinstance(extensions, dict):
            allowed_extensions = set(profile.allowed_extension_definitions)
            unknown = sorted(set(extensions) - allowed_extensions)
            for extension_id in unknown:
                findings.append(
                    _finding(
                        "OPENCTI_UNSUPPORTED_EXTENSION",
                        "Extension definition is not in the pinned profile",
                        object_id=object_id,
                        dependency_id=extension_id,
                    )
                )
            if object_type != "channel" and extensions:
                findings.append(
                    _finding(
                        "OPENCTI_UNSUPPORTED_EXTENSION",
                        "Extensions are not profiled for this object type",
                        object_id=object_id,
                        property_name="extensions",
                    )
                )
        if object_type == "channel":
            rule = profile.custom_types.get("channel")
            extension_ids = set(extensions) if isinstance(extensions, dict) else set()
            definition = (
                extensions.get(rule.extension_definition_id)
                if rule is not None and isinstance(extensions, dict)
                else None
            )
            extension_properties = (
                definition.get("extension_properties") if isinstance(definition, dict) else None
            )
            extension_property_set = (
                set(extension_properties) if isinstance(extension_properties, list) else set()
            )
            exact_channel = (
                rule is not None
                and isinstance(definition, dict)
                and extension_ids == {rule.extension_definition_id}
                and definition.get("type") == "extension-definition"
                and definition.get("spec_version") == "2.1"
                and definition.get("id") == rule.extension_definition_id
                and definition.get("created_by_ref") == rule.created_by_ref
                and definition.get("name") == rule.name
                and definition.get("version") == rule.version
                and definition.get("extension_types") == [rule.extension_type]
                and extension_property_set == set(rule.extension_properties)
            )
            if not exact_channel:
                findings.append(
                    _finding(
                        "OPENCTI_UNSUPPORTED_CUSTOM_TYPE",
                        "Channel does not match the exact pinned OpenCTI representation",
                        object_id=object_id,
                    )
                )
        if object_type == "extension-definition" and object_id not in set(
            profile.allowed_extension_definitions
        ):
            findings.append(
                _finding(
                    "OPENCTI_UNSUPPORTED_EXTENSION",
                    "Extension definition is not in the pinned profile",
                    object_id=object_id,
                )
            )
        if object_type == "identity" and _semantic_type(obj) == "identity":
            findings.append(
                _finding(
                    "OPENCTI_UNSUPPORTED_REPRESENTATION",
                    "Identity must represent an individual, organization, or sector",
                    object_id=object_id,
                    property_name="identity_class",
                )
            )
        if object_type == "location" and _semantic_type(obj) == "location":
            findings.append(
                _finding(
                    "OPENCTI_UNSUPPORTED_REPRESENTATION",
                    "Location must use the pinned Country or Region representation",
                    object_id=object_id,
                    property_name="x_opencti_location_type",
                )
            )

    graph: dict[str, frozenset[str]] = {}
    for object_id, obj in by_id.items():
        refs = object_references(obj)
        graph[object_id] = refs
        for dependency in sorted(refs - by_id.keys()):
            findings.append(
                _finding(
                    "OPENCTI_MISSING_DEPENDENCY",
                    "Referenced object is absent",
                    object_id=object_id,
                    dependency_id=dependency,
                )
            )
        if obj.get("type") == "relationship":
            source_ref = str(obj.get("source_ref", ""))
            target_ref = str(obj.get("target_ref", ""))
            source_type = _semantic_type(by_id.get(source_ref, {}))
            target_type = _semantic_type(by_id.get(target_ref, {}))
            relationship_type = str(obj.get("relationship_type", ""))
            relationship_tuple = f"{source_type}|{target_type}"
            if relationship_tuple not in profile.relationships.get(relationship_type, ()):
                findings.append(
                    _finding(
                        "OPENCTI_ILLEGAL_RELATIONSHIP",
                        f"Relationship tuple is not profiled: {relationship_type} {relationship_tuple}",
                        object_id=object_id,
                    )
                )

    findings.extend(_cycle_findings(graph, profile.limits.max_dependency_depth))
    marking_definitions = {
        object_id: obj
        for object_id, obj in by_id.items()
        if obj.get("type") == "marking-definition"
    }
    for object_id, obj in by_id.items():
        marking_refs = obj.get("object_marking_refs", [])
        if not isinstance(marking_refs, list):
            continue
        tlp_values = {
            value
            for ref in marking_refs
            if isinstance(ref, str) and (marked := marking_definitions.get(ref))
            if (value := _tlp_value(marked, profile.tlp_red_ids)) is not None
        }
        if len(tlp_values) > 1:
            findings.append(
                _finding(
                    "OPENCTI_MARKING_CONFLICT",
                    "Object has conflicting TLP markings",
                    object_id=object_id,
                )
            )
        if "red" in tlp_values:
            findings.append(
                _finding(
                    "OPENCTI_TLP_RED_BLOCKED",
                    "TLP:RED delivery is blocked by default",
                    object_id=object_id,
                )
            )

    ordered = tuple(
        sorted(
            findings,
            key=lambda item: (
                item.code,
                item.object_id or "",
                item.property_name or "",
                item.dependency_id or "",
            ),
        )
    )
    return CompatibilityReport(
        profile_id=profile.metadata.id,
        profile_sha256=profile.metadata.profile_sha256,
        compatible=not ordered,
        checked_object_ids=tuple(sorted(object_ids)),
        findings=ordered,
    )
