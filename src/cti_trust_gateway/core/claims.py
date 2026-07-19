"""Conversion of STIX assertions into atomic verifiable claims."""

from __future__ import annotations

import re
from typing import Any
from uuid import uuid4

from cti_trust_gateway.domain.models import Claim

PATTERN_VALUE_RE = re.compile(r"\[([^:]+):[^=]+\s*=\s*'((?:\\'|[^'])*)'\]")
VALUE_OBSERVABLE_TYPES = {
    "domain-name",
    "email-addr",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "url",
}
ENTITY_TYPES = {"malware", "tool", "intrusion-set", "campaign", "channel", "report"}


def _claim(**kwargs: Any) -> Claim:
    return Claim(id=f"claim--{uuid4()}", **kwargs)


def extract_claims(bundle: dict[str, Any]) -> list[Claim]:
    objects = [obj for obj in bundle.get("objects", []) if isinstance(obj, dict)]
    by_id = {obj.get("id"): obj for obj in objects}
    claims: list[Claim] = []
    for obj in objects:
        object_id = str(obj.get("id", ""))
        object_type = obj.get("type")
        if object_type in VALUE_OBSERVABLE_TYPES:
            value = str(obj.get("value", ""))
            claims.append(
                _claim(
                    kind="observable",
                    statement=f"The source contains {object_type} {value}.",
                    value=value,
                    value_type=str(object_type),
                    object_ids=[object_id],
                )
            )
        elif object_type == "file":
            for algorithm, value in obj.get("hashes", {}).items():
                claims.append(
                    _claim(
                        kind="observable",
                        statement=f"The source contains {algorithm} hash {value}.",
                        value=str(value),
                        value_type=f"hash:{algorithm}",
                        object_ids=[object_id],
                    )
                )
            if obj.get("name"):
                claims.append(
                    _claim(
                        kind="observable",
                        statement=f"The source contains file name {obj['name']}.",
                        value=str(obj["name"]),
                        value_type="file-name",
                        object_ids=[object_id],
                    )
                )
        elif object_type == "autonomous-system":
            claims.append(
                _claim(
                    kind="observable",
                    statement=f"The source contains autonomous system {obj.get('number', '')}.",
                    value=str(obj.get("number", "")),
                    value_type="autonomous-system-number",
                    object_ids=[object_id],
                )
            )
        elif object_type == "windows-registry-key":
            claims.append(
                _claim(
                    kind="observable",
                    statement=f"The source contains registry key {obj.get('key', '')}.",
                    value=str(obj.get("key", "")),
                    value_type="windows-registry-key",
                    object_ids=[object_id],
                )
            )
        elif object_type == "indicator":
            for observable_type, value in PATTERN_VALUE_RE.findall(str(obj.get("pattern", ""))):
                claims.append(
                    _claim(
                        kind="observable",
                        statement=f"The source contains {observable_type} {value}.",
                        value=value.replace("\\'", "'"),
                        value_type=observable_type,
                        object_ids=[object_id],
                    )
                )
        elif object_type == "vulnerability":
            value = str(obj.get("name", ""))
            claims.append(
                _claim(
                    kind="vulnerability",
                    statement=f"The source mentions vulnerability {value}.",
                    value=value,
                    object_ids=[object_id],
                )
            )
            product = obj.get("x_product") or obj.get("x_cti_product")
            if product:
                claims.append(
                    _claim(
                        kind="entity",
                        statement=f"The source associates {value} with product {product}.",
                        value=str(product),
                        value_type="product",
                        object_ids=[object_id],
                    )
                )
        elif object_type == "attack-pattern":
            attack_id = next(
                (
                    str(ref.get("external_id"))
                    for ref in obj.get("external_references", [])
                    if str(ref.get("external_id", "")).startswith("T")
                ),
                str(obj.get("name", "")),
            )
            claims.append(
                _claim(
                    kind="attack",
                    statement=f"The source maps behavior to ATT&CK {attack_id}.",
                    value=attack_id,
                    value_type="attack-id",
                    reference_name=str(obj.get("name", "")),
                    object_ids=[object_id],
                )
            )
        elif object_type == "identity":
            for property_name in ("name", "identity_class"):
                value = str(obj.get(property_name, ""))
                if value:
                    claims.append(
                        _claim(
                            kind="entity",
                            statement=f"The source identifies {property_name} {value}.",
                            value=value,
                            value_type=f"identity-{property_name.replace('_', '-')}",
                            object_ids=[object_id],
                        )
                    )
        elif object_type == "location":
            for property_name in ("name", "region", "country", "administrative_area", "city"):
                value = str(obj.get(property_name, ""))
                if value:
                    claims.append(
                        _claim(
                            kind="entity",
                            statement=f"The source identifies location {property_name} {value}.",
                            value=value,
                            value_type=f"location-{property_name.replace('_', '-')}",
                            object_ids=[object_id],
                        )
                    )
        elif object_type in ENTITY_TYPES:
            name = str(obj.get("name", ""))
            claims.append(
                _claim(
                    kind="entity",
                    statement=f"The source mentions {object_type} {name}.",
                    value=name,
                    object_ids=[object_id],
                )
            )
        if isinstance(obj.get("confidence"), int):
            claims.append(
                _claim(
                    kind="confidence",
                    statement=f"The candidate assigns confidence {obj['confidence']} to {object_id}.",
                    value=str(obj["confidence"]),
                    object_ids=[object_id],
                    deterministic=False,
                )
            )

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        source = by_id.get(obj.get("source_ref"), {})
        target = by_id.get(obj.get("target_ref"), {})
        source_name = str(source.get("name") or source.get("value") or obj.get("source_ref", ""))
        target_name = str(target.get("name") or target.get("value") or obj.get("target_ref", ""))
        relationship = str(obj.get("relationship_type", "related-to"))
        claims.append(
            _claim(
                kind="relationship",
                statement=f"{source_name} {relationship} {target_name}.",
                source_entity=source_name,
                target_entity=target_name,
                relationship_type=relationship,
                object_ids=[
                    str(obj.get("id", "")),
                    str(obj.get("source_ref", "")),
                    str(obj.get("target_ref", "")),
                ],
                deterministic=False,
            )
        )
    return claims
