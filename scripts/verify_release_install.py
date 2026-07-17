"""Verify an installed release from outside the source checkout."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import cti_trust_gateway
from cti_trust_gateway import __version__
from cti_trust_gateway.api.app import create_app
from cti_trust_gateway.config import bundled_policy_path
from cti_trust_gateway.core.service import GatewayService
from cti_trust_gateway.domain.models import ValidationStatus, Verdict
from cti_trust_gateway.exporters.exporter import build_export
from cti_trust_gateway.storage.repository import Repository
from cti_trust_gateway.validators.stix import (
    BUNDLED_SCHEMA_DIR,
    SCHEMA_COMMIT,
    SCHEMA_SHA256,
    _schema_hash,
)


def _bundle(value: str, *, valid_id: bool = True) -> bytes:
    object_id = (
        "ipv4-addr--ff305314-899d-40ab-97c9-68cd42e91e6f" if valid_id else "ipv4-addr--not-a-uuid"
    )
    return json.dumps(
        {
            "type": "bundle",
            "id": "bundle--f45c4269-c867-4b29-ad71-80d639a3183e",
            "objects": [
                {
                    "type": "ipv4-addr",
                    "spec_version": "2.1",
                    "id": object_id,
                    "value": value,
                }
            ],
        }
    ).encode()


def main() -> None:
    assert __version__ == "0.1.0b2"
    assert "site-packages" in Path(cti_trust_gateway.__file__).resolve().parts
    assert bundled_policy_path().is_file()
    schema_files = list(BUNDLED_SCHEMA_DIR.rglob("*.json"))
    assert len(schema_files) == 57
    assert SCHEMA_COMMIT == "c4f8d589acf2bdb3783655c89e0ffb6e150006ae"
    assert _schema_hash(BUNDLED_SCHEMA_DIR) == SCHEMA_SHA256

    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary) / "release.db"
        service = GatewayService(
            Repository(f"sqlite:///{database}"), default_policy=bundled_policy_path()
        )
        valid = service.analyze(b"Observed 203.0.113.9", "report.txt", _bundle("203.0.113.9"))
        assert valid.verdict == Verdict.PASS
        assert valid.candidate.validation.status == ValidationStatus.EXECUTED
        exported = build_export(valid).bundle["objects"]
        assert len(exported) == 1 and exported[0]["value"] == "203.0.113.9"

        invalid = service.analyze(
            b"Observed 203.0.113.9",
            "report.txt",
            _bundle("203.0.113.9", valid_id=False),
        )
        assert invalid.verdict != Verdict.PASS
        assert build_export(invalid).bundle["objects"] == []

        os.environ["CTI_GATEWAY_STIX_SCHEMA_DIR"] = str(Path(temporary) / "missing-schemas")
        try:
            unavailable = service.analyze(
                b"Observed 203.0.113.9",
                "report.txt",
                _bundle("203.0.113.9"),
            )
        finally:
            os.environ.pop("CTI_GATEWAY_STIX_SCHEMA_DIR", None)
        assert unavailable.verdict != Verdict.PASS
        assert unavailable.candidate.validation.status == ValidationStatus.UNAVAILABLE
        assert build_export(unavailable).bundle["objects"] == []

        app = create_app(f"sqlite:///{Path(temporary) / 'api.db'}")
        assert app.version == __version__

    print(
        "release_install_ok",
        f"version={__version__}",
        f"schemas={len(schema_files)}",
        f"schema_sha256={SCHEMA_SHA256}",
        "validation=EXECUTED",
    )


if __name__ == "__main__":
    main()
