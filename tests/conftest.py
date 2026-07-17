from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest

from cti_trust_gateway.core.service import GatewayService
from cti_trust_gateway.storage.repository import Repository


def sid(kind: str, name: str) -> str:
    deterministic_v4 = UUID(hex=uuid5(NAMESPACE_URL, name).hex, version=4)
    return f"{kind}--{deterministic_v4}"


def make_bundle(objects: list[dict[str, Any]], name: str = "test") -> bytes:
    return json.dumps({"type": "bundle", "id": sid("bundle", name), "objects": objects}).encode()


@pytest.fixture
def service(tmp_path: Path) -> GatewayService:
    project = Path(__file__).resolve().parents[1]
    repository = Repository(f"sqlite:///{tmp_path / 'test.db'}")
    return GatewayService(repository, default_policy=project / "policies" / "default.yml")
