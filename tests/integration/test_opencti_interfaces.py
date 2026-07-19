from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from cti_trust_gateway.api.app import create_app
from cti_trust_gateway.cli.main import app
from cti_trust_gateway.config import bundled_policy_path
from cti_trust_gateway.core.service import GatewayService
from cti_trust_gateway.storage.repository import Repository
from tests.conftest import make_bundle, sid

CONNECTOR_ID = "12345678-1234-4234-8234-123456789abc"


def _configure(monkeypatch: pytest.MonkeyPatch, database: Path) -> None:
    monkeypatch.setenv("CTI_GATEWAY_DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("CTI_GATEWAY_OPENCTI_URL", "https://127.0.0.1")
    monkeypatch.setenv("CTI_GATEWAY_OPENCTI_IMPORT_CONNECTOR_ID", CONNECTOR_ID)
    monkeypatch.setenv("CTI_GATEWAY_OPENCTI_HOST_ALLOWLIST", "127.0.0.1")
    monkeypatch.setenv("CTI_GATEWAY_OPENCTI_ALLOW_LOOPBACK", "true")


def _seed(database: Path) -> object:
    service = GatewayService(
        Repository(f"sqlite:///{database}"), default_policy=bundled_policy_path()
    )
    return service.analyze(
        b"Observed 203.0.113.80.",
        "interface.txt",
        make_bundle(
            [
                {
                    "type": "ipv4-addr",
                    "spec_version": "2.1",
                    "id": sid("ipv4-addr", "interface"),
                    "value": "203.0.113.80",
                }
            ],
            "interface",
        ),
    )


def test_cli_offline_commands_and_dry_run_never_open_a_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "cli-opencti.db"
    _configure(monkeypatch, database)
    case = _seed(database)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("offline CLI command attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    runner = CliRunner()
    checked = runner.invoke(app, ["opencti", "check", case.id])  # type: ignore[attr-defined]
    assert checked.exit_code == 0, checked.output
    assert json.loads(checked.output)["ready"] is True
    planned = runner.invoke(app, ["opencti", "plan", case.id])  # type: ignore[attr-defined]
    assert planned.exit_code == 0, planned.output
    plan = json.loads(planned.output)
    assert plan["status"] == "PREPARED"
    assert len(plan["plan_sha256"]) == 64
    status = runner.invoke(app, ["opencti", "status", plan["id"]])
    assert status.exit_code == 0
    assert json.loads(status.output)["attempts"] == []
    history = runner.invoke(
        app,
        ["opencti", "history", "--case-id", case.id],  # type: ignore[attr-defined]
    )
    assert history.exit_code == 0
    assert len(json.loads(history.output)) == 1
    dry_run = runner.invoke(app, ["opencti", "deliver", plan["id"]])
    assert dry_run.exit_code == 0
    assert "Dry-run only" in dry_run.output


def test_api_exposes_planning_and_history_but_no_live_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "api-opencti.db"
    _configure(monkeypatch, database)
    case = _seed(database)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("API planning/read path attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    api = TestClient(create_app(f"sqlite:///{database}"))
    created = api.post(f"/api/v1/opencti/plans/{case.id}")  # type: ignore[attr-defined]
    assert created.status_code == 201
    plan = created.json()
    assert plan["status"] == "PREPARED"
    assert api.get(f"/api/v1/opencti/plans/{plan['id']}").json() == plan
    assert len(api.get("/api/v1/opencti/plans").json()) == 1
    assert api.get(f"/api/v1/opencti/plans/{plan['id']}/history").json() == []
    page = api.get(f"/cases/{case.id}")  # type: ignore[attr-defined]
    assert page.status_code == 200
    assert "OpenCTI Draft readiness" in page.text
    assert "Live OpenCTI delivery is CLI-only in this unauthenticated research beta." in page.text
    assert "READY" in page.text
    paths = {route.path for route in api.app.routes}
    assert not any(
        word in path
        for path in paths
        for word in ("deliver", "probe", "reconcile", "validate-draft")
    )
