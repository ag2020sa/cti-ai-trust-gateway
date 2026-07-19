from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from cti_trust_gateway.api.app import create_app
from cti_trust_gateway.demo import run_demo
from tests.conftest import make_bundle, sid


def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(f"sqlite:///{tmp_path / 'api.db'}"))


def test_health_security_headers_and_not_found(tmp_path: Path) -> None:
    api = client(tmp_path)
    response = api.get("/health")
    assert response.json()["status"] == "ok"
    assert response.json()["version"] == "0.2.0b1"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert api.get("/api/v1/cases/missing").status_code == 404


def test_upload_review_manifest_and_export(tmp_path: Path) -> None:
    api = client(tmp_path)
    candidate = make_bundle(
        [
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": sid("ipv4-addr", "api"),
                "value": "203.0.113.8",
            }
        ],
        "api",
    )
    response = api.post(
        "/api/v1/cases",
        files={
            "source": ("report.txt", b"Observed 203.0.113.8", "text/plain"),
            "candidate": ("candidate.json", candidate, "application/json"),
        },
    )
    assert response.status_code == 201
    case = response.json()
    case_id = case["id"]
    assert case["verdict"] == "PASS"
    assert api.get(f"/api/v1/cases/{case_id}/manifest").status_code == 200
    assert len(api.get(f"/api/v1/cases/{case_id}/export/stix").json()["objects"]) == 1
    review = api.post(
        f"/api/v1/cases/{case_id}/reviews",
        json={"object_id": sid("ipv4-addr", "api"), "action": "reject", "comment": "manual"},
    )
    assert review.status_code == 200
    assert len(review.json()["audit"]) == 2
    assert api.get(f"/api/v1/cases/{case_id}/export/stix").json()["objects"] == []


def test_upload_validation_error(tmp_path: Path) -> None:
    response = client(tmp_path).post(
        "/api/v1/cases",
        files={
            "source": ("bad.exe", b"x", "application/octet-stream"),
            "candidate": ("candidate.json", b"{}", "application/json"),
        },
    )
    assert response.status_code == 422


def test_case_page_disables_empty_exports_and_backend_stays_fail_closed(
    tmp_path: Path,
) -> None:
    api = client(tmp_path)
    cases = run_demo(api.app.state.service)

    passed = cases["pass"]
    pass_page = api.get(f"/cases/{passed.id}")
    assert pass_page.status_code == 200
    assert f'href="/api/v1/cases/{passed.id}/export/stix"' in pass_page.text
    assert "No source-verified STIX objects are available for export." not in pass_page.text

    for scenario in ("reject", "quarantine"):
        case = cases[scenario]
        page = api.get(f"/cases/{case.id}")
        assert page.status_code == 200
        assert 'disabled aria-describedby="export-status"' in page.text
        assert "Export blocked by policy." in page.text
        assert "No source-verified STIX objects are available for export." in page.text
        assert f'href="/api/v1/cases/{case.id}/manifest"' in page.text
        assert f'href="/api/v1/cases/{case.id}/export/stix"' not in page.text
        assert api.get(f"/api/v1/cases/{case.id}/export/stix").json()["objects"] == []
