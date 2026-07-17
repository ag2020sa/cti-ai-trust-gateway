from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from cti_trust_gateway.cli.main import app
from tests.conftest import make_bundle, sid


def test_verify_command(tmp_path: Path, monkeypatch: object) -> None:
    report = tmp_path / "report.txt"
    candidate = tmp_path / "candidate.json"
    report.write_text("Observed 192.0.2.88", encoding="utf-8")
    candidate.write_bytes(
        make_bundle(
            [{"type": "ipv4-addr", "id": sid("ipv4-addr", "cli"), "value": "192.0.2.88"}],
            "cli",
        )
    )
    result = CliRunner().invoke(app, ["verify", str(report), str(candidate)])
    assert result.exit_code == 0, result.output
    assert "Final verdict: PASS" in result.output
    assert "Evidence coverage: 100.0%" in result.output
