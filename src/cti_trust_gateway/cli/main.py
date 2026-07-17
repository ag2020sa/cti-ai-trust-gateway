"""Local command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from cti_trust_gateway.config import bundled_policy_path
from cti_trust_gateway.core.service import GatewayService
from cti_trust_gateway.exporters.exporter import write_artifacts
from cti_trust_gateway.storage.repository import Repository

app = typer.Typer(help="Verify AI-produced CTI against its source evidence.")


def _service() -> GatewayService:
    return GatewayService(Repository(), default_policy=bundled_policy_path())


@app.command()
def verify(
    report: Path = typer.Argument(..., exists=True, dir_okay=False),
    candidate: Path = typer.Argument(..., exists=True, dir_okay=False),
    policy: Path | None = typer.Option(None, exists=True, dir_okay=False),
) -> None:
    case = _service().analyze(
        report.read_bytes(), report.name, candidate.read_bytes(), policy_path=policy
    )
    counts: dict[str, int] = {}
    for finding in case.findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    unsupported = [claim.statement for claim in case.claims if claim.status != "SUPPORTED"]
    result = write_artifacts(case, Path("data/runtime/exports") / case.id)
    typer.echo(f"Case: {case.id}")
    typer.echo(f"Final verdict: {case.verdict.value}")
    typer.echo(f"Finding counts: {json.dumps(counts)}")
    typer.echo(f"Unsupported claims: {len(unsupported)}")
    typer.echo(f"Evidence coverage: {case.evidence_coverage:.1%}")
    for name, path in result.artifact_paths.items():
        typer.echo(f"{name}: {path}")


@app.command()
def show(case_id: str) -> None:
    case = _service().repository.get(case_id)
    if case is None:
        raise typer.BadParameter("Case not found")
    typer.echo(case.model_dump_json(indent=2))


@app.command()
def export(case_id: str, format: str = typer.Option("stix")) -> None:  # noqa: A002
    if format != "stix":
        raise typer.BadParameter("Only stix format is supported")
    case = _service().repository.get(case_id)
    if case is None:
        raise typer.BadParameter("Case not found")
    result = write_artifacts(case, Path("data/runtime/exports") / case.id)
    typer.echo(result.artifact_paths["stix"])


@app.command()
def demo() -> None:
    from cti_trust_gateway.demo import run_demo

    results = run_demo(_service())
    for name, case in results.items():
        typer.echo(f"{name}: {case.verdict.value} ({case.id})")


if __name__ == "__main__":
    app()
