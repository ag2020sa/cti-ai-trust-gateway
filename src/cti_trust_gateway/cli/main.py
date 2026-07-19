"""Local command-line interface."""

from __future__ import annotations

import json
import os
from pathlib import Path

import typer

from cti_trust_gateway.compatibility import load_opencti_profile
from cti_trust_gateway.config import bundled_policy_path
from cti_trust_gateway.core.service import GatewayService
from cti_trust_gateway.delivery.config import OpenCTIConfig
from cti_trust_gateway.delivery.service import DeliveryGateError, OpenCTIDeliveryService
from cti_trust_gateway.delivery.transport import OpenCTITransportError
from cti_trust_gateway.exporters.exporter import write_artifacts
from cti_trust_gateway.storage.repository import DeliveryReservationError, Repository

app = typer.Typer(help="Verify AI-produced CTI against its source evidence.")
opencti_app = typer.Typer(help="Plan and explicitly deliver approved artifacts to OpenCTI Draft.")
app.add_typer(opencti_app, name="opencti")


def _repository() -> Repository:
    return Repository(
        os.environ.get("CTI_GATEWAY_DATABASE_URL", "sqlite:///data/runtime/gateway.db")
    )


def _service() -> GatewayService:
    return GatewayService(_repository(), default_policy=bundled_policy_path())


def _opencti_service() -> OpenCTIDeliveryService:
    return OpenCTIDeliveryService(_repository(), load_opencti_profile(), OpenCTIConfig.from_env())


def _opencti_error(exc: BaseException) -> None:
    code = getattr(exc, "code", exc.__class__.__name__)
    typer.echo(str(code), err=True)
    raise typer.Exit(code=2)


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


@opencti_app.command("check")
def opencti_check(case_id: str) -> None:
    """Offline compatibility and approval assessment; never uses the network."""
    try:
        assessment = _opencti_service().check(case_id)
    except (KeyError, RuntimeError, ValueError) as exc:
        _opencti_error(exc)
    output = {
        "case_id": assessment.case_id,
        "ready": assessment.artifact is not None and not assessment.blockers,
        "blockers": assessment.blockers,
        "profile_id": assessment.compatibility.profile_id,
        "profile_sha256": assessment.compatibility.profile_sha256,
        "compatibility_findings": [
            item.model_dump(mode="json") for item in assessment.compatibility.findings
        ],
        "artifact_sha256": assessment.artifact.artifact_sha256 if assessment.artifact else None,
        "included_object_ids": assessment.artifact.included_object_ids
        if assessment.artifact
        else (),
        "excluded_object_ids": assessment.excluded_object_ids,
        "exclusion_reasons": assessment.exclusion_reasons,
    }
    typer.echo(json.dumps(output, ensure_ascii=False, indent=2))


@opencti_app.command("plan")
def opencti_plan(
    case_id: str,
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
) -> None:
    """Create and persist a deterministic plan without network access."""
    try:
        plan = _opencti_service().create_plan(case_id)
    except (KeyError, RuntimeError, ValueError) as exc:
        _opencti_error(exc)
    rendered = plan.model_dump_json(indent=2)
    if output is not None:
        output.write_text(rendered, encoding="utf-8")
        typer.echo(str(output.resolve()))
    else:
        typer.echo(rendered)


@opencti_app.command("probe")
def opencti_probe() -> None:
    """Explicitly probe the configured destination and pinned import connector."""
    try:
        capabilities = _opencti_service().adapter.probe()
    except (RuntimeError, ValueError) as exc:
        _opencti_error(exc)
    typer.echo(capabilities.model_dump_json(indent=2))


@opencti_app.command("deliver")
def opencti_deliver(
    plan_id: str,
    execute: bool = typer.Option(False, "--execute"),
    confirm_plan_sha256: str = typer.Option("", "--confirm-plan-sha256"),
) -> None:
    """Dry-run by default; live delivery needs both explicit execution gates."""
    service = _opencti_service()
    if not execute:
        plan = service.repository.get_delivery_plan(plan_id)
        if plan is None:
            raise typer.BadParameter("Plan not found")
        typer.echo(plan.model_dump_json(indent=2))
        typer.echo("Dry-run only: add --execute and the full plan SHA-256 for live delivery.")
        return
    try:
        receipt = service.execute(plan_id, confirm_plan_sha256)
    except (
        KeyError,
        DeliveryGateError,
        DeliveryReservationError,
        OpenCTITransportError,
        RuntimeError,
        ValueError,
    ) as exc:
        _opencti_error(exc)
    typer.echo(receipt.model_dump_json(indent=2))


@opencti_app.command("status")
def opencti_status(plan_id: str) -> None:
    """Read a persisted plan and attempt status without network access."""
    repository = _repository()
    plan = repository.get_delivery_plan(plan_id)
    if plan is None:
        raise typer.BadParameter("Plan not found")
    typer.echo(
        json.dumps(
            {
                "plan": plan.model_dump(mode="json"),
                "attempts": [
                    item.model_dump(mode="json")
                    for item in repository.list_delivery_attempts(plan_id)
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


@opencti_app.command("history")
def opencti_history(case_id: str | None = None) -> None:
    """List persisted plans and attempts without network access."""
    repository = _repository()
    output = []
    for plan in repository.list_delivery_plans(case_id):
        output.append(
            {
                "plan": plan.model_dump(mode="json"),
                "attempts": [
                    item.model_dump(mode="json")
                    for item in repository.list_delivery_attempts(plan.id)
                ],
            }
        )
    typer.echo(json.dumps(output, ensure_ascii=False, indent=2))


@opencti_app.command("reconcile")
def opencti_reconcile(attempt_id: str) -> None:
    """Explicitly query one ambiguous or processing import work."""
    try:
        receipt = _opencti_service().reconcile(attempt_id)
    except (KeyError, RuntimeError, ValueError) as exc:
        _opencti_error(exc)
    typer.echo(receipt.model_dump_json(indent=2))


if __name__ == "__main__":
    app()
