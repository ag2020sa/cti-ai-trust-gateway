"""FastAPI boundary for local analysis and review."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from cti_trust_gateway import __version__
from cti_trust_gateway.compatibility import load_opencti_profile
from cti_trust_gateway.config import bundled_policy_path
from cti_trust_gateway.core.service import GatewayService
from cti_trust_gateway.delivery.config import OpenCTIConfig
from cti_trust_gateway.delivery.service import OpenCTIDeliveryService
from cti_trust_gateway.domain.models import ReviewDecision, Verdict
from cti_trust_gateway.exporters.exporter import build_export
from cti_trust_gateway.parsers.document import DocumentError
from cti_trust_gateway.storage.repository import Repository, ReviewNotAllowed
from cti_trust_gateway.validators.stix import CandidateError

PACKAGE_DIR = Path(__file__).resolve().parents[1]
WEB_DIR = PACKAGE_DIR / "web"
DEFAULT_DB = os.environ.get("CTI_GATEWAY_DATABASE_URL", "sqlite:///data/runtime/gateway.db")
DEFAULT_POLICY = Path(
    os.environ.get(
        "CTI_GATEWAY_POLICY_PATH",
        str(bundled_policy_path()),
    )
)
SOURCE_MEDIA_TYPES = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".pdf": "application/pdf",
}


class ReviewRequest(BaseModel):
    finding_id: str | None = Field(default=None, max_length=120)
    object_id: str | None = Field(default=None, max_length=120)
    action: str = Field(pattern="^(accept|edit|reject)$")
    comment: str = Field(default="", max_length=2000)
    edited_value: str | None = Field(default=None, max_length=4000)
    analyst: str = Field(default="local-analyst", min_length=1, max_length=120)


def create_app(database_url: str | None = None) -> FastAPI:
    repository = Repository(database_url or DEFAULT_DB)
    service = GatewayService(repository, default_policy=DEFAULT_POLICY)
    app = FastAPI(title="CTI AI Trust Gateway", version=__version__)
    app.state.repository = repository
    app.state.service = service

    def opencti_delivery() -> OpenCTIDeliveryService:
        return OpenCTIDeliveryService(repository, load_opencti_profile(), OpenCTIConfig.from_env())

    templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
    app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'"
        )
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "local-demo", "version": __version__}

    @app.post("/api/v1/cases", status_code=201)
    async def create_case(
        request: Request,
        source: Annotated[UploadFile, File()],
        candidate: Annotated[UploadFile, File()],
        source_metadata: Annotated[str | None, Form()] = None,
        tlp: Annotated[str | None, Form()] = None,
        policy_name: Annotated[str | None, Form()] = None,
    ) -> dict[str, Any]:
        if policy_name and policy_name != "default":
            raise HTTPException(400, "Only the default policy is installed")
        form = await request.form()
        if len(form.getlist("source")) != 1 or len(form.getlist("candidate")) != 1:
            raise HTTPException(422, "Exactly one source and one candidate file are required")
        source_name = source.filename or ""
        candidate_name = candidate.filename or ""
        if (
            Path(source_name).name != source_name
            or Path(source_name).suffix.lower() not in SOURCE_MEDIA_TYPES
        ):
            raise HTTPException(422, "Invalid or unsupported source filename")
        if (
            Path(candidate_name).name != candidate_name
            or Path(candidate_name).suffix.lower() != ".json"
        ):
            raise HTTPException(422, "Candidate filename must end in .json")
        expected_source_type = SOURCE_MEDIA_TYPES[Path(source_name).suffix.lower()]
        if source.content_type not in {expected_source_type, "application/octet-stream"}:
            raise HTTPException(422, "Source MIME type does not match its filename")
        if candidate.content_type not in {"application/json", "application/octet-stream"}:
            raise HTTPException(422, "Candidate MIME type does not match .json")
        source_bytes = await source.read(service.max_upload_size + 1)
        candidate_bytes = await candidate.read(service.max_upload_size + 1)
        if (
            len(source_bytes) > service.max_upload_size
            or len(candidate_bytes) > service.max_upload_size
        ):
            raise HTTPException(413, "Upload exceeds the configured byte limit")
        try:
            metadata = json.loads(source_metadata) if source_metadata else None
            case = service.analyze(
                source_bytes,
                source_name,
                candidate_bytes,
                source_metadata=metadata,
                tlp=tlp,
            )
        except (DocumentError, CandidateError, json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from exc
        return case.model_dump(mode="json")

    @app.get("/api/v1/cases")
    def list_cases(
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> list[dict[str, Any]]:
        return [
            case.model_dump(mode="json") for case in repository.list(limit=limit, offset=offset)
        ]

    @app.get("/api/v1/cases/{case_id}")
    def get_case(case_id: str) -> dict[str, Any]:
        case = repository.get(case_id)
        if case is None:
            raise HTTPException(404, "Case not found")
        return case.model_dump(mode="json")

    @app.get("/api/v1/cases/{case_id}/findings")
    def findings(case_id: str) -> list[dict[str, Any]]:
        case = repository.get(case_id)
        if case is None:
            raise HTTPException(404, "Case not found")
        return [finding.model_dump(mode="json") for finding in case.findings]

    @app.post("/api/v1/cases/{case_id}/reviews")
    def review(case_id: str, request: ReviewRequest) -> dict[str, Any]:
        try:
            case = repository.add_review(
                case_id,
                ReviewDecision(
                    id=f"review--{uuid4()}",
                    case_id=case_id,
                    **request.model_dump(),
                ),
            )
        except KeyError as exc:
            raise HTTPException(404, "Case not found") from exc
        except ReviewNotAllowed as exc:
            raise HTTPException(409, str(exc)) from exc
        return case.model_dump(mode="json")

    @app.get("/api/v1/cases/{case_id}/manifest")
    def manifest(case_id: str) -> dict[str, Any]:
        case = repository.get(case_id)
        if case is None:
            raise HTTPException(404, "Case not found")
        return service.manifest(case).model_dump(mode="json")

    @app.get("/api/v1/cases/{case_id}/export/stix")
    def export(case_id: str) -> JSONResponse:
        case = repository.get(case_id)
        if case is None:
            raise HTTPException(404, "Case not found")
        return JSONResponse(build_export(case).bundle)

    @app.post("/api/v1/opencti/plans/{case_id}", status_code=201)
    def create_opencti_plan(case_id: str) -> dict[str, Any]:
        """Offline plan creation only; this endpoint cannot deliver."""
        try:
            return opencti_delivery().create_plan(case_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(404, "Case not found") from exc
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(409, getattr(exc, "code", "OPENCTI_PLAN_BLOCKED")) from exc

    @app.get("/api/v1/opencti/plans")
    def list_opencti_plans(
        case_id: str | None = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> list[dict[str, Any]]:
        return [
            plan.model_dump(mode="json")
            for plan in repository.list_delivery_plans(case_id, limit=limit, offset=offset)
        ]

    @app.get("/api/v1/opencti/plans/{plan_id}")
    def get_opencti_plan(plan_id: str) -> dict[str, Any]:
        plan = repository.get_delivery_plan(plan_id)
        if plan is None:
            raise HTTPException(404, "Plan not found")
        return plan.model_dump(mode="json")

    @app.get("/api/v1/opencti/plans/{plan_id}/history")
    def get_opencti_history(
        plan_id: str,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> list[dict[str, Any]]:
        if repository.get_delivery_plan(plan_id) is None:
            raise HTTPException(404, "Plan not found")
        return [
            attempt.model_dump(mode="json")
            for attempt in repository.list_delivery_attempts(plan_id, limit=limit, offset=offset)
        ]

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name="index.html", context={"cases": repository.list()}
        )

    @app.get("/cases/{case_id}", response_class=HTMLResponse)
    def case_page(request: Request, case_id: str) -> HTMLResponse:
        case = repository.get(case_id)
        if case is None:
            raise HTTPException(404, "Case not found")
        export_available = bool(build_export(case).bundle["objects"])
        export_blocked_by_policy = case.verdict in {Verdict.REJECT, Verdict.QUARANTINE}
        try:
            opencti_assessment = opencti_delivery().check(case_id)
            opencti_ready = (
                opencti_assessment.artifact is not None and not opencti_assessment.blockers
            )
            opencti_blockers = opencti_assessment.blockers
            opencti_profile_id = opencti_assessment.compatibility.profile_id
            opencti_profile_sha256 = opencti_assessment.compatibility.profile_sha256
            opencti_gates = opencti_assessment.gates.model_dump(mode="json")
            opencti_artifact_sha256 = (
                opencti_assessment.artifact.artifact_sha256
                if opencti_assessment.artifact is not None
                else None
            )
            opencti_included_count = (
                len(opencti_assessment.artifact.included_object_ids)
                if opencti_assessment.artifact is not None
                else 0
            )
            opencti_excluded_count = len(opencti_assessment.excluded_object_ids)
        except (RuntimeError, ValueError):
            opencti_ready = False
            opencti_blockers = ("OPENCTI_PROFILE_UNAVAILABLE",)
            opencti_profile_id = "unavailable"
            opencti_profile_sha256 = "unavailable"
            opencti_gates = {}
            opencti_artifact_sha256 = None
            opencti_included_count = 0
            opencti_excluded_count = 0
        return templates.TemplateResponse(
            request=request,
            name="case.html",
            context={
                "case": case,
                "export_available": export_available,
                "export_blocked_by_policy": export_blocked_by_policy,
                "opencti_ready": opencti_ready,
                "opencti_blockers": opencti_blockers,
                "opencti_profile_id": opencti_profile_id,
                "opencti_profile_sha256": opencti_profile_sha256,
                "opencti_gates": opencti_gates,
                "opencti_artifact_sha256": opencti_artifact_sha256,
                "opencti_included_count": opencti_included_count,
                "opencti_excluded_count": opencti_excluded_count,
            },
        )

    return app


app = create_app()
