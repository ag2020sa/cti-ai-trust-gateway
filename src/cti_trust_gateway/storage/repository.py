"""SQLite persistence for cases, reviews, and hash-chained audit events."""

from __future__ import annotations

import builtins
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    select,
    text,
)
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy.pool import NullPool

from cti_trust_gateway.core.snapshots import analysis_snapshot_sha256
from cti_trust_gateway.domain.models import (
    AnalysisCase,
    AuditEvent,
    DeliveryAttempt,
    DeliveryPlan,
    DeliveryStatus,
    ReviewDecision,
    ValidationStatus,
    Verdict,
    utc_now,
)


class ReviewNotAllowed(ValueError):
    pass


class DeliveryReservationError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class Base(DeclarativeBase):
    pass


class CaseRecord(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    created_at: Mapped[Any] = mapped_column(DateTime(timezone=True))
    verdict: Mapped[str] = mapped_column(String(20), index=True)
    payload: Mapped[str] = mapped_column(Text)


class DeliveryPlanRecord(Base):
    __tablename__ = "delivery_plans"
    __table_args__ = (UniqueConstraint("logical_key", name="uq_delivery_plan_logical_key"),)
    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    logical_key: Mapped[str] = mapped_column(String(64), nullable=False)
    case_id: Mapped[str] = mapped_column(String(80), index=True)
    created_at: Mapped[Any] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), index=True)
    plan_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    payload: Mapped[str] = mapped_column(Text)


class DeliveryAttemptRecord(Base):
    __tablename__ = "delivery_attempts"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    plan_id: Mapped[str] = mapped_column(String(96), ForeignKey("delivery_plans.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    started_at: Mapped[Any] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[Any | None] = mapped_column(DateTime(timezone=True), nullable=True)
    draft_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    remote_file_id: Mapped[str | None] = mapped_column(String(300), nullable=True)
    work_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    message: Mapped[str] = mapped_column(String(500), default="")


class Repository:
    def __init__(self, database_url: str = "sqlite:///data/runtime/gateway.db") -> None:
        if database_url.startswith("sqlite:///"):
            db_path = Path(database_url.removeprefix("sqlite:///"))
            db_path.parent.mkdir(parents=True, exist_ok=True)
        engine_options: dict[str, Any] = {}
        if database_url.startswith("sqlite:"):
            engine_options["poolclass"] = NullPool
            engine_options["connect_args"] = {"timeout": 5}
        self.engine = create_engine(database_url, **engine_options)
        Base.metadata.create_all(self.engine)

    def save(self, case: AnalysisCase) -> None:
        payload = case.model_dump_json()
        with Session(self.engine) as session:
            record = session.get(CaseRecord, case.id)
            if record is None:
                session.add(
                    CaseRecord(
                        id=case.id,
                        created_at=case.created_at,
                        verdict=case.verdict.value,
                        payload=payload,
                    )
                )
            else:
                record.verdict = case.verdict.value
                record.payload = payload
            session.commit()

    def get(self, case_id: str) -> AnalysisCase | None:
        with Session(self.engine) as session:
            record = session.get(CaseRecord, case_id)
            return AnalysisCase.model_validate_json(record.payload) if record else None

    def list(self, *, limit: int = 100, offset: int = 0) -> list[AnalysisCase]:
        if not 1 <= limit <= 100 or not 0 <= offset <= 100_000:
            raise ValueError("CASE_PAGINATION_INVALID")
        with Session(self.engine) as session:
            records = session.scalars(
                select(CaseRecord)
                .order_by(CaseRecord.created_at.desc())
                .limit(limit)
                .offset(offset)
            ).all()
            return [AnalysisCase.model_validate_json(record.payload) for record in records]

    def save_delivery_plan(self, plan: DeliveryPlan) -> DeliveryPlan:
        try:
            with Session(self.engine) as session:
                if self.engine.dialect.name == "sqlite":
                    session.execute(text("BEGIN IMMEDIATE"))
                return self._save_delivery_plan_locked(session, plan)
        except (IntegrityError, OperationalError) as exc:
            raise DeliveryReservationError("DELIVERY_DATABASE_CONFLICT") from exc

    def _save_delivery_plan_locked(self, session: Session, plan: DeliveryPlan) -> DeliveryPlan:
        existing = session.scalar(
            select(DeliveryPlanRecord).where(DeliveryPlanRecord.logical_key == plan.logical_key)
        )
        if existing is not None:
            stored = self._plan_from_record(existing)
            has_attempt = session.scalar(
                select(DeliveryAttemptRecord.id)
                .where(DeliveryAttemptRecord.plan_id == existing.id)
                .limit(1)
            )
            if (
                stored.status == DeliveryStatus.PREPARED
                and stored.expires_at <= utc_now()
                and has_attempt is None
            ):
                existing.created_at = plan.created_at
                existing.expires_at = plan.expires_at
                existing.status = plan.status.value
                existing.plan_sha256 = plan.plan_sha256
                existing.artifact_sha256 = plan.artifact_sha256
                existing.payload = plan.model_dump_json()
                session.commit()
                return plan
            if existing.plan_sha256 != plan.plan_sha256:
                if existing.id == plan.id:
                    return stored
                raise DeliveryReservationError("DELIVERY_PLAN_LOGICAL_KEY_COLLISION")
            return self._plan_from_record(existing)
        session.add(
            DeliveryPlanRecord(
                id=plan.id,
                logical_key=plan.logical_key,
                case_id=plan.case_id,
                created_at=plan.created_at,
                expires_at=plan.expires_at,
                status=plan.status.value,
                plan_sha256=plan.plan_sha256,
                artifact_sha256=plan.artifact_sha256,
                payload=plan.model_dump_json(),
            )
        )
        session.commit()
        return plan

    def get_delivery_plan(self, plan_id: str) -> DeliveryPlan | None:
        with Session(self.engine) as session:
            record = session.get(DeliveryPlanRecord, plan_id)
            return self._plan_from_record(record) if record else None

    def list_delivery_plans(
        self, case_id: str | None = None, *, limit: int = 100, offset: int = 0
    ) -> builtins.list[DeliveryPlan]:
        if not 1 <= limit <= 100 or not 0 <= offset <= 100_000:
            raise ValueError("DELIVERY_PAGINATION_INVALID")
        with Session(self.engine) as session:
            query = select(DeliveryPlanRecord)
            if case_id is not None:
                query = query.where(DeliveryPlanRecord.case_id == case_id)
            records = session.scalars(
                query.order_by(DeliveryPlanRecord.created_at.desc()).limit(limit).offset(offset)
            ).all()
            return [self._plan_from_record(record) for record in records]

    def reserve_delivery_attempt(self, plan_id: str) -> DeliveryAttempt:
        with Session(self.engine) as session:
            if self.engine.dialect.name == "sqlite":
                session.execute(text("BEGIN IMMEDIATE"))
            plan = session.get(DeliveryPlanRecord, plan_id)
            if plan is None:
                raise KeyError(plan_id)
            if plan.status == DeliveryStatus.BLOCKED.value:
                raise DeliveryReservationError("DELIVERY_PLAN_BLOCKED")
            previous = session.scalars(
                select(DeliveryAttemptRecord)
                .where(DeliveryAttemptRecord.plan_id == plan_id)
                .order_by(DeliveryAttemptRecord.started_at.desc())
            ).all()
            if any(item.status == DeliveryStatus.SUCCEEDED.value for item in previous):
                existing_noop = next(
                    (item for item in previous if item.status == DeliveryStatus.NOOP.value), None
                )
                if existing_noop is not None:
                    session.commit()
                    return self._attempt_from_record(existing_noop)
                now = utc_now()
                attempt = DeliveryAttemptRecord(
                    id=f"attempt--{uuid4()}",
                    plan_id=plan_id,
                    status=DeliveryStatus.NOOP.value,
                    started_at=now,
                    finished_at=now,
                    message="Equivalent plan already succeeded",
                )
                session.add(attempt)
                session.commit()
                return self._attempt_from_record(attempt)
            if any(
                item.status
                in {
                    DeliveryStatus.SUBMITTED.value,
                    DeliveryStatus.PREPARED.value,
                    DeliveryStatus.PROCESSING.value,
                    DeliveryStatus.UNKNOWN.value,
                    DeliveryStatus.PARTIAL.value,
                }
                or (
                    item.status == DeliveryStatus.FAILED.value
                    and any((item.draft_id, item.remote_file_id, item.work_id))
                )
                for item in previous
            ):
                raise DeliveryReservationError("DELIVERY_RECONCILIATION_REQUIRED")
            attempt = DeliveryAttemptRecord(
                id=f"attempt--{uuid4()}",
                plan_id=plan_id,
                status=DeliveryStatus.PREPARED.value,
                started_at=utc_now(),
                message="Execution reserved",
            )
            session.add(attempt)
            plan.status = DeliveryStatus.PREPARED.value
            session.commit()
            return self._attempt_from_record(attempt)

    def update_delivery_attempt(
        self,
        attempt_id: str,
        status: DeliveryStatus,
        *,
        draft_id: str | None = None,
        remote_file_id: str | None = None,
        work_id: str | None = None,
        message: str = "",
        expected_statuses: set[DeliveryStatus] | None = None,
    ) -> DeliveryAttempt:
        with Session(self.engine) as session:
            if self.engine.dialect.name == "sqlite":
                session.execute(text("BEGIN IMMEDIATE"))
            attempt = session.get(DeliveryAttemptRecord, attempt_id)
            if attempt is None:
                raise KeyError(attempt_id)
            current = DeliveryStatus(attempt.status)
            if expected_statuses is not None and current not in expected_statuses:
                raise DeliveryReservationError("DELIVERY_STATE_CONFLICT")
            allowed: dict[DeliveryStatus, set[DeliveryStatus]] = {
                DeliveryStatus.PREPARED: {DeliveryStatus.SUBMITTED, DeliveryStatus.FAILED},
                DeliveryStatus.SUBMITTED: {
                    DeliveryStatus.SUBMITTED,
                    DeliveryStatus.PROCESSING,
                    DeliveryStatus.SUCCEEDED,
                    DeliveryStatus.FAILED,
                    DeliveryStatus.PARTIAL,
                    DeliveryStatus.UNKNOWN,
                },
                DeliveryStatus.PROCESSING: {
                    DeliveryStatus.SUBMITTED,
                    DeliveryStatus.PROCESSING,
                    DeliveryStatus.SUCCEEDED,
                    DeliveryStatus.FAILED,
                    DeliveryStatus.PARTIAL,
                    DeliveryStatus.UNKNOWN,
                },
                DeliveryStatus.UNKNOWN: {
                    DeliveryStatus.UNKNOWN,
                    DeliveryStatus.PROCESSING,
                    DeliveryStatus.SUCCEEDED,
                    DeliveryStatus.FAILED,
                    DeliveryStatus.PARTIAL,
                },
                DeliveryStatus.PARTIAL: {
                    DeliveryStatus.PARTIAL,
                    DeliveryStatus.PROCESSING,
                    DeliveryStatus.SUCCEEDED,
                    DeliveryStatus.FAILED,
                    DeliveryStatus.UNKNOWN,
                },
            }
            if status not in allowed.get(current, set()):
                raise DeliveryReservationError("DELIVERY_STATE_TRANSITION_INVALID")
            attempt.status = status.value
            if draft_id is not None:
                if attempt.draft_id not in {None, draft_id}:
                    raise DeliveryReservationError("DELIVERY_REMOTE_ID_CONFLICT")
                attempt.draft_id = self._validate_remote_id(draft_id, 120)
            if remote_file_id is not None:
                if attempt.remote_file_id not in {None, remote_file_id}:
                    raise DeliveryReservationError("DELIVERY_REMOTE_ID_CONFLICT")
                attempt.remote_file_id = self._validate_remote_id(remote_file_id, 300)
            if work_id is not None:
                if attempt.work_id not in {None, work_id}:
                    raise DeliveryReservationError("DELIVERY_REMOTE_ID_CONFLICT")
                attempt.work_id = self._validate_remote_id(work_id, 120)
            attempt.message = self._sanitize_message(message)
            if status in {
                DeliveryStatus.SUCCEEDED,
                DeliveryStatus.FAILED,
                DeliveryStatus.PARTIAL,
                DeliveryStatus.UNKNOWN,
                DeliveryStatus.NOOP,
            }:
                attempt.finished_at = utc_now()
            else:
                attempt.finished_at = None
            plan = session.get(DeliveryPlanRecord, attempt.plan_id)
            if plan is not None:
                plan.status = status.value
            session.commit()
            return self._attempt_from_record(attempt)

    def get_delivery_attempt(self, attempt_id: str) -> DeliveryAttempt | None:
        with Session(self.engine) as session:
            record = session.get(DeliveryAttemptRecord, attempt_id)
            return self._attempt_from_record(record) if record else None

    def list_delivery_attempts(
        self, plan_id: str, *, limit: int = 100, offset: int = 0
    ) -> builtins.list[DeliveryAttempt]:
        if not 1 <= limit <= 100 or not 0 <= offset <= 100_000:
            raise ValueError("DELIVERY_PAGINATION_INVALID")
        with Session(self.engine) as session:
            records = session.scalars(
                select(DeliveryAttemptRecord)
                .where(DeliveryAttemptRecord.plan_id == plan_id)
                .order_by(DeliveryAttemptRecord.started_at.desc())
                .limit(limit)
                .offset(offset)
            ).all()
            return [self._attempt_from_record(record) for record in records]

    @staticmethod
    def _plan_from_record(record: DeliveryPlanRecord) -> DeliveryPlan:
        plan = DeliveryPlan.model_validate_json(record.payload)
        created_matches = plan.created_at.replace(tzinfo=None) == record.created_at.replace(
            tzinfo=None
        )
        expires_matches = plan.expires_at.replace(tzinfo=None) == record.expires_at.replace(
            tzinfo=None
        )
        if (
            plan.id != record.id
            or plan.logical_key != record.logical_key
            or plan.case_id != record.case_id
            or not created_matches
            or not expires_matches
            or plan.plan_sha256 != record.plan_sha256
            or plan.artifact_sha256 != record.artifact_sha256
        ):
            raise DeliveryReservationError("DELIVERY_PLAN_RECORD_INTEGRITY")
        return plan.model_copy(update={"status": DeliveryStatus(record.status)})

    @staticmethod
    def _attempt_from_record(record: DeliveryAttemptRecord) -> DeliveryAttempt:
        return DeliveryAttempt(
            id=record.id,
            plan_id=record.plan_id,
            status=DeliveryStatus(record.status),
            started_at=record.started_at,
            finished_at=record.finished_at,
            draft_id=record.draft_id,
            remote_file_id=record.remote_file_id,
            work_id=record.work_id,
            message=record.message,
        )

    @staticmethod
    def _sanitize_message(message: object) -> str:
        value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+\-/]+=*", "Bearer [REDACTED]", str(message))
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)[:500]

    @staticmethod
    def _validate_remote_id(value: str, limit: int) -> str:
        if len(value) > limit or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", value):
            raise DeliveryReservationError("DELIVERY_REMOTE_ID_INVALID")
        return value

    def add_review(self, case_id: str, review: ReviewDecision) -> AnalysisCase:
        with Session(self.engine) as session:
            if self.engine.dialect.name == "sqlite":
                session.execute(text("BEGIN IMMEDIATE"))
            record = session.get(CaseRecord, case_id)
            if record is None:
                raise KeyError(case_id)
            case = AnalysisCase.model_validate_json(record.payload)
            finding_ids = {finding.id for finding in case.findings}
            object_ids = {
                str(obj.get("id"))
                for obj in case.candidate.raw.get("objects", [])
                if isinstance(obj, dict) and obj.get("id")
            }
            if review.finding_id and review.finding_id not in finding_ids:
                raise ReviewNotAllowed("Review references an unknown finding")
            if review.object_id and review.object_id not in object_ids:
                raise ReviewNotAllowed("Review references an unknown candidate object")
            if review.action == "edit":
                raise ReviewNotAllowed("Edits require a corrected candidate and a complete rerun")
            if review.action == "accept":
                if not review.object_id:
                    raise ReviewNotAllowed("Accept requires an object_id")
                if not review.comment.strip():
                    raise ReviewNotAllowed("Accept requires an analyst rationale")
                if case.verdict in {Verdict.REJECT, Verdict.QUARANTINE}:
                    raise ReviewNotAllowed(f"{case.verdict.value} cases cannot be accepted")
                if (
                    not case.candidate.is_valid
                    or case.candidate.validation.status != ValidationStatus.EXECUTED
                ):
                    raise ReviewNotAllowed(
                        "Objects cannot be accepted without successful validation"
                    )
                hard_findings = [
                    finding
                    for finding in case.findings
                    if finding.severity.value in {"high", "critical"}
                    and (
                        review.object_id in finding.object_ids
                        or review.finding_id == finding.id
                        or not finding.object_ids
                    )
                ]
                if hard_findings:
                    raise ReviewNotAllowed("High or critical findings require correction and rerun")
            current_snapshot = analysis_snapshot_sha256(case)
            stored_snapshot = case.metadata.get("analysis_snapshot_sha256")
            if stored_snapshot != current_snapshot:
                raise ReviewNotAllowed("Analysis snapshot integrity failed; rerun analysis")
            if review.analysis_snapshot_sha256 not in {None, current_snapshot}:
                raise ReviewNotAllowed("Review references a stale analysis snapshot")
            review = review.model_copy(update={"analysis_snapshot_sha256": current_snapshot})
            case.reviews.append(review)
            case.audit.append(
                self.make_event(
                    case, "review.recorded", review.analyst, review.model_dump(mode="json")
                )
            )
            record.verdict = case.verdict.value
            record.payload = case.model_dump_json()
            session.commit()
            return case

    def append_audit(
        self, case_id: str, event_type: str, actor: str, payload: dict[str, Any]
    ) -> AuditEvent:
        with Session(self.engine) as session:
            if self.engine.dialect.name == "sqlite":
                session.execute(text("BEGIN IMMEDIATE"))
            record = session.get(CaseRecord, case_id)
            if record is None:
                raise KeyError(case_id)
            case = AnalysisCase.model_validate_json(record.payload)
            event = self.make_event(case, event_type, actor, payload)
            case.audit.append(event)
            record.verdict = case.verdict.value
            record.payload = case.model_dump_json()
            session.commit()
            return event

    @staticmethod
    def verify_audit_chain(case: AnalysisCase) -> bool:
        previous_hash: str | None = None
        for event in case.audit:
            if event.case_id != case.id or event.previous_hash != previous_hash:
                return False
            canonical = json.dumps(
                {
                    "case_id": event.case_id,
                    "event_type": event.event_type,
                    "actor": event.actor,
                    "timestamp": event.timestamp.isoformat(),
                    "payload": event.payload,
                    "previous_hash": event.previous_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            if hashlib.sha256(canonical.encode()).hexdigest() != event.event_hash:
                return False
            previous_hash = event.event_hash
        return bool(case.audit)

    @staticmethod
    def make_event(
        case: AnalysisCase, event_type: str, actor: str, payload: dict[str, Any]
    ) -> AuditEvent:
        previous_hash = case.audit[-1].event_hash if case.audit else None
        timestamp = utc_now()
        canonical = json.dumps(
            {
                "case_id": case.id,
                "event_type": event_type,
                "actor": actor,
                "timestamp": timestamp.isoformat(),
                "payload": payload,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return AuditEvent(
            id=f"audit--{uuid4()}",
            case_id=case.id,
            event_type=event_type,
            actor=actor,
            timestamp=timestamp,
            payload=payload,
            previous_hash=previous_hash,
            event_hash=hashlib.sha256(canonical.encode()).hexdigest(),
        )
