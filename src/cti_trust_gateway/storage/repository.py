"""SQLite persistence for cases, reviews, and hash-chained audit events."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy.pool import NullPool

from cti_trust_gateway.domain.models import (
    AnalysisCase,
    AuditEvent,
    ReviewDecision,
    ValidationStatus,
    Verdict,
    utc_now,
)


class ReviewNotAllowed(ValueError):
    pass


class Base(DeclarativeBase):
    pass


class CaseRecord(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    created_at: Mapped[Any] = mapped_column(DateTime(timezone=True))
    verdict: Mapped[str] = mapped_column(String(20), index=True)
    payload: Mapped[str] = mapped_column(Text)


class Repository:
    def __init__(self, database_url: str = "sqlite:///data/runtime/gateway.db") -> None:
        if database_url.startswith("sqlite:///"):
            db_path = Path(database_url.removeprefix("sqlite:///"))
            db_path.parent.mkdir(parents=True, exist_ok=True)
        engine_options: dict[str, Any] = {}
        if database_url.startswith("sqlite:"):
            engine_options["poolclass"] = NullPool
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

    def list(self) -> list[AnalysisCase]:
        with Session(self.engine) as session:
            records = session.scalars(
                select(CaseRecord).order_by(CaseRecord.created_at.desc())
            ).all()
            return [AnalysisCase.model_validate_json(record.payload) for record in records]

    def add_review(self, case_id: str, review: ReviewDecision) -> AnalysisCase:
        case = self.get(case_id)
        if case is None:
            raise KeyError(case_id)
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
                raise ReviewNotAllowed("Objects cannot be accepted without successful validation")
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
        case.reviews.append(review)
        case.audit.append(
            self.make_event(case, "review.recorded", review.analyst, review.model_dump(mode="json"))
        )
        self.save(case)
        return case

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
