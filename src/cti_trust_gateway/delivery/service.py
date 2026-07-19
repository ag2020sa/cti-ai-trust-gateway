"""Side-effect-free planning and explicitly gated OpenCTI Draft execution."""

from __future__ import annotations

import re
from datetime import UTC, timedelta

from cti_trust_gateway.compatibility.profile import OpenCTIProfile
from cti_trust_gateway.core.canonical import canonical_sha256
from cti_trust_gateway.delivery.artifact import ApprovedArtifactBuilder, ArtifactAssessment
from cti_trust_gateway.delivery.config import OpenCTIConfig, OpenCTIConfigError
from cti_trust_gateway.delivery.security import OpenCTISecurityError, parse_destination
from cti_trust_gateway.delivery.transport import (
    OpenCTIAdapter,
    OpenCTITransportError,
    StrictOpenCTIAdapter,
    safe_transport_message,
)
from cti_trust_gateway.domain.models import (
    DeliveryGates,
    DeliveryOperation,
    DeliveryPlan,
    DeliveryReceipt,
    DeliveryStatus,
    DestinationFingerprint,
    utc_now,
)
from cti_trust_gateway.storage.repository import DeliveryReservationError, Repository

FULL_SHA256 = re.compile(r"[0-9a-f]{64}")


class DeliveryGateError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _plan_digest_payload(plan: DeliveryPlan) -> dict[str, object]:
    return plan.model_dump(
        mode="json",
        exclude={"status", "plan_sha256"},
    )


def verify_plan_hash(plan: DeliveryPlan) -> bool:
    return (
        plan.id == f"plan--{plan.logical_key}"
        and canonical_sha256(_plan_digest_payload(plan)) == plan.plan_sha256
    )


class OpenCTIDeliveryService:
    def __init__(
        self,
        repository: Repository,
        profile: OpenCTIProfile,
        config: OpenCTIConfig,
        *,
        adapter: OpenCTIAdapter | None = None,
    ) -> None:
        self.repository = repository
        self.profile = profile
        self.config = config
        self.artifacts = ApprovedArtifactBuilder(repository, profile)
        self.adapter = adapter or StrictOpenCTIAdapter(config)

    def check(self, case_id: str) -> ArtifactAssessment:
        return self.artifacts.build(case_id)

    def create_plan(self, case_id: str) -> DeliveryPlan:
        case = self.repository.get(case_id)
        if case is None:
            raise KeyError(case_id)
        assessment = self.check(case_id)
        blockers = list(assessment.blockers)
        if self.config.expected_version != self.profile.metadata.platform_version:
            blockers.append("OPENCTI_VERSION_MISMATCH")
        try:
            target = parse_destination(self.config)
            destination = self.config.fingerprint(target.origin)
        except (OpenCTIConfigError, OpenCTISecurityError) as exc:
            blockers.append(exc.code)
            destination = DestinationFingerprint(
                origin="",
                expected_version=self.config.expected_version,
                import_connector_id=self.config.import_connector_id,
                import_connector_name=self.config.import_connector_name,
                allowlist_sha256=canonical_sha256(self.config.host_allowlist),
            )
        artifact = assessment.artifact
        if artifact is not None:
            if len(artifact.included_object_ids) > self.config.max_objects:
                blockers.append("OPENCTI_LIMIT_EXCEEDED")
            if artifact.size_bytes > self.config.max_bytes:
                blockers.append("OPENCTI_LIMIT_EXCEEDED")
        marking_ids = tuple(sorted(set(artifact.marking_ids) if artifact is not None else set()))
        options = self.config.delivery_options()
        operations = self._operations(case_id, artifact.artifact_sha256 if artifact else "")
        artifact_sha256 = artifact.artifact_sha256 if artifact else ""
        logical_key = canonical_sha256(
            {
                "destination": destination.model_dump(mode="json"),
                "case_id": case_id,
                "source_sha256": case.source.sha256,
                "candidate_sha256": str(case.metadata.get("candidate_sha256", "")),
                "validation_sha256": str(case.candidate.validation.schema_sha256 or ""),
                "policy_sha256": str(case.metadata.get("policy_sha256", "")),
                "approval_snapshot": assessment.review_snapshot_sha256,
                "bundle_sha256": artifact_sha256,
                "profile_sha256": self.profile.metadata.profile_sha256,
                "marking_ids": marking_ids,
                "options": options.model_dump(mode="json"),
                "mode": "opencti-draft",
            }
        )
        now = utc_now()
        plan_data: dict[str, object] = {
            "id": f"plan--{logical_key}",
            "logical_key": logical_key,
            "case_id": case_id,
            "mode": "opencti-draft",
            "created_at": now,
            "expires_at": now + timedelta(seconds=self.config.plan_ttl_seconds),
            "source_sha256": case.source.sha256,
            "candidate_sha256": str(case.metadata.get("candidate_sha256", "")),
            "validation_sha256": str(case.candidate.validation.schema_sha256 or ""),
            "policy_sha256": str(case.metadata.get("policy_sha256", "")),
            "review_snapshot_sha256": assessment.review_snapshot_sha256,
            "profile_id": self.profile.metadata.id,
            "profile_sha256": self.profile.metadata.profile_sha256,
            "artifact_id": artifact.id if artifact else "",
            "artifact_sha256": artifact_sha256,
            "graph_sha256": artifact.graph_sha256 if artifact else "",
            "artifact_size_bytes": artifact.size_bytes if artifact else 0,
            "included_object_ids": artifact.included_object_ids if artifact else (),
            "excluded_object_ids": assessment.excluded_object_ids,
            "exclusion_reasons": assessment.exclusion_reasons,
            "marking_ids": marking_ids,
            "destination": destination,
            "options": options,
            "operations": operations,
            "blockers": tuple(sorted(set(blockers))),
            "warnings": (
                "Dry-run is the default; network is used only by deliver --execute.",
                "OpenCTI Draft still requires separate manual approval.",
            ),
            "status": DeliveryStatus.BLOCKED if blockers else DeliveryStatus.PREPARED,
            "plan_sha256": "0" * 64,
            "gates": DeliveryGates(
                valid_stix=assessment.gates.valid_stix,
                opencti_compatible=assessment.gates.opencti_compatible,
                evidence_verified=assessment.gates.evidence_verified,
                delivery_authorized=not blockers,
                reasons=tuple(sorted(set(blockers))),
            ),
        }
        provisional = DeliveryPlan.model_validate(plan_data)
        plan_sha256 = canonical_sha256(_plan_digest_payload(provisional))
        plan = provisional.model_copy(update={"plan_sha256": plan_sha256})
        previous = self.repository.get_delivery_plan(plan.id)
        stored = self.repository.save_delivery_plan(plan)
        if previous is None or previous.created_at != stored.created_at:
            action = "opencti.plan.created" if previous is None else "opencti.plan.refreshed"
            self.repository.append_audit(
                case_id,
                action,
                "gateway",
                {
                    "plan_id": stored.id,
                    "plan_sha256": stored.plan_sha256,
                    "status": stored.status.value,
                    "artifact_sha256": stored.artifact_sha256,
                },
            )
        return stored

    def execute(self, plan_id: str, confirmation_sha256: str) -> DeliveryReceipt:
        plan = self._execution_gates(plan_id, confirmation_sha256)
        attempt = self.repository.reserve_delivery_attempt(plan.id)
        if attempt.status == DeliveryStatus.NOOP:
            return DeliveryReceipt(
                plan_id=plan.id,
                attempt_id=attempt.id,
                status=DeliveryStatus.NOOP,
                message=attempt.message,
            )
        try:
            assessment = self.check(plan.case_id)
            artifact = assessment.artifact
            if artifact is None or assessment.blockers:
                raise DeliveryGateError("DELIVERY_SNAPSHOT_STALE")
            self._match_artifact(plan, artifact)
            capabilities = self.adapter.probe()
            if (
                capabilities.origin != plan.destination.origin
                or capabilities.platform_version != plan.destination.expected_version
                or capabilities.connector_id != plan.destination.import_connector_id
                or capabilities.connector_name != plan.destination.import_connector_name
                or not set(plan.marking_ids).issubset(capabilities.marking_id_map)
            ):
                raise DeliveryGateError("OPENCTI_CAPABILITY_MISMATCH")
            self.repository.update_delivery_attempt(
                attempt.id,
                DeliveryStatus.SUBMITTED,
                message="Mutation boundary durably entered; automatic retry is disabled",
                expected_statuses={DeliveryStatus.PREPARED},
            )

            def progress(
                status: DeliveryStatus,
                draft_id: str | None,
                remote_file_id: str | None,
                work_id: str | None,
                message: str,
            ) -> None:
                try:
                    self.repository.update_delivery_attempt(
                        attempt.id,
                        status,
                        draft_id=draft_id,
                        remote_file_id=remote_file_id,
                        work_id=work_id,
                        message=message,
                    )
                except DeliveryReservationError as exc:
                    raise OpenCTITransportError(
                        "DELIVERY_PERSISTENCE_UNKNOWN", ambiguous=True
                    ) from exc

            receipt = self.adapter.deliver(artifact, plan, capabilities, attempt.id, progress)
            updated = self.repository.update_delivery_attempt(
                attempt.id,
                receipt.status,
                draft_id=receipt.draft_id,
                remote_file_id=receipt.remote_file_id,
                work_id=receipt.work_id,
                message=receipt.message,
            )
            self._audit_attempt(plan, updated.status, updated.id, updated.draft_id, updated.work_id)
            return receipt
        except (DeliveryGateError, OpenCTIConfigError, OpenCTISecurityError) as exc:
            updated = self.repository.update_delivery_attempt(
                attempt.id, DeliveryStatus.FAILED, message=exc.code
            )
            self._audit_attempt(plan, updated.status, updated.id, updated.draft_id, updated.work_id)
            raise
        except OpenCTITransportError as exc:
            current = self.repository.get_delivery_attempt(attempt.id)
            has_draft = bool(current and current.draft_id)
            status = (
                DeliveryStatus.FAILED
                if current is not None and current.status == DeliveryStatus.PREPARED
                else DeliveryStatus.UNKNOWN
                if exc.ambiguous
                else DeliveryStatus.PARTIAL
                if has_draft
                else DeliveryStatus.FAILED
            )
            updated = self.repository.update_delivery_attempt(
                attempt.id, status, message=safe_transport_message(exc)
            )
            self._audit_attempt(plan, updated.status, updated.id, updated.draft_id, updated.work_id)
            raise

    def reconcile(self, attempt_id: str) -> DeliveryReceipt:
        attempt = self.repository.get_delivery_attempt(attempt_id)
        if attempt is None:
            raise KeyError(attempt_id)
        plan = self.repository.get_delivery_plan(attempt.plan_id)
        if plan is None:
            raise KeyError(attempt.plan_id)
        if attempt.status not in {
            DeliveryStatus.PREPARED,
            DeliveryStatus.SUBMITTED,
            DeliveryStatus.PROCESSING,
            DeliveryStatus.UNKNOWN,
            DeliveryStatus.PARTIAL,
        }:
            raise DeliveryGateError("DELIVERY_RECONCILIATION_NOT_REQUIRED")
        if attempt.status == DeliveryStatus.PREPARED:
            updated = self.repository.update_delivery_attempt(
                attempt.id,
                DeliveryStatus.FAILED,
                message="Preflight reservation explicitly abandoned before mutation boundary",
                expected_statuses={DeliveryStatus.PREPARED},
            )
            return DeliveryReceipt(
                plan_id=plan.id,
                attempt_id=attempt.id,
                status=updated.status,
                message=updated.message,
            )
        self.config.require_execution_secrets()
        if self.config.expected_version != self.profile.metadata.platform_version:
            raise DeliveryGateError("OPENCTI_VERSION_MISMATCH")
        target = parse_destination(self.config)
        if (
            self.config.fingerprint(target.origin) != plan.destination
            or self.config.delivery_options() != plan.options
        ):
            raise DeliveryGateError("OPENCTI_DESTINATION_MISMATCH")
        if not attempt.work_id:
            raise DeliveryGateError("DELIVERY_RECONCILIATION_UNAVAILABLE")
        capabilities = self.adapter.probe()
        if capabilities.connector_id != plan.destination.import_connector_id:
            raise DeliveryGateError("OPENCTI_CAPABILITY_MISMATCH")
        status = self.adapter.reconcile(attempt.work_id)
        updated = self.repository.update_delivery_attempt(
            attempt.id,
            status,
            draft_id=attempt.draft_id,
            remote_file_id=attempt.remote_file_id,
            work_id=attempt.work_id,
            message="Explicit reconciliation completed",
        )
        self._audit_attempt(plan, updated.status, updated.id, updated.draft_id, updated.work_id)
        return DeliveryReceipt(
            plan_id=plan.id,
            attempt_id=attempt.id,
            status=updated.status,
            draft_id=updated.draft_id,
            remote_file_id=updated.remote_file_id,
            work_id=updated.work_id,
            message=updated.message,
        )

    def _execution_gates(self, plan_id: str, confirmation_sha256: str) -> DeliveryPlan:
        if not FULL_SHA256.fullmatch(confirmation_sha256):
            raise DeliveryGateError("DELIVERY_CONFIRMATION_INVALID")
        try:
            plan = self.repository.get_delivery_plan(plan_id)
        except DeliveryReservationError as exc:
            raise DeliveryGateError("DELIVERY_PLAN_INTEGRITY") from exc
        if plan is None:
            raise KeyError(plan_id)
        if confirmation_sha256 != plan.plan_sha256:
            raise DeliveryGateError("DELIVERY_CONFIRMATION_MISMATCH")
        if not verify_plan_hash(plan):
            raise DeliveryGateError("DELIVERY_PLAN_INTEGRITY")
        if plan.status not in {DeliveryStatus.PREPARED, DeliveryStatus.SUCCEEDED} or plan.blockers:
            raise DeliveryGateError("DELIVERY_PLAN_BLOCKED")
        if plan.status != DeliveryStatus.SUCCEEDED and utc_now() > plan.expires_at.astimezone(UTC):
            raise DeliveryGateError("DELIVERY_PLAN_STALE")
        self.config.require_execution_secrets()
        if self.config.expected_version != self.profile.metadata.platform_version:
            raise DeliveryGateError("OPENCTI_VERSION_MISMATCH")
        target = parse_destination(self.config)
        if (
            self.config.fingerprint(target.origin) != plan.destination
            or self.config.delivery_options() != plan.options
        ):
            raise DeliveryGateError("OPENCTI_DESTINATION_MISMATCH")
        assessment = self.check(plan.case_id)
        if assessment.artifact is None or assessment.blockers:
            raise DeliveryGateError("DELIVERY_SNAPSHOT_STALE")
        self._match_artifact(plan, assessment.artifact)
        return plan

    @staticmethod
    def _match_artifact(plan: DeliveryPlan, artifact: object) -> None:
        expected = {
            "source_sha256": plan.source_sha256,
            "candidate_sha256": plan.candidate_sha256,
            "validation_sha256": plan.validation_sha256,
            "policy_sha256": plan.policy_sha256,
            "review_snapshot_sha256": plan.review_snapshot_sha256,
            "profile_sha256": plan.profile_sha256,
            "artifact_sha256": plan.artifact_sha256,
            "graph_sha256": plan.graph_sha256,
        }
        if any(getattr(artifact, name, None) != value for name, value in expected.items()):
            raise DeliveryGateError("DELIVERY_SNAPSHOT_STALE")

    @staticmethod
    def _operations(case_id: str, artifact_sha256: str) -> tuple[DeliveryOperation, ...]:
        if not artifact_sha256:
            return ()
        return (
            DeliveryOperation(
                ordinal=1,
                kind="create-draft",
                request_sha256=canonical_sha256({"case_id": case_id, "manual_approval": True}),
                description="Create an isolated OpenCTI Draft workspace",
            ),
            DeliveryOperation(
                ordinal=2,
                kind="upload-bundle",
                request_sha256=canonical_sha256(
                    {
                        "artifact_sha256": artifact_sha256,
                        "validation_mode": "draft",
                        "mime": "application/json",
                    }
                ),
                description=(
                    "Upload the exact approved artifact bytes to the pinned import connector"
                ),
            ),
            DeliveryOperation(
                ordinal=3,
                kind="poll-work",
                request_sha256=canonical_sha256({"bounded": True, "automatic_validation": False}),
                description="Poll the import work without approving the Draft",
            ),
        )

    def _audit_attempt(
        self,
        plan: DeliveryPlan,
        status: DeliveryStatus,
        attempt_id: str,
        draft_id: str | None,
        work_id: str | None,
    ) -> None:
        self.repository.append_audit(
            plan.case_id,
            "opencti.delivery.status",
            "gateway",
            {
                "plan_id": plan.id,
                "attempt_id": attempt_id,
                "status": status.value,
                "draft_id": draft_id,
                "work_id": work_id,
            },
        )
