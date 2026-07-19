from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy.orm import Session

from cti_trust_gateway.compatibility import load_opencti_profile
from cti_trust_gateway.core.service import GatewayService
from cti_trust_gateway.delivery.config import OpenCTIConfig, OpenCTIConfigError
from cti_trust_gateway.delivery.security import DestinationTarget
from cti_trust_gateway.delivery.service import (
    DeliveryGateError,
    OpenCTIDeliveryService,
    verify_plan_hash,
)
from cti_trust_gateway.delivery.transport import (
    CREATE_DRAFT_MUTATION,
    UPLOAD_DRAFT_MUTATION,
    OpenCTITransportError,
    StrictOpenCTIAdapter,
)
from cti_trust_gateway.domain.models import (
    DeliveryReceipt,
    DeliveryStatus,
    DestinationCapabilities,
    ReviewDecision,
    utc_now,
)
from cti_trust_gateway.storage.repository import (
    DeliveryPlanRecord,
    DeliveryReservationError,
)
from tests.conftest import make_bundle, sid

CONNECTOR_ID = "12345678-1234-4234-8234-123456789abc"


def _config(**changes: object) -> OpenCTIConfig:
    values: dict[str, object] = {
        "enabled": True,
        "url": "https://127.0.0.1",
        "token": SecretStr("synthetic-token"),
        "import_connector_id": CONNECTOR_ID,
        "host_allowlist": ("127.0.0.1",),
        "allow_loopback": True,
        "poll_attempts": 1,
        "poll_interval_seconds": 0,
    }
    values.update(changes)
    return OpenCTIConfig.model_validate(values)


def _case(service: GatewayService) -> object:
    return service.analyze(
        b"Observed 203.0.113.70.",
        "delivery.txt",
        make_bundle(
            [
                {
                    "type": "ipv4-addr",
                    "spec_version": "2.1",
                    "id": sid("ipv4-addr", "delivery-ip"),
                    "value": "203.0.113.70",
                }
            ],
            "delivery",
        ),
    )


def _capabilities(markings: dict[str, str] | None = None) -> DestinationCapabilities:
    return DestinationCapabilities(
        origin="https://127.0.0.1",
        platform_version="7.260715.0",
        connector_id=CONNECTOR_ID,
        connector_name="ImportFileStix",
        connector_type="INTERNAL_IMPORT_FILE",
        connector_scope=("application/json",),
        connector_active=True,
        marking_id_map=markings or {},
        fingerprint_sha256="f" * 64,
    )


class FakeAdapter:
    def __init__(self, *, fail: OpenCTITransportError | None = None) -> None:
        self.fail = fail
        self.probe_calls = 0
        self.deliver_calls = 0

    def probe(self) -> DestinationCapabilities:
        self.probe_calls += 1
        return _capabilities()

    def deliver(
        self,
        artifact: object,
        plan: object,
        capabilities: DestinationCapabilities,
        attempt_id: str,
        progress: Any,
    ) -> DeliveryReceipt:
        self.deliver_calls += 1
        progress(DeliveryStatus.PROCESSING, "draft--one", None, None, "created")
        if self.fail is not None:
            raise self.fail
        progress(
            DeliveryStatus.SUBMITTED,
            "draft--one",
            "import/global/file.json",
            "work--one",
            "submitted",
        )
        return DeliveryReceipt(
            plan_id=plan.id,
            attempt_id=attempt_id,
            status=DeliveryStatus.SUCCEEDED,
            draft_id="draft--one",
            remote_file_id="import/global/file.json",
            work_id="work--one",
            message="completed; manual approval remains",
        )

    def reconcile(self, work_id: str) -> DeliveryStatus:
        return DeliveryStatus.SUCCEEDED


def test_check_plan_status_history_and_api_reads_are_network_free(
    service: GatewayService, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(service)

    def network_forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("network must remain disabled")

    monkeypatch.setattr(socket, "getaddrinfo", network_forbidden)
    monkeypatch.setattr(socket, "create_connection", network_forbidden)
    delivery = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(enabled=False)
    )
    assessment = delivery.check(case.id)  # type: ignore[attr-defined]
    plan = delivery.create_plan(case.id)  # type: ignore[attr-defined]
    assert assessment.artifact is not None
    assert plan.status == DeliveryStatus.PREPARED
    assert verify_plan_hash(plan)
    assert delivery.repository.get_delivery_plan(plan.id) == plan
    assert delivery.repository.list_delivery_attempts(plan.id) == []
    assert delivery.create_plan(case.id).id == plan.id  # type: ignore[attr-defined]


def test_expired_unattempted_plan_is_explicitly_refreshed(service: GatewayService) -> None:
    case = _case(service)
    delivery = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(enabled=False)
    )
    plan = delivery.create_plan(case.id)  # type: ignore[attr-defined]
    old_time = utc_now() - timedelta(days=1)
    expired = plan.model_copy(
        update={"created_at": old_time, "expires_at": old_time + timedelta(seconds=1)}
    )
    with Session(service.repository.engine) as session:
        record = session.get(DeliveryPlanRecord, plan.id)
        assert record is not None
        record.created_at = expired.created_at
        record.expires_at = expired.expires_at
        record.payload = expired.model_dump_json()
        session.commit()

    refreshed = delivery.create_plan(case.id)  # type: ignore[attr-defined]
    assert refreshed.id == plan.id
    assert refreshed.created_at > expired.expires_at
    assert refreshed.expires_at > refreshed.created_at
    assert verify_plan_hash(refreshed)
    assert service.repository.list_delivery_attempts(plan.id) == []
    persisted = service.repository.get(case.id)  # type: ignore[attr-defined]
    assert persisted is not None
    assert persisted.audit[-1].event_type == "opencti.plan.refreshed"


def test_full_confirmation_enabled_env_and_fresh_snapshot_are_all_required(
    service: GatewayService,
) -> None:
    case = _case(service)
    disabled = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(enabled=False)
    )
    plan = disabled.create_plan(case.id)  # type: ignore[attr-defined]
    with pytest.raises(DeliveryGateError, match="DELIVERY_CONFIRMATION_INVALID"):
        disabled.execute(plan.id, plan.plan_sha256[:12])
    with pytest.raises(OpenCTIConfigError, match="OPENCTI_DELIVERY_DISABLED"):
        disabled.execute(plan.id, plan.plan_sha256)

    service.repository.add_review(
        case.id,  # type: ignore[attr-defined]
        ReviewDecision(
            id="review--stale",
            case_id=case.id,  # type: ignore[attr-defined]
            object_id=case.candidate.raw["objects"][0]["id"],  # type: ignore[attr-defined]
            action="reject",
            comment="Invalidate the persisted approval snapshot",
        ),
    )
    enabled = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(), adapter=FakeAdapter()
    )
    with pytest.raises(DeliveryGateError, match="DELIVERY_SNAPSHOT_STALE"):
        enabled.execute(plan.id, plan.plan_sha256)


def test_success_is_recorded_once_and_equivalent_execution_is_noop(
    service: GatewayService,
) -> None:
    case = _case(service)
    adapter = FakeAdapter()
    delivery = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(), adapter=adapter
    )
    plan = delivery.create_plan(case.id)  # type: ignore[attr-defined]
    receipt = delivery.execute(plan.id, plan.plan_sha256)
    assert receipt.status == DeliveryStatus.SUCCEEDED
    assert adapter.probe_calls == adapter.deliver_calls == 1
    second = delivery.execute(plan.id, plan.plan_sha256)
    assert second.status == DeliveryStatus.NOOP
    assert adapter.probe_calls == adapter.deliver_calls == 1
    statuses = [item.status for item in service.repository.list_delivery_attempts(plan.id)]
    assert statuses == [DeliveryStatus.NOOP, DeliveryStatus.SUCCEEDED]


def test_partial_or_ambiguous_submission_never_blindly_retries(
    service: GatewayService,
) -> None:
    case = _case(service)
    adapter = FakeAdapter(fail=OpenCTITransportError("synthetic explicit failure"))
    delivery = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(), adapter=adapter
    )
    plan = delivery.create_plan(case.id)  # type: ignore[attr-defined]
    with pytest.raises(OpenCTITransportError):
        delivery.execute(plan.id, plan.plan_sha256)
    attempts = service.repository.list_delivery_attempts(plan.id)
    assert attempts[0].status == DeliveryStatus.PARTIAL
    assert attempts[0].draft_id == "draft--one"
    with pytest.raises(DeliveryGateError, match="DELIVERY_PLAN_BLOCKED"):
        delivery.execute(plan.id, plan.plan_sha256)
    assert adapter.deliver_calls == 1


def test_sqlite_attempt_reservation_allows_only_one_executor(service: GatewayService) -> None:
    case = _case(service)
    delivery = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(enabled=False)
    )
    plan = delivery.create_plan(case.id)  # type: ignore[attr-defined]

    def reserve() -> str:
        try:
            return service.repository.reserve_delivery_attempt(plan.id).id
        except DeliveryReservationError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: reserve(), range(2)))
    assert sum(result.startswith("attempt--") for result in results) == 1
    assert "DELIVERY_RECONCILIATION_REQUIRED" in results


class RecordingAdapter(StrictOpenCTIAdapter):
    def __init__(self, config: OpenCTIConfig, responses: list[dict[str, Any]]) -> None:
        super().__init__(config)
        self.responses = responses
        self.requests: list[tuple[bytes, str]] = []

    def _request(
        self,
        target: DestinationTarget,
        body: bytes,
        content_type: str,
        *,
        mutation: bool = False,
    ) -> dict[str, Any]:
        self.requests.append((body, content_type))
        return self.responses.pop(0)


def test_official_multipart_contract_sends_exact_artifact_bytes(
    service: GatewayService, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(service)
    config = _config()
    planning = OpenCTIDeliveryService(service.repository, load_opencti_profile(), config)
    plan = planning.create_plan(case.id)  # type: ignore[attr-defined]
    assessment = planning.check(case.id)  # type: ignore[attr-defined]
    assert assessment.artifact is not None
    adapter = RecordingAdapter(
        config,
        [
            {"draftWorkspaceAdd": {"id": "draft--contract"}},
            {
                "uploadAndAskJobImport": {
                    "id": "import/global/contract.json",
                    "name": "contract.json",
                    "works": [{"id": "work--contract", "status": "wait"}],
                }
            },
            {"work": {"id": "work--contract", "status": "complete", "errors": []}},
        ],
    )
    target = DestinationTarget(
        scheme="https",
        host="127.0.0.1",
        port=443,
        origin="https://127.0.0.1",
        graphql_path="/graphql",
        addresses=("127.0.0.1",),
    )
    monkeypatch.setattr(
        "cti_trust_gateway.delivery.transport.resolve_destination", lambda config: target
    )
    receipt = adapter.deliver(
        assessment.artifact,
        plan,
        _capabilities(),
        "attempt--contract",
        lambda *args: None,
    )
    assert receipt.status == DeliveryStatus.SUCCEEDED
    assert len(adapter.requests) == 3
    create_body = adapter.requests[0][0]
    multipart_body, content_type = adapter.requests[1]
    create_payload = json.loads(create_body)
    assert create_payload["query"] == CREATE_DRAFT_MUTATION
    assert UPLOAD_DRAFT_MUTATION.splitlines()[0].encode() in multipart_body
    assert assessment.artifact.bundle_bytes() in multipart_body
    assert b'"validationMode":"draft"' in multipart_body
    assert b'"configuration":null' in multipart_body
    assert b'"noTriggerImport":false' in multipart_body
    assert content_type.startswith("multipart/form-data; boundary=cti-gateway-")
    prohibited = (b"import_bundle_from_json", b"stixBundlePush", b"bypass_validation")
    assert not any(value in multipart_body for value in prohibited)


class FakeSocket:
    def settimeout(self, timeout: int) -> None:
        self.timeout = timeout


class FakeResponse:
    def __init__(self, status: int, body: bytes, content_length: str | None = None) -> None:
        self.status = status
        self.body = body
        self.content_length = content_length

    def getheader(self, name: str) -> str | None:
        return self.content_length if name == "Content-Length" else None

    def read(self, amount: int) -> bytes:
        return self.body[:amount]


class FakeConnection:
    response = FakeResponse(200, b'{"data":{"about":{"version":"7.260715.0"}}}')
    raise_after_submit = False
    last_headers: dict[str, str] = {}

    def __init__(self, host: str, port: int, timeout: int) -> None:
        self.sock: object | None = None

    def request(self, *args: object, **kwargs: object) -> None:
        self.__class__.last_headers = dict(kwargs.get("headers", {}))  # type: ignore[arg-type]
        return None

    def getresponse(self) -> FakeResponse:
        if self.raise_after_submit:
            raise TimeoutError("synthetic timeout with Bearer secret")
        return self.response

    def close(self) -> None:
        return None


def test_redirect_bounds_invalid_json_and_timeout_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(max_response_bytes=32)
    adapter = StrictOpenCTIAdapter(config)
    target = DestinationTarget(
        scheme="http",
        host="127.0.0.1",
        port=8000,
        origin="http://127.0.0.1:8000",
        graphql_path="/graphql",
        addresses=("127.0.0.1",),
    )
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: FakeSocket())
    monkeypatch.setattr("http.client.HTTPConnection", FakeConnection)

    FakeConnection.response = FakeResponse(302, b"")
    with pytest.raises(OpenCTITransportError, match="OPENCTI_REDIRECT_BLOCKED"):
        adapter._request(target, b"{}", "application/json")
    FakeConnection.response = FakeResponse(200, b"x" * 40, "40")
    with pytest.raises(OpenCTITransportError, match="OPENCTI_RESPONSE_TOO_LARGE"):
        adapter._request(target, b"{}", "application/json")
    FakeConnection.response = FakeResponse(200, b"not-json")
    with pytest.raises(OpenCTITransportError, match="OPENCTI_RESPONSE_INVALID"):
        adapter._request(target, b"{}", "application/json")
    FakeConnection.raise_after_submit = True
    with pytest.raises(OpenCTITransportError) as captured:
        adapter._request(target, b"{}", "application/json", mutation=True)
    assert captured.value.code == "OPENCTI_SUBMISSION_UNKNOWN"
    assert captured.value.ambiguous is True
    assert "secret" not in str(captured.value)
    FakeConnection.raise_after_submit = False


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"about": {"version": "wrong"}}, "OPENCTI_VERSION_MISMATCH"),
        ({"connector": {"id": "wrong"}}, "OPENCTI_CONNECTOR_IDENTITY_MISMATCH"),
        ({"connector": {"connector_type": "EXTERNAL_IMPORT"}}, "OPENCTI_CONNECTOR_TYPE_MISMATCH"),
        ({"connector": {"active": False}}, "OPENCTI_CONNECTOR_INACTIVE"),
        ({"connector": {"connector_scope": ["text/csv"]}}, "OPENCTI_CONNECTOR_SCOPE_MISMATCH"),
    ],
)
def test_probe_fails_closed_on_capability_mismatch(
    monkeypatch: pytest.MonkeyPatch, change: dict[str, dict[str, Any]], code: str
) -> None:
    data: dict[str, Any] = {
        "about": {"version": "7.260715.0"},
        "connector": {
            "id": CONNECTOR_ID,
            "name": "ImportFileStix",
            "active": True,
            "connector_type": "INTERNAL_IMPORT_FILE",
            "connector_scope": ["application/json"],
        },
        "markingDefinitions": {"edges": []},
    }
    for key, values in change.items():
        data.setdefault(key, {}).update(values)
    adapter = RecordingAdapter(_config(), [data])
    monkeypatch.setattr(
        "cti_trust_gateway.delivery.transport.resolve_destination",
        lambda config: DestinationTarget(
            scheme="http",
            host="127.0.0.1",
            port=8000,
            origin="http://127.0.0.1:8000",
            graphql_path="/graphql",
            addresses=("127.0.0.1",),
        ),
    )
    with pytest.raises(OpenCTITransportError, match=code):
        adapter.probe()


def test_no_token_or_connection_failure_never_exposes_a_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = DestinationTarget(
        scheme="http",
        host="127.0.0.1",
        port=8000,
        origin="http://127.0.0.1:8000",
        graphql_path="/graphql",
        addresses=("127.0.0.1",),
    )
    with pytest.raises(OpenCTITransportError, match="OPENCTI_TOKEN_UNAVAILABLE"):
        StrictOpenCTIAdapter(_config(token=None))._request(target, b"{}", "application/json")

    def fail(*args: object, **kwargs: object) -> object:
        raise OSError("Bearer synthetic-token should be hidden")

    monkeypatch.setattr(socket, "create_connection", fail)
    with pytest.raises(OpenCTITransportError) as captured:
        StrictOpenCTIAdapter(_config())._request(target, b"{}", "application/json")
    assert captured.value.code == "OPENCTI_CONNECTION_FAILED"
    assert "synthetic-token" not in str(captured.value)


def test_blocked_limits_missing_case_and_empty_operation_plan(service: GatewayService) -> None:
    delivery = OpenCTIDeliveryService(
        service.repository,
        load_opencti_profile(),
        _config(max_objects=1, max_bytes=1),
    )
    with pytest.raises(KeyError):
        delivery.create_plan("case--missing")
    case = _case(service)
    plan = delivery.create_plan(case.id)  # type: ignore[attr-defined]
    assert plan.status == DeliveryStatus.BLOCKED
    assert plan.blockers == ("OPENCTI_LIMIT_EXCEEDED",)
    assert OpenCTIDeliveryService._operations(case.id, "") == ()  # type: ignore[attr-defined]

    invalid_config = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), OpenCTIConfig()
    )
    invalid_plan = invalid_config.create_plan(case.id)  # type: ignore[attr-defined]
    assert "OPENCTI_CONFIG_INCOMPLETE" in invalid_plan.blockers
    with pytest.raises(DeliveryGateError, match="DELIVERY_PLAN_BLOCKED"):
        invalid_config.execute(invalid_plan.id, invalid_plan.plan_sha256)


class ProbeFailureAdapter(FakeAdapter):
    def __init__(self, error: OpenCTITransportError) -> None:
        super().__init__()
        self.error = error

    def probe(self) -> DestinationCapabilities:
        raise self.error


def test_pre_draft_explicit_and_ambiguous_failures_map_to_failed_and_unknown(
    service: GatewayService,
) -> None:
    explicit_case = _case(service)
    explicit = OpenCTIDeliveryService(
        service.repository,
        load_opencti_profile(),
        _config(),
        adapter=ProbeFailureAdapter(OpenCTITransportError("explicit")),
    )
    explicit_plan = explicit.create_plan(explicit_case.id)  # type: ignore[attr-defined]
    with pytest.raises(OpenCTITransportError):
        explicit.execute(explicit_plan.id, explicit_plan.plan_sha256)
    assert (
        service.repository.list_delivery_attempts(explicit_plan.id)[0].status
        == DeliveryStatus.FAILED
    )

    ambiguous_case = _case(service)
    ambiguous = OpenCTIDeliveryService(
        service.repository,
        load_opencti_profile(),
        _config(),
        adapter=ProbeFailureAdapter(OpenCTITransportError("timeout", ambiguous=True)),
    )
    ambiguous_plan = ambiguous.create_plan(ambiguous_case.id)  # type: ignore[attr-defined]
    with pytest.raises(OpenCTITransportError):
        ambiguous.execute(ambiguous_plan.id, ambiguous_plan.plan_sha256)
    assert (
        service.repository.list_delivery_attempts(ambiguous_plan.id)[0].status
        == DeliveryStatus.FAILED
    )


def test_capability_mismatch_is_a_persisted_failed_attempt(service: GatewayService) -> None:
    case = _case(service)
    adapter = FakeAdapter()
    adapter.probe = lambda: _capabilities().model_copy(update={"origin": "https://wrong.example"})  # type: ignore[method-assign]
    delivery = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(), adapter=adapter
    )
    plan = delivery.create_plan(case.id)  # type: ignore[attr-defined]
    with pytest.raises(DeliveryGateError, match="OPENCTI_CAPABILITY_MISMATCH"):
        delivery.execute(plan.id, plan.plan_sha256)
    assert service.repository.list_delivery_attempts(plan.id)[0].status == DeliveryStatus.FAILED


def test_plan_gate_integrity_expiry_destination_and_confirmation_variants(
    service: GatewayService,
) -> None:
    case = _case(service)
    delivery = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(), adapter=FakeAdapter()
    )
    plan = delivery.create_plan(case.id)  # type: ignore[attr-defined]
    with pytest.raises(KeyError):
        delivery._execution_gates("plan--missing", "a" * 64)
    with pytest.raises(DeliveryGateError, match="DELIVERY_CONFIRMATION_MISMATCH"):
        delivery._execution_gates(plan.id, "a" * 64)
    OpenCTIDeliveryService._match_artifact(
        plan,
        delivery.check(case.id).artifact,  # type: ignore[arg-type,attr-defined]
    )
    with pytest.raises(DeliveryGateError, match="DELIVERY_SNAPSHOT_STALE"):
        OpenCTIDeliveryService._match_artifact(plan, object())

    changed_destination = OpenCTIDeliveryService(
        service.repository,
        load_opencti_profile(),
        _config(url="https://127.0.0.1:9000", host_allowlist=("127.0.0.1:9000",)),
        adapter=FakeAdapter(),
    )
    with pytest.raises(DeliveryGateError, match="OPENCTI_DESTINATION_MISMATCH"):
        changed_destination._execution_gates(plan.id, plan.plan_sha256)

    with Session(service.repository.engine) as session:
        record = session.get(DeliveryPlanRecord, plan.id)
        assert record is not None
        expired = plan.model_copy(update={"expires_at": utc_now() - timedelta(seconds=1)})
        record.payload = expired.model_dump_json()
        session.commit()
        with pytest.raises(DeliveryGateError, match="DELIVERY_PLAN_INTEGRITY"):
            delivery._execution_gates(plan.id, plan.plan_sha256)


def test_tampered_persisted_plan_hash_is_rejected(service: GatewayService) -> None:
    case = _case(service)
    delivery = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(), adapter=FakeAdapter()
    )
    plan = delivery.create_plan(case.id)  # type: ignore[attr-defined]
    with Session(service.repository.engine) as session:
        record = session.get(DeliveryPlanRecord, plan.id)
        assert record is not None
        record.payload = plan.model_copy(update={"artifact_sha256": "f" * 64}).model_dump_json()
        session.commit()
    with pytest.raises(DeliveryGateError, match="DELIVERY_PLAN_INTEGRITY"):
        delivery._execution_gates(plan.id, plan.plan_sha256)


def test_explicit_reconciliation_success_and_required_fields(service: GatewayService) -> None:
    case = _case(service)
    adapter = FakeAdapter()
    delivery = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(), adapter=adapter
    )
    plan = delivery.create_plan(case.id)  # type: ignore[attr-defined]
    attempt = service.repository.reserve_delivery_attempt(plan.id)
    abandoned = delivery.reconcile(attempt.id)
    assert abandoned.status == DeliveryStatus.FAILED
    attempt = service.repository.reserve_delivery_attempt(plan.id)
    service.repository.update_delivery_attempt(attempt.id, DeliveryStatus.SUBMITTED)
    attempt = service.repository.update_delivery_attempt(
        attempt.id,
        DeliveryStatus.UNKNOWN,
        draft_id="draft--reconcile",
        remote_file_id="import/global/reconcile.json",
        work_id="work--reconcile",
    )
    receipt = delivery.reconcile(attempt.id)
    assert receipt.status == DeliveryStatus.SUCCEEDED
    assert receipt.work_id == "work--reconcile"
    with pytest.raises(DeliveryGateError, match="DELIVERY_RECONCILIATION_NOT_REQUIRED"):
        delivery.reconcile(attempt.id)
    with pytest.raises(KeyError):
        delivery.reconcile("attempt--missing")


def _target(
    *,
    scheme: str = "http",
    addresses: tuple[str, ...] = ("127.0.0.1",),
    port: int | None = None,
) -> DestinationTarget:
    selected_port = port if port is not None else (443 if scheme == "https" else 8000)
    default_port = 443 if scheme == "https" else 80
    rendered_port = "" if selected_port == default_port else f":{selected_port}"
    return DestinationTarget(
        scheme=scheme,
        host="127.0.0.1",
        port=selected_port,
        origin=f"{scheme}://127.0.0.1{rendered_port}",
        graphql_path="/graphql",
        addresses=addresses,
    )


def test_successful_probe_parses_string_scope_and_marking_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marking = "marking-definition--green"
    data = {
        "about": {"version": "7.260715.0"},
        "connector": {
            "id": CONNECTOR_ID,
            "name": "ImportFileStix",
            "active": True,
            "connector_type": "INTERNAL_IMPORT_FILE",
            "connector_scope": "application/json,text/xml",
        },
        "markingDefinitions": {
            "edges": [
                {"node": {"id": "internal--green", "standard_id": marking}},
                {"node": None},
            ]
        },
    }
    adapter = RecordingAdapter(_config(), [data])
    monkeypatch.setattr(
        "cti_trust_gateway.delivery.transport.resolve_destination",
        lambda config: _target(scheme="https", addresses=("127.0.0.1",)),
    )
    capabilities = adapter.probe()
    assert capabilities.marking_id_map == {marking: "internal--green"}
    assert capabilities.connector_scope == ("application/json", "text/xml")

    missing_contract = RecordingAdapter(_config(), [{}])
    with pytest.raises(OpenCTITransportError, match="OPENCTI_PROBE_CONTRACT_MISMATCH"):
        missing_contract.probe()
    invalid_scope = RecordingAdapter(
        _config(),
        [
            {
                **data,
                "connector": {**data["connector"], "connector_scope": 7},
            }
        ],
    )
    with pytest.raises(OpenCTITransportError, match="OPENCTI_CONNECTOR_SCOPE_MISMATCH"):
        invalid_scope.probe()


def test_delivery_contract_rejects_artifact_marking_draft_upload_and_missing_work(
    service: GatewayService, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(service)
    config = _config()
    delivery = OpenCTIDeliveryService(service.repository, load_opencti_profile(), config)
    plan = delivery.create_plan(case.id)  # type: ignore[attr-defined]
    artifact = delivery.check(case.id).artifact  # type: ignore[attr-defined]
    assert artifact is not None
    monkeypatch.setattr(
        "cti_trust_gateway.delivery.transport.resolve_destination",
        lambda config: _target(scheme="https"),
    )
    adapter = RecordingAdapter(config, [])
    with pytest.raises(OpenCTITransportError, match="DELIVERY_ARTIFACT_MISMATCH"):
        adapter.deliver(
            artifact,
            plan.model_copy(update={"artifact_sha256": "0" * 64}),
            _capabilities(),
            "attempt--x",
            lambda *args: None,
        )
    draft_failure = RecordingAdapter(config, [{}])
    with pytest.raises(OpenCTITransportError, match="OPENCTI_DRAFT_CREATE_FAILED"):
        draft_failure.deliver(artifact, plan, _capabilities(), "attempt--x", lambda *args: None)
    marked_plan = plan.model_copy(update={"marking_ids": ("marking-definition--missing",)})
    marking_failure = RecordingAdapter(config, [{"draftWorkspaceAdd": {"id": "draft--one"}}])
    with pytest.raises(OpenCTITransportError, match="DELIVERY_ARTIFACT_MISMATCH"):
        marking_failure.deliver(
            artifact, marked_plan, _capabilities(), "attempt--x", lambda *args: None
        )
    upload_failure = RecordingAdapter(config, [{"draftWorkspaceAdd": {"id": "draft--one"}}, {}])
    with pytest.raises(OpenCTITransportError, match="OPENCTI_UPLOAD_FAILED"):
        upload_failure.deliver(artifact, plan, _capabilities(), "attempt--x", lambda *args: None)
    missing_work = RecordingAdapter(
        config,
        [
            {"draftWorkspaceAdd": {"id": "draft--one"}},
            {"uploadAndAskJobImport": {"id": "file--one", "works": None}},
        ],
    )
    receipt = missing_work.deliver(
        artifact, plan, _capabilities(), "attempt--x", lambda *args: None
    )
    assert receipt.status == DeliveryStatus.UNKNOWN


@pytest.mark.parametrize(
    ("work", "expected"),
    [
        (None, DeliveryStatus.UNKNOWN),
        ({"status": "complete", "errors": ["failure"]}, DeliveryStatus.FAILED),
        ({"status": "wait", "errors": []}, DeliveryStatus.PROCESSING),
        ({"status": "unexpected", "errors": []}, DeliveryStatus.UNKNOWN),
    ],
)
def test_transport_reconciliation_status_mapping(
    monkeypatch: pytest.MonkeyPatch, work: object, expected: DeliveryStatus
) -> None:
    adapter = RecordingAdapter(_config(), [{"work": work}])
    monkeypatch.setattr(
        "cti_trust_gateway.delivery.transport.resolve_destination", lambda config: _target()
    )
    assert adapter.reconcile("work--one") == expected


def test_low_level_http_status_body_graphql_and_tls_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(max_response_bytes=32)
    adapter = StrictOpenCTIAdapter(config)
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: FakeSocket())
    monkeypatch.setattr("http.client.HTTPConnection", FakeConnection)
    with pytest.raises(OpenCTITransportError, match="OPENCTI_DNS_FAILED"):
        adapter._request(_target(addresses=()), b"{}", "application/json")
    FakeConnection.response = FakeResponse(500, b"failure")
    with pytest.raises(OpenCTITransportError, match="OPENCTI_HTTP_ERROR"):
        adapter._request(_target(), b"{}", "application/json")
    FakeConnection.response = FakeResponse(200, b"x" * 40)
    with pytest.raises(OpenCTITransportError, match="OPENCTI_RESPONSE_TOO_LARGE"):
        adapter._request(_target(), b"{}", "application/json")
    for body in (
        b"[]",
        b'{"errors":[{"message":"synthetic"}]}',
        b'{"data":[]}',
    ):
        FakeConnection.response = FakeResponse(200, body)
        with pytest.raises(OpenCTITransportError):
            adapter._request(_target(), b"{}", "application/json")
    FakeConnection.response = FakeResponse(200, b'{"data":{}}', "invalid")
    with pytest.raises(OpenCTITransportError, match="OPENCTI_RESPONSE_INVALID"):
        adapter._request(_target(), b"{}", "application/json")

    class FakeContext:
        def wrap_socket(self, raw: object, server_hostname: str) -> object:
            assert server_hostname == "127.0.0.1"
            return raw

    monkeypatch.setattr("ssl.create_default_context", lambda **kwargs: FakeContext())
    FakeConnection.response = FakeResponse(200, b'{"data":{}}')
    assert adapter._request(_target(scheme="https"), b"{}", "application/json") == {}
    assert FakeConnection.last_headers["Host"] == "127.0.0.1"


def test_safe_transport_message_redacts_non_transport_errors() -> None:
    from cti_trust_gateway.delivery.transport import safe_transport_message

    assert safe_transport_message(OpenCTITransportError("STABLE_CODE")) == "STABLE_CODE"
    assert safe_transport_message(ValueError("Bearer secret-token")) == "Bearer [REDACTED]"
