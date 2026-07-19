from __future__ import annotations

import ipaddress
import math
import multiprocessing
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from cti_trust_gateway.compatibility import load_opencti_profile
from cti_trust_gateway.compatibility.checker import check_opencti_compatibility
from cti_trust_gateway.compatibility.profile import ProfileIntegrityError, _profile_digest
from cti_trust_gateway.core.canonical import canonical_bytes, canonical_sha256
from cti_trust_gateway.core.service import GatewayService
from cti_trust_gateway.delivery.artifact import ApprovedArtifactBuilder
from cti_trust_gateway.delivery.config import OpenCTIConfig, OpenCTIConfigError, _boolean
from cti_trust_gateway.delivery.security import (
    OpenCTISecurityError,
    _address_allowed,
    parse_destination,
)
from cti_trust_gateway.delivery.service import (
    DeliveryGateError,
    OpenCTIDeliveryService,
    verify_plan_hash,
)
from cti_trust_gateway.delivery.transport import OpenCTITransportError, StrictOpenCTIAdapter
from cti_trust_gateway.domain.models import DeliveryStatus
from cti_trust_gateway.storage.repository import DeliveryReservationError, Repository
from cti_trust_gateway.validators.stix import CandidateError, parse_candidate, validate_candidate
from tests.adversarial.test_opencti_delivery import CONNECTOR_ID, FakeAdapter, _case, _config
from tests.conftest import make_bundle, sid

CHANNEL_EXTENSION_ID = "extension-definition--be4ebfff-c203-4698-8853-4797fa138ec7"


def _channel(name: str = "Twitter") -> dict[str, Any]:
    return {
        "type": "channel",
        "spec_version": "2.1",
        "id": sid("channel", "audit-channel"),
        "created": "2025-10-10T20:54:21.731804Z",
        "modified": "2025-10-10T20:54:21.731804Z",
        "name": name,
        "extensions": {
            CHANNEL_EXTENSION_ID: {
                "type": "extension-definition",
                "spec_version": "2.1",
                "id": CHANNEL_EXTENSION_ID,
                "created_by_ref": "identity--32207a20-5ece-40d2-b7a7-c5c207a12244",
                "created": "2025-09-10T00:00:00.000Z",
                "modified": "2025-09-10T00:00:00.000Z",
                "name": "Channel",
                "description": "Extension for creating channel objects in STIX",
                "schema": "{'type': 'object', 'properties': {'type': {'const': 'channel'}}}",
                "version": "1.0.0",
                "extension_types": ["new-sdo"],
                "extension_properties": ["name", "description", "aliases", "channel_types"],
            }
        },
    }


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_fail_canonicalization_and_candidate_parsing(value: float) -> None:
    with pytest.raises(ValueError, match="CANONICAL_JSON_NON_FINITE_NUMBER"):
        canonical_bytes({"value": value})
    token = "NaN" if math.isnan(value) else "Infinity" if value > 0 else "-Infinity"
    with pytest.raises(CandidateError):
        parse_candidate(f'{{"type":"bundle","objects":[{{"value":{token}}}]}}')


def test_malformed_unicode_and_non_string_mapping_keys_fail_closed() -> None:
    with pytest.raises(UnicodeEncodeError):
        canonical_bytes({"value": "\ud800"})
    with pytest.raises(TypeError, match="CANONICAL_JSON_NON_STRING_KEY"):
        canonical_bytes({1: "invalid"})


def test_identical_duplicate_is_deterministic_but_conflict_is_rejected() -> None:
    obj = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": sid("ipv4-addr", "duplicate-audit"),
        "value": "203.0.113.90",
    }
    identical = parse_candidate(make_bundle([obj, dict(obj)], "duplicate-identical"))
    candidate, findings = validate_candidate(identical)
    assert candidate.is_valid
    assert not {finding.rule_id for finding in findings} & {"STIX-DUPLICATE-CONFLICT-001"}

    conflict = parse_candidate(
        make_bundle([obj, {**obj, "value": "203.0.113.91"}], "duplicate-conflict")
    )
    candidate, findings = validate_candidate(conflict)
    assert not candidate.is_valid
    assert "STIX-DUPLICATE-CONFLICT-001" in {finding.rule_id for finding in findings}


def test_profile_is_deeply_immutable_and_exact_channel_is_independently_validated() -> None:
    profile = load_opencti_profile()
    with pytest.raises(TypeError, match="FROZEN_MAPPING"):
        profile.types.pop("url")
    bundle = parse_candidate(make_bundle([_channel()], "exact-channel"))
    candidate, findings = validate_candidate(bundle)
    assert candidate.is_valid, [finding.rule_id for finding in findings]
    report = check_opencti_compatibility(bundle["objects"], profile)
    assert report.compatible

    invented = {key: value for key, value in _channel().items() if key != "extensions"}
    report = check_opencti_compatibility([invented], profile)
    assert "OPENCTI_UNSUPPORTED_CUSTOM_TYPE" in {finding.code for finding in report.findings}


@pytest.mark.parametrize(
    "obj",
    [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": sid("identity", "individual-audit"),
            "name": "Example Person",
            "identity_class": "individual",
        },
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": sid("identity", "sector-audit"),
            "name": "Financial Services",
            "identity_class": "class",
        },
        {
            "type": "location",
            "spec_version": "2.1",
            "id": sid("location", "country-audit"),
            "name": "Saudi Arabia",
            "country": "SA",
            "x_opencti_location_type": "Country",
        },
        {
            "type": "location",
            "spec_version": "2.1",
            "id": sid("location", "region-audit"),
            "name": "Western Asia",
            "region": "western-asia",
            "x_opencti_location_type": "Region",
        },
    ],
)
def test_pinned_identity_and_location_representations(obj: dict[str, Any]) -> None:
    assert check_opencti_compatibility([obj], load_opencti_profile()).compatible


def test_unprofiled_platform_version_blocks_offline_plan(service: GatewayService) -> None:
    case = _case(service)
    delivery = OpenCTIDeliveryService(
        service.repository,
        load_opencti_profile(),
        _config(expected_version="8.0.0"),
        adapter=FakeAdapter(),
    )
    plan = delivery.create_plan(case.id)
    assert plan.status == DeliveryStatus.BLOCKED
    assert "OPENCTI_VERSION_MISMATCH" in plan.blockers


@pytest.mark.parametrize(
    "mutation",
    [
        lambda plan: plan.model_copy(update={"id": "plan--forged"}),
        lambda plan: plan.model_copy(update={"expires_at": plan.expires_at + timedelta(days=1)}),
        lambda plan: plan.model_copy(
            update={"options": plan.options.model_copy(update={"poll_attempts": 99})}
        ),
        lambda plan: plan.model_copy(
            update={"options": plan.options.model_copy(update={"allow_private": True})}
        ),
        lambda plan: plan.model_copy(
            update={
                "destination": plan.destination.model_copy(update={"origin": "https://other.test"})
            }
        ),
    ],
)
def test_plan_confirmation_rejects_every_authority_tamper(
    service: GatewayService, mutation: Any
) -> None:
    plan = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(), adapter=FakeAdapter()
    ).create_plan(_case(service).id)
    assert verify_plan_hash(plan)
    assert not verify_plan_hash(mutation(plan))


def test_semantically_order_only_bundles_produce_identical_artifact_bytes(
    service: GatewayService,
) -> None:
    ip_a = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": sid("ipv4-addr", "order-a"),
        "value": "203.0.113.101",
    }
    ip_b = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": sid("ipv4-addr", "order-b"),
        "value": "203.0.113.102",
    }
    domain_id = sid("domain-name", "order-domain")
    domain_a = {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": domain_id,
        "value": "order.example",
        "resolves_to_refs": [ip_a["id"], ip_b["id"]],
    }
    domain_b = {**domain_a, "resolves_to_refs": [ip_b["id"], ip_a["id"]]}
    source = b"order.example resolved to 203.0.113.101 and 203.0.113.102."
    first = service.analyze(source, "order.txt", make_bundle([domain_a, ip_a, ip_b], "order"))
    second = service.analyze(source, "order.txt", make_bundle([ip_b, domain_b, ip_a], "order"))
    builder = ApprovedArtifactBuilder(service.repository, load_opencti_profile())
    left = builder.build(first.id).artifact
    right = builder.build(second.id).artifact
    assert left is not None and right is not None
    assert left.bundle_bytes() == right.bundle_bytes()
    assert left.artifact_sha256 == right.artifact_sha256


def test_unmodeled_description_and_candidate_report_narrative_never_cross_boundary(
    service: GatewayService,
) -> None:
    malware_id = sid("malware", "smuggled-description")
    smuggled = service.analyze(
        b"GlassRAT was observed.",
        "smuggle.txt",
        make_bundle(
            [
                {
                    "type": "malware",
                    "spec_version": "2.1",
                    "id": malware_id,
                    "name": "GlassRAT",
                    "is_family": False,
                    "description": "UNVERIFIED: APT99 destroyed Example Corp.",
                }
            ],
            "smuggled-description",
        ),
    )
    blocked = ApprovedArtifactBuilder(service.repository, load_opencti_profile()).build(smuggled.id)
    assert blocked.artifact is None
    assert "UNMODELED_ASSERTION_PROPERTY" in blocked.exclusion_reasons[malware_id]

    ip_id = sid("ipv4-addr", "report-rewrite")
    report_id = sid("report", "report-rewrite")
    report_case = service.analyze(
        b"Daily report observed 203.0.113.77.",
        "report.txt",
        make_bundle(
            [
                {"type": "ipv4-addr", "spec_version": "2.1", "id": ip_id, "value": "203.0.113.77"},
                {
                    "type": "report",
                    "spec_version": "2.1",
                    "id": report_id,
                    "name": "Daily report",
                    "published": "2026-07-18T00:00:00Z",
                    "object_refs": [ip_id],
                    "description": "UNVERIFIED: APT99 destroyed everything.",
                },
            ],
            "report-rewrite",
        ),
    )
    artifact = (
        ApprovedArtifactBuilder(service.repository, load_opencti_profile())
        .build(report_case.id)
        .artifact
    )
    assert artifact is not None
    assert b"APT99" not in artifact.bundle_bytes()
    assert report_id not in artifact.included_object_ids


def test_source_snapshot_tamper_and_terminal_state_regression_fail_closed(
    service: GatewayService,
) -> None:
    case = _case(service)
    case.source.sha256 = "f" * 64
    service.repository.save(case)
    assessment = ApprovedArtifactBuilder(service.repository, load_opencti_profile()).build(case.id)
    assert "ANALYSIS_SNAPSHOT_INTEGRITY_FAILURE" in assessment.blockers

    clean_case = _case(service)
    delivery = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(), adapter=FakeAdapter()
    )
    plan = delivery.create_plan(clean_case.id)
    receipt = delivery.execute(plan.id, plan.plan_sha256)
    with pytest.raises(DeliveryReservationError, match="DELIVERY_STATE_TRANSITION_INVALID"):
        service.repository.update_delivery_attempt(receipt.attempt_id, DeliveryStatus.PROCESSING)


def test_direct_adapter_respects_disabled_gate_before_resolution(
    service: GatewayService, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(service)
    config = _config(enabled=False)
    delivery = OpenCTIDeliveryService(service.repository, load_opencti_profile(), config)
    plan = delivery.create_plan(case.id)
    artifact = delivery.check(case.id).artifact
    assert artifact is not None
    monkeypatch.setattr(
        "cti_trust_gateway.delivery.transport.resolve_destination",
        lambda _config: (_ for _ in ()).throw(AssertionError("must not resolve")),
    )
    with pytest.raises(Exception, match="OPENCTI_DELIVERY_DISABLED"):
        StrictOpenCTIAdapter(config).deliver(
            artifact, plan, object(), "attempt--x", lambda *args: None
        )  # type: ignore[arg-type]


def test_remote_token_echo_is_rejected_before_persistence() -> None:
    config = OpenCTIConfig(
        enabled=True,
        url="https://127.0.0.1",
        token=SecretStr("top-secret-token"),
        import_connector_id=CONNECTOR_ID,
        host_allowlist=("127.0.0.1",),
        allow_loopback=True,
    )
    adapter = StrictOpenCTIAdapter(config)
    with pytest.raises(OpenCTITransportError, match="OPENCTI_REMOTE_VALUE_INVALID"):
        adapter._remote_identifier("draft--top-secret-token", 120)


def test_allowlist_is_exact_to_port_and_api_pagination_is_bounded(
    tmp_path: Path,
) -> None:
    with pytest.raises(OpenCTISecurityError, match="OPENCTI_HOST_NOT_ALLOWLISTED"):
        parse_destination(
            OpenCTIConfig(
                url="https://opencti.example.test:444",
                import_connector_id=CONNECTOR_ID,
                host_allowlist=("opencti.example.test",),
            )
        )
    from cti_trust_gateway.api.app import create_app

    client = TestClient(create_app(f"sqlite:///{tmp_path / 'bounded-api.db'}"))
    assert client.get("/api/v1/opencti/plans?limit=101").status_code == 422
    assert client.get("/api/v1/cases?offset=100001").status_code == 422


@pytest.mark.parametrize(
    "url,allowlist,code",
    [
        ("https://127.0.0.01", ("127.0.0.01",), "OPENCTI_URL_INVALID"),
        ("https://[::1]", ("[::1]:444",), "OPENCTI_HOST_NOT_ALLOWLISTED"),
        ("https://example.test", ("example.test:70000",), "OPENCTI_HOST_ALLOWLIST_INVALID"),
        ("https://[::1", ("[::1]",), "OPENCTI_URL_INVALID"),
    ],
)
def test_host_and_authority_edge_cases_fail_closed(
    url: str, allowlist: tuple[str, ...], code: str
) -> None:
    with pytest.raises(OpenCTISecurityError, match=code):
        parse_destination(
            OpenCTIConfig(
                url=url,
                import_connector_id=CONNECTOR_ID,
                host_allowlist=allowlist,
                allow_loopback=True,
            )
        )
    assert not _address_allowed(
        ipaddress.ip_address("::ffff:127.0.0.1"), OpenCTIConfig(allow_loopback=False)
    )


def test_checker_handles_non_json_missing_ids_extensions_depth_and_marking_conflict() -> None:
    profile = load_opencti_profile()
    bad_json = check_opencti_compatibility(
        [{"type": "url", "id": "url--x", "value": math.nan}], profile
    )
    assert "OPENCTI_CANONICALIZATION_FAILED" in {finding.code for finding in bad_json.findings}
    missing = check_opencti_compatibility([{"type": "url", "value": "https://x.test"}], profile)
    assert "OPENCTI_UNSUPPORTED_PROPERTY" in {finding.code for finding in missing.findings}
    extended = check_opencti_compatibility(
        [
            {
                "type": "url",
                "id": "url--x",
                "value": "https://x.test",
                "extensions": {"not-an-extension": {}},
            }
        ],
        profile,
    )
    assert "OPENCTI_UNSUPPORTED_EXTENSION" in {finding.code for finding in extended.findings}

    first = {
        "type": "marking-definition",
        "id": "marking-definition--11111111-1111-4111-8111-111111111111",
        "definition_type": "tlp",
        "definition": {"tlp": "green"},
    }
    second = {
        "type": "marking-definition",
        "id": "marking-definition--22222222-2222-4222-8222-222222222222",
        "definition_type": "tlp",
        "definition": {"tlp": "amber"},
    }
    marked = {
        "type": "url",
        "id": "url--marked",
        "value": "https://marked.test",
        "object_marking_refs": [first["id"], second["id"]],
    }
    conflict = check_opencti_compatibility([first, second, marked], profile)
    assert "OPENCTI_MARKING_CONFLICT" in {finding.code for finding in conflict.findings}

    a = {
        "type": "domain-name",
        "id": "domain-name--a",
        "value": "a",
        "resolves_to_refs": ["domain-name--b"],
    }
    b = {
        "type": "domain-name",
        "id": "domain-name--b",
        "value": "b",
        "resolves_to_refs": ["domain-name--c"],
    }
    c = {"type": "domain-name", "id": "domain-name--c", "value": "c"}
    shallow = profile.model_copy(
        update={"limits": profile.limits.model_copy(update={"max_dependency_depth": 1})}
    )
    depth = check_opencti_compatibility([a, b, c], shallow)
    assert "OPENCTI_LIMIT_EXCEEDED" in {finding.code for finding in depth.findings}


def test_plan_limits_and_mutation_persistence_failure_are_blocked(
    service: GatewayService,
) -> None:
    case = _case(service)
    blocked = OpenCTIDeliveryService(
        service.repository,
        load_opencti_profile(),
        _config(max_objects=1, max_bytes=1),
    ).create_plan(case.id)
    assert "OPENCTI_LIMIT_EXCEEDED" in blocked.blockers
    with pytest.raises(KeyError):
        OpenCTIDeliveryService(service.repository, load_opencti_profile(), _config()).create_plan(
            "case--missing"
        )

    class InvalidRemoteAdapter(FakeAdapter):
        def deliver(
            self,
            artifact: object,
            plan: object,
            capabilities: object,
            attempt_id: str,
            progress: Any,
        ) -> Any:
            progress(DeliveryStatus.PROCESSING, "draft--one", None, None, "created")
            progress(
                DeliveryStatus.SUBMITTED, "draft--one", "invalid value with spaces", None, "sent"
            )

    clean = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(), adapter=InvalidRemoteAdapter()
    )
    clean_plan = clean.create_plan(_case(service).id)
    with pytest.raises(OpenCTITransportError, match="DELIVERY_PERSISTENCE_UNKNOWN"):
        clean.execute(clean_plan.id, clean_plan.plan_sha256)
    assert (
        service.repository.list_delivery_attempts(clean_plan.id)[0].status == DeliveryStatus.UNKNOWN
    )


def _reserve_in_process(database: str, plan_id: str, output: Any) -> None:
    repository = Repository(f"sqlite:///{database}")
    try:
        output.put(repository.reserve_delivery_attempt(plan_id).id)
    except DeliveryReservationError as exc:
        output.put(exc.code)


def _append_audit_in_process(database: str, case_id: str, actor: str, output: Any) -> None:
    repository = Repository(f"sqlite:///{database}")
    event = repository.append_audit(case_id, "audit.concurrent", actor, {"actor": actor})
    output.put(event.id)


def test_two_independent_processes_cannot_reserve_same_plan(service: GatewayService) -> None:
    plan = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(enabled=False)
    ).create_plan(_case(service).id)
    database = str(service.repository.engine.url.database)
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    processes = [
        context.Process(target=_reserve_in_process, args=(database, plan.id, output))
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    results = [output.get(timeout=5) for _ in processes]
    assert sum(value.startswith("attempt--") for value in results) == 1
    assert "DELIVERY_RECONCILIATION_REQUIRED" in results


def test_two_independent_processes_preserve_audit_chain(service: GatewayService) -> None:
    case = _case(service)
    database = str(service.repository.engine.url.database)
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    processes = [
        context.Process(
            target=_append_audit_in_process,
            args=(database, case.id, f"worker-{index}", output),
        )
        for index in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    assert len({output.get(timeout=5) for _ in processes}) == 2
    stored = service.repository.get(case.id)
    assert stored is not None
    assert sum(event.event_type == "audit.concurrent" for event in stored.audit) == 2
    assert service.repository.verify_audit_chain(stored)


def test_delivery_ledger_negative_and_idempotent_branches(service: GatewayService) -> None:
    repository = service.repository
    with pytest.raises(KeyError):
        repository.reserve_delivery_attempt("plan--missing")
    assert repository.get_delivery_attempt("attempt--missing") is None
    with pytest.raises(ValueError, match="DELIVERY_PAGINATION_INVALID"):
        repository.list_delivery_plans(limit=0)
    with pytest.raises(ValueError, match="DELIVERY_PAGINATION_INVALID"):
        repository.list_delivery_attempts("plan--missing", offset=100_001)

    blocked_delivery = OpenCTIDeliveryService(
        repository,
        load_opencti_profile(),
        _config(max_bytes=1),
        adapter=FakeAdapter(),
    )
    blocked_plan = blocked_delivery.create_plan(_case(service).id)
    with pytest.raises(DeliveryReservationError, match="DELIVERY_PLAN_BLOCKED"):
        repository.reserve_delivery_attempt(blocked_plan.id)

    delivery = OpenCTIDeliveryService(
        repository, load_opencti_profile(), _config(), adapter=FakeAdapter()
    )
    plan = delivery.create_plan(_case(service).id)
    receipt = delivery.execute(plan.id, plan.plan_sha256)
    assert receipt.status == DeliveryStatus.SUCCEEDED
    first_noop = repository.reserve_delivery_attempt(plan.id)
    second_noop = repository.reserve_delivery_attempt(plan.id)
    assert first_noop.id == second_noop.id

    pending_plan = OpenCTIDeliveryService(
        repository,
        load_opencti_profile(),
        _config(plan_ttl_seconds=901),
        adapter=FakeAdapter(),
    ).create_plan(_case(service).id)
    pending = repository.reserve_delivery_attempt(pending_plan.id)
    with pytest.raises(DeliveryReservationError, match="DELIVERY_STATE_CONFLICT"):
        repository.update_delivery_attempt(
            pending.id,
            DeliveryStatus.SUBMITTED,
            expected_statuses={DeliveryStatus.PROCESSING},
        )
    repository.update_delivery_attempt(
        pending.id,
        DeliveryStatus.SUBMITTED,
        draft_id="draft--one",
        remote_file_id="file--one",
        work_id="work--one",
    )
    for field, value in (
        ("draft_id", "draft--two"),
        ("remote_file_id", "file--two"),
        ("work_id", "work--two"),
    ):
        with pytest.raises(DeliveryReservationError, match="DELIVERY_REMOTE_ID_CONFLICT"):
            repository.update_delivery_attempt(
                pending.id,
                DeliveryStatus.PROCESSING,
                **{field: value},
            )


def test_profile_and_config_failure_branches_are_stable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ProfileIntegrityError):
        _profile_digest({})
    oversized = tmp_path / "oversized.yml"
    oversized.write_bytes(b"x" * (256 * 1024 + 1))
    with pytest.raises(ProfileIntegrityError):
        load_opencti_profile(oversized)
    scalar = tmp_path / "scalar.yml"
    scalar.write_text("not-a-mapping", encoding="utf-8")
    with pytest.raises(ProfileIntegrityError):
        load_opencti_profile(scalar)

    monkeypatch.setenv("AUDIT_BOOLEAN", "false")
    assert _boolean("AUDIT_BOOLEAN", True) is False
    with pytest.raises(OpenCTIConfigError, match="OPENCTI_CONNECTOR_ID_INVALID"):
        _config(import_connector_id="11111111-1111-1111-8111-111111111111").validate_nonsecret()
    with pytest.raises(OpenCTIConfigError, match="OPENCTI_CA_BUNDLE_UNAVAILABLE"):
        _config(ca_bundle=tmp_path / "missing.pem").validate_nonsecret()
    large_ca = tmp_path / "large.pem"
    large_ca.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(OpenCTIConfigError, match="OPENCTI_CA_BUNDLE_TOO_LARGE"):
        _config(ca_bundle=large_ca).validate_nonsecret()


def test_artifact_duplicate_conflict_and_blocked_dependency_paths(
    service: GatewayService,
) -> None:
    case = _case(service)
    obj = case.candidate.raw["objects"][0]
    case.candidate.raw["objects"].append({**obj, "value": "203.0.113.250"})
    service.repository.save(case)
    conflict = ApprovedArtifactBuilder(service.repository, load_opencti_profile()).build(case.id)
    assert "OPENCTI_DUPLICATE_ID_CONFLICT" in conflict.blockers

    selected = {"relationship--one"}
    reasons = {"relationship--one": [], "malware--blocked": ["BLOCKED"]}
    ApprovedArtifactBuilder._close_dependencies(
        selected,
        {
            "relationship--one": {
                "type": "relationship",
                "source_ref": "malware--blocked",
                "target_ref": "malware--blocked",
            },
            "malware--blocked": {"type": "malware"},
        },
        reasons,
    )
    assert selected == set()
    assert "UNAPPROVED_DEPENDENCY" in reasons["relationship--one"]


def test_execution_stale_version_and_reconcile_gate_branches(
    service: GatewayService, monkeypatch: pytest.MonkeyPatch
) -> None:
    delivery = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), _config(), adapter=FakeAdapter()
    )
    plan = delivery.create_plan(_case(service).id)
    monkeypatch.setattr(
        "cti_trust_gateway.delivery.service.utc_now",
        lambda: plan.expires_at + timedelta(seconds=1),
    )
    with pytest.raises(DeliveryGateError, match="DELIVERY_PLAN_STALE"):
        delivery._execution_gates(plan.id, plan.plan_sha256)
    monkeypatch.undo()

    changed_version = OpenCTIDeliveryService(
        service.repository,
        load_opencti_profile(),
        _config(expected_version="8.0.0"),
        adapter=FakeAdapter(),
    )
    with pytest.raises(DeliveryGateError, match="OPENCTI_VERSION_MISMATCH"):
        changed_version._execution_gates(plan.id, plan.plan_sha256)

    attempt = service.repository.reserve_delivery_attempt(plan.id)
    service.repository.update_delivery_attempt(attempt.id, DeliveryStatus.SUBMITTED)
    service.repository.update_delivery_attempt(attempt.id, DeliveryStatus.UNKNOWN)
    with pytest.raises(DeliveryGateError, match="DELIVERY_RECONCILIATION_UNAVAILABLE"):
        delivery.reconcile(attempt.id)


def test_transport_name_marking_poll_and_mutation_error_branches(
    service: GatewayService, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.adversarial.test_opencti_delivery import (
        FakeConnection,
        FakeResponse,
        FakeSocket,
        RecordingAdapter,
        _capabilities,
        _target,
    )

    probe_data = {
        "about": {"version": "7.260715.0"},
        "connector": {
            "id": CONNECTOR_ID,
            "name": "WrongConnector",
            "active": True,
            "connector_type": "INTERNAL_IMPORT_FILE",
            "connector_scope": ["application/json"],
        },
        "markingDefinitions": {"edges": [None]},
    }
    monkeypatch.setattr(
        "cti_trust_gateway.delivery.transport.resolve_destination",
        lambda _config: _target(scheme="https"),
    )
    with pytest.raises(OpenCTITransportError, match="OPENCTI_CONNECTOR_NAME_MISMATCH"):
        RecordingAdapter(_config(), [probe_data]).probe()

    delivery = OpenCTIDeliveryService(service.repository, load_opencti_profile(), _config())
    plan = delivery.create_plan(_case(service).id)
    artifact = delivery.check(plan.case_id).artifact
    assert artifact is not None
    marked = plan.model_copy(update={"marking_ids": ("marking-definition--missing",)})
    marked = marked.model_copy(
        update={
            "plan_sha256": canonical_sha256(
                marked.model_dump(mode="json", exclude={"status", "plan_sha256"})
            )
        }
    )
    with pytest.raises(OpenCTITransportError, match="OPENCTI_MARKING_UNAVAILABLE"):
        RecordingAdapter(_config(), [{"draftWorkspaceAdd": {"id": "draft--one"}}]).deliver(
            artifact, marked, _capabilities(), "attempt--x", lambda *args: None
        )

    polling_config = _config(poll_attempts=2, poll_interval_seconds=0)
    polling_delivery = OpenCTIDeliveryService(
        service.repository, load_opencti_profile(), polling_config
    )
    polling_plan = polling_delivery.create_plan(_case(service).id)
    polling_artifact = polling_delivery.check(polling_plan.case_id).artifact
    assert polling_artifact is not None
    polling = RecordingAdapter(
        polling_config,
        [
            {"draftWorkspaceAdd": {"id": "draft--poll"}},
            {
                "uploadAndAskJobImport": {
                    "id": "file--poll",
                    "works": [{"id": "work--poll"}],
                }
            },
            {"work": {"status": "progress", "errors": []}},
            {"work": {"status": "complete", "errors": []}},
        ],
    )
    receipt = polling.deliver(
        polling_artifact,
        polling_plan,
        _capabilities(),
        "attempt--poll",
        lambda *args: None,
    )
    assert receipt.status == DeliveryStatus.SUCCEEDED

    adapter = StrictOpenCTIAdapter(_config(max_response_bytes=100))
    monkeypatch.setattr("socket.create_connection", lambda *args, **kwargs: FakeSocket())
    monkeypatch.setattr("http.client.HTTPConnection", FakeConnection)
    FakeConnection.response = FakeResponse(200, b'{"errors":[{"message":"x"}]}')
    with pytest.raises(OpenCTITransportError) as captured:
        adapter._request(_target(), b"{}", "application/json", mutation=True)
    assert captured.value.ambiguous is True
