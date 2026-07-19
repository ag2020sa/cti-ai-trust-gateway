"""Strict minimal HTTP adapter for the pinned OpenCTI Draft GraphQL contract."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import time
from collections.abc import Callable
from typing import Any, Protocol

from cti_trust_gateway import __version__
from cti_trust_gateway.core.canonical import canonical_json, canonical_sha256, sha256_bytes
from cti_trust_gateway.delivery.config import OpenCTIConfig
from cti_trust_gateway.delivery.security import (
    DestinationTarget,
    resolve_destination,
    sanitize_message,
)
from cti_trust_gateway.domain.models import (
    ApprovedArtifact,
    DeliveryPlan,
    DeliveryReceipt,
    DeliveryStatus,
    DestinationCapabilities,
)

CREATE_DRAFT_MUTATION = """
mutation GatewayDraftCreate($input: DraftWorkspaceAddInput!) {
  draftWorkspaceAdd(input: $input) { id }
}
""".strip()

UPLOAD_DRAFT_MUTATION = """
mutation GatewayDraftUpload(
  $file: Upload!,
  $fileMarkings: [String!],
  $connectors: [ConnectorWithConfig!],
  $validationMode: ValidationMode,
  $draftId: String,
  $noTriggerImport: Boolean
) {
  uploadAndAskJobImport(
    file: $file,
    fileMarkings: $fileMarkings,
    connectors: $connectors,
    validationMode: $validationMode,
    draftId: $draftId,
    noTriggerImport: $noTriggerImport
  ) { id name works { id status } }
}
""".strip()

PROBE_QUERY = """
query GatewayProbe($connectorId: String!) {
  about { version }
  connector(id: $connectorId) {
    id name active connector_type connector_scope
  }
  markingDefinitions(first: 500) {
    edges { node { id standard_id } }
  }
}
""".strip()

WORK_QUERY = """
query GatewayWork($id: ID!) {
  work(id: $id) { id status errors }
}
""".strip()

ProgressCallback = Callable[[DeliveryStatus, str | None, str | None, str | None, str], None]


class OpenCTITransportError(RuntimeError):
    def __init__(self, code: str, *, ambiguous: bool = False) -> None:
        self.code = code
        self.ambiguous = ambiguous
        super().__init__(code)


class OpenCTIAdapter(Protocol):
    def probe(self) -> DestinationCapabilities: ...

    def deliver(
        self,
        artifact: ApprovedArtifact,
        plan: DeliveryPlan,
        capabilities: DestinationCapabilities,
        attempt_id: str,
        progress: ProgressCallback,
    ) -> DeliveryReceipt: ...

    def reconcile(self, work_id: str) -> DeliveryStatus: ...


class StrictOpenCTIAdapter:
    def __init__(self, config: OpenCTIConfig) -> None:
        self.config = config
        self._ca_bundle_bytes = config.read_ca_bundle()
        self._ca_bundle_sha256 = (
            sha256_bytes(self._ca_bundle_bytes) if self._ca_bundle_bytes is not None else None
        )

    def probe(self) -> DestinationCapabilities:
        self.config.require_execution_secrets()
        target = resolve_destination(self.config)
        response = self._graphql(
            target, PROBE_QUERY, {"connectorId": self.config.import_connector_id}
        )
        about = response.get("about")
        connector = response.get("connector")
        if not isinstance(about, dict) or not isinstance(connector, dict):
            raise OpenCTITransportError("OPENCTI_PROBE_CONTRACT_MISMATCH")
        version = str(about.get("version", ""))
        connector_id = str(connector.get("id", ""))
        connector_type = str(connector.get("connector_type", ""))
        connector_name = str(connector.get("name", ""))
        scope_value = connector.get("connector_scope", [])
        if isinstance(scope_value, str):
            scope = tuple(sorted(item.strip() for item in scope_value.split(",") if item.strip()))
        elif isinstance(scope_value, list):
            scope = tuple(sorted(str(item) for item in scope_value))
        else:
            scope = ()
        if version != self.config.expected_version:
            raise OpenCTITransportError("OPENCTI_VERSION_MISMATCH")
        if connector_id != self.config.import_connector_id:
            raise OpenCTITransportError("OPENCTI_CONNECTOR_IDENTITY_MISMATCH")
        if connector_type != "INTERNAL_IMPORT_FILE":
            raise OpenCTITransportError("OPENCTI_CONNECTOR_TYPE_MISMATCH")
        if connector.get("active") is not True:
            raise OpenCTITransportError("OPENCTI_CONNECTOR_INACTIVE")
        if "application/json" not in scope:
            raise OpenCTITransportError("OPENCTI_CONNECTOR_SCOPE_MISMATCH")
        if connector_name != self.config.import_connector_name:
            raise OpenCTITransportError("OPENCTI_CONNECTOR_NAME_MISMATCH")
        marking_id_map: dict[str, str] = {}
        markings = response.get("markingDefinitions")
        if isinstance(markings, dict) and isinstance(markings.get("edges"), list):
            for edge in markings["edges"]:
                node = edge.get("node") if isinstance(edge, dict) else None
                if isinstance(node, dict) and isinstance(node.get("standard_id"), str):
                    standard_id = self._remote_identifier(node["standard_id"], 120)
                    internal_id = self._remote_identifier(node.get("id", ""), 120)
                    marking_id_map[standard_id] = internal_id
        fingerprint_sha256 = canonical_sha256(
            {
                "origin": target.origin,
                "platform_version": version,
                "connector_id": connector_id,
                "connector_name": connector_name,
                "connector_type": connector_type,
                "connector_scope": scope,
                "connector_active": True,
                "marking_id_map": marking_id_map,
            }
        )
        return DestinationCapabilities(
            origin=target.origin,
            platform_version=version,
            connector_id=connector_id,
            connector_name=connector_name,
            connector_type=connector_type,
            connector_scope=scope,
            connector_active=True,
            marking_id_map=marking_id_map,
            fingerprint_sha256=fingerprint_sha256,
        )

    def deliver(
        self,
        artifact: ApprovedArtifact,
        plan: DeliveryPlan,
        capabilities: DestinationCapabilities,
        attempt_id: str,
        progress: ProgressCallback,
    ) -> DeliveryReceipt:
        self.config.require_execution_secrets()
        bundle_bytes = artifact.bundle_bytes()
        plan_payload = plan.model_dump(mode="json", exclude={"status", "plan_sha256"})
        target = resolve_destination(self.config)
        current_destination = self.config.fingerprint(target.origin)
        if (
            artifact.artifact_sha256 != plan.artifact_sha256
            or sha256_bytes(bundle_bytes) != artifact.artifact_sha256
            or artifact.id != f"artifact--{artifact.artifact_sha256}"
            or artifact.size_bytes != len(bundle_bytes)
            or plan.id != f"plan--{plan.logical_key}"
            or canonical_sha256(plan_payload) != plan.plan_sha256
            or capabilities.origin != plan.destination.origin
            or capabilities.platform_version != plan.destination.expected_version
            or capabilities.connector_id != plan.destination.import_connector_id
            or capabilities.connector_name != plan.destination.import_connector_name
            or current_destination != plan.destination
            or self._ca_bundle_sha256 != plan.destination.ca_bundle_sha256
        ):
            raise OpenCTITransportError("DELIVERY_ARTIFACT_MISMATCH")
        draft_data = self._graphql(
            target,
            CREATE_DRAFT_MUTATION,
            {
                "input": {
                    "name": f"CTI Trust Gateway {plan.case_id}"[:120],
                    "description": (
                        f"Approved artifact {artifact.artifact_sha256}; manual approval required."
                    ),
                    "entity_id": None,
                }
            },
            mutation=True,
        )
        draft = draft_data.get("draftWorkspaceAdd")
        draft_id_value = draft.get("id", "") if isinstance(draft, dict) else ""
        if not draft_id_value:
            raise OpenCTITransportError("OPENCTI_DRAFT_CREATE_FAILED")
        draft_id = self._remote_identifier(draft_id_value, 120)
        progress(DeliveryStatus.PROCESSING, draft_id, None, None, "Draft created")

        required_markings = tuple(sorted(set(plan.marking_ids)))
        try:
            target_marking_ids = [capabilities.marking_id_map[item] for item in required_markings]
        except KeyError as exc:
            raise OpenCTITransportError("OPENCTI_MARKING_UNAVAILABLE") from exc
        upload_data = self._multipart_graphql(
            target,
            UPLOAD_DRAFT_MUTATION,
            {
                "file": None,
                "fileMarkings": target_marking_ids,
                "connectors": [
                    {
                        "connectorId": self.config.import_connector_id,
                        "configuration": None,
                    }
                ],
                "validationMode": "draft",
                "draftId": draft_id,
                "noTriggerImport": False,
            },
            artifact.bundle_bytes(),
            f"cti-trust-{artifact.artifact_sha256}.json",
            artifact.artifact_sha256,
        )
        uploaded = upload_data.get("uploadAndAskJobImport")
        if not isinstance(uploaded, dict) or not uploaded.get("id"):
            raise OpenCTITransportError("OPENCTI_UPLOAD_FAILED")
        remote_file_id = self._remote_identifier(uploaded["id"], 300)
        works = uploaded.get("works")
        work_id = ""
        if isinstance(works, list):
            work_id = next(
                (
                    self._remote_identifier(work["id"], 120)
                    for work in works
                    if isinstance(work, dict) and work.get("id")
                ),
                "",
            )
        progress(
            DeliveryStatus.SUBMITTED,
            draft_id,
            remote_file_id,
            work_id or None,
            "Bundle submitted to OpenCTI Draft",
        )
        if not work_id:
            return DeliveryReceipt(
                plan_id=plan.id,
                attempt_id=attempt_id,
                status=DeliveryStatus.UNKNOWN,
                draft_id=draft_id,
                remote_file_id=remote_file_id,
                message="Import work identifier was not returned; reconcile before retry",
            )
        final_status = DeliveryStatus.PROCESSING
        for attempt in range(self.config.poll_attempts):
            final_status = self.reconcile(work_id)
            if final_status in {DeliveryStatus.SUCCEEDED, DeliveryStatus.FAILED}:
                break
            if attempt + 1 < self.config.poll_attempts:
                time.sleep(self.config.poll_interval_seconds)
        message = (
            "OpenCTI Draft import work completed; manual approval remains required"
            if final_status == DeliveryStatus.SUCCEEDED
            else "OpenCTI Draft import work requires later reconciliation"
        )
        return DeliveryReceipt(
            plan_id=plan.id,
            attempt_id=attempt_id,
            status=final_status,
            draft_id=draft_id,
            remote_file_id=remote_file_id,
            work_id=work_id,
            message=message,
        )

    def reconcile(self, work_id: str) -> DeliveryStatus:
        self.config.require_execution_secrets()
        target = resolve_destination(self.config)
        response = self._graphql(target, WORK_QUERY, {"id": work_id})
        work = response.get("work")
        if not isinstance(work, dict):
            return DeliveryStatus.UNKNOWN
        status = str(work.get("status", "")).casefold()
        errors = work.get("errors")
        if errors:
            return DeliveryStatus.FAILED
        if status == "complete":
            return DeliveryStatus.SUCCEEDED
        if status in {"wait", "progress"}:
            return DeliveryStatus.PROCESSING
        return DeliveryStatus.UNKNOWN

    def _graphql(
        self,
        target: DestinationTarget,
        query: str,
        variables: dict[str, Any],
        *,
        mutation: bool = False,
    ) -> dict[str, Any]:
        body = canonical_json({"query": query, "variables": variables}).encode("utf-8")
        return self._request(target, body, "application/json", mutation=mutation)

    def _multipart_graphql(
        self,
        target: DestinationTarget,
        query: str,
        variables: dict[str, Any],
        file_bytes: bytes,
        filename: str,
        boundary_seed: str,
    ) -> dict[str, Any]:
        boundary = f"cti-gateway-{boundary_seed[:32]}"
        operations = canonical_json({"query": query, "variables": variables}).encode("utf-8")
        mapping = canonical_json({"0": ["variables.file"]}).encode("utf-8")
        delimiter = f"--{boundary}\r\n".encode()
        body = b"".join(
            (
                delimiter,
                b'Content-Disposition: form-data; name="operations"\r\n',
                b"Content-Type: application/json\r\n\r\n",
                operations,
                b"\r\n",
                delimiter,
                b'Content-Disposition: form-data; name="map"\r\n',
                b"Content-Type: application/json\r\n\r\n",
                mapping,
                b"\r\n",
                delimiter,
                (f'Content-Disposition: form-data; name="0"; filename="{filename}"\r\n').encode(),
                b"Content-Type: application/json\r\n\r\n",
                file_bytes,
                b"\r\n",
                f"--{boundary}--\r\n".encode(),
            )
        )
        return self._request(
            target,
            body,
            f"multipart/form-data; boundary={boundary}",
            mutation=True,
        )

    def _request(
        self,
        target: DestinationTarget,
        body: bytes,
        content_type: str,
        *,
        mutation: bool = False,
    ) -> dict[str, Any]:
        if self.config.token is None:
            raise OpenCTITransportError("OPENCTI_TOKEN_UNAVAILABLE")
        if not target.addresses:
            raise OpenCTITransportError("OPENCTI_DNS_FAILED")
        connection = http.client.HTTPConnection(
            target.host, target.port, timeout=self.config.read_timeout_seconds
        )
        submission_possible = False
        try:
            raw_socket = socket.create_connection(
                (target.addresses[0], target.port),
                timeout=self.config.connect_timeout_seconds,
            )
            raw_socket.settimeout(self.config.read_timeout_seconds)
            if target.scheme == "https":
                context = ssl.create_default_context()
                if self._ca_bundle_bytes is not None:
                    try:
                        context.load_verify_locations(cadata=self._ca_bundle_bytes.decode("ascii"))
                    except (UnicodeDecodeError, ssl.SSLError) as exc:
                        raise OpenCTITransportError("OPENCTI_CA_BUNDLE_INVALID") from exc
                connection.sock = context.wrap_socket(raw_socket, server_hostname=target.host)
            else:
                connection.sock = raw_socket
            default_port = 443 if target.scheme == "https" else 80
            rendered_host = f"[{target.host}]" if ":" in target.host else target.host
            host_header = (
                rendered_host if target.port == default_port else f"{rendered_host}:{target.port}"
            )
            submission_possible = mutation
            connection.request(
                "POST",
                target.graphql_path,
                body=body,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self.config.token.get_secret_value()}",
                    "Content-Type": content_type,
                    "Content-Length": str(len(body)),
                    "Host": host_header,
                    "User-Agent": f"cti-ai-trust-gateway/{__version__}",
                },
            )
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise OpenCTITransportError("OPENCTI_REDIRECT_BLOCKED")
            if not 200 <= response.status < 300:
                raise OpenCTITransportError("OPENCTI_HTTP_ERROR")
            content_length = response.getheader("Content-Length")
            if content_length and int(content_length) > self.config.max_response_bytes:
                raise OpenCTITransportError("OPENCTI_RESPONSE_TOO_LARGE")
            response_body = response.read(self.config.max_response_bytes + 1)
            if len(response_body) > self.config.max_response_bytes:
                raise OpenCTITransportError("OPENCTI_RESPONSE_TOO_LARGE")
            try:
                payload = json.loads(response_body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise OpenCTITransportError("OPENCTI_RESPONSE_INVALID") from exc
            if not isinstance(payload, dict):
                raise OpenCTITransportError("OPENCTI_RESPONSE_INVALID")
            if payload.get("errors"):
                raise OpenCTITransportError("OPENCTI_GRAPHQL_ERROR")
            data = payload.get("data")
            if not isinstance(data, dict):
                raise OpenCTITransportError("OPENCTI_RESPONSE_INVALID")
            return data
        except OpenCTITransportError as exc:
            if submission_possible and not exc.ambiguous:
                raise OpenCTITransportError(exc.code, ambiguous=True) from exc
            raise
        except (OSError, http.client.HTTPException) as exc:
            code = (
                "OPENCTI_SUBMISSION_UNKNOWN" if submission_possible else "OPENCTI_CONNECTION_FAILED"
            )
            raise OpenCTITransportError(code, ambiguous=submission_possible) from exc
        except (TypeError, ValueError) as exc:
            raise OpenCTITransportError(
                "OPENCTI_RESPONSE_INVALID", ambiguous=submission_possible
            ) from exc
        finally:
            connection.close()

    def _remote_identifier(self, value: object, limit: int) -> str:
        rendered = str(value)
        secret = self.config.token.get_secret_value() if self.config.token is not None else ""
        if (
            not rendered
            or len(rendered) > limit
            or not all(character.isalnum() or character in "._:/-" for character in rendered)
            or (secret and secret in rendered)
        ):
            raise OpenCTITransportError("OPENCTI_REMOTE_VALUE_INVALID")
        return rendered


def safe_transport_message(error: BaseException) -> str:
    if isinstance(error, OpenCTITransportError):
        return error.code
    return sanitize_message(error)
