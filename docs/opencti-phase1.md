# OpenCTI Phase 1: approved Draft delivery

> **OpenCTI Draft delivery is EXPERIMENTAL, disabled by default, contract-tested, and not live-verified.**

This is a research-beta compatibility integration, not a production certification. OpenCTI and
STIX names are used solely for compatibility identification; no endorsement is implied.

## Purpose and assurance boundary

Phase 1 moves only a persisted, evidence-backed, policy-approved STIX artifact into an isolated
OpenCTI Draft workspace. It does not publish directly to the live knowledge base, does not approve
the OpenCTI Draft, and does not turn a gateway verdict into a claim of global truth. An OpenCTI
analyst must still review and approve the Draft.

The four persisted delivery gates remain separate:

1. `VALID_STIX` proves that the candidate passed the mandatory, pinned STIX validator.
2. `OPENCTI_COMPATIBLE` proves conformance to the pinned OpenCTI profile.
3. `EVIDENCE_VERIFIED` proves that selected objects and relationships are grounded or explicitly
   approved under the review policy.
4. `DELIVERY_AUTHORIZED` proves that artifact closure, policy, integrity, and limits pass.
5. Offline planning records the intended destination and operations without DNS or network access.
6. Explicit CLI execution probes the destination, rechecks every gate, creates a Draft, uploads the
   exact artifact, and records the import work state.

`check`, `plan`, `status`, `history`, and all OpenCTI API endpoints are network-free. Only `probe`,
`deliver --execute`, and `reconcile` can contact OpenCTI.

## Pinned public contract

The compatibility profile is `opencti-7.260715.0` with SHA-256
`d3bb230c922ec7fbbc7cc4c915382ac6717de91e59821c8d8215c069979dce3f`.

| Component | Pin |
| --- | --- |
| OpenCTI platform | `148ceb414d1338d7c10ff79f0302d0a03dae332f` |
| PyCTI | `7.260715.0` |
| OpenCTI connectors | `b70a94b526574a040953cba73b3c76ec3ead6f21` |
| OASIS STIX schema tree | `c4f8d589acf2bdb3783655c89e0ffb6e150006ae` |
| OASIS schema aggregate SHA-256 | `43c2bf45bbaeeb44e5852553abffdebeaaa1584111d92d8a8d3a3101d8bd220f` |

The contract was derived from these public upstream sources at the exact platform and connector
commits:

- [PyCTI client implementation](https://github.com/OpenCTI-Platform/opencti/blob/148ceb414d1338d7c10ff79f0302d0a03dae332f/client-python/pycti/api/opencti_api_client.py)
- [Draft workspace GraphQL schema](https://github.com/OpenCTI-Platform/opencti/blob/148ceb414d1338d7c10ff79f0302d0a03dae332f/opencti-platform/opencti-graphql/src/modules/draftWorkspace/draftWorkspace.graphql)
- [UI Draft creation path](https://github.com/OpenCTI-Platform/opencti/blob/148ceb414d1338d7c10ff79f0302d0a03dae332f/opencti-platform/opencti-front/src/private/components/common/files/import_files/useCreateDraft.ts)
- [UI import path](https://github.com/OpenCTI-Platform/opencti/blob/148ceb414d1338d7c10ff79f0302d0a03dae332f/opencti-platform/opencti-front/src/components/UploadImport.tsx)
- [Backend indexed-file/import implementation](https://github.com/OpenCTI-Platform/opencti/blob/148ceb414d1338d7c10ff79f0302d0a03dae332f/opencti-platform/opencti-graphql/src/domain/indexedFile.ts)
- [ImportFileStix connector](https://github.com/OpenCTI-Platform/connectors/tree/b70a94b526574a040953cba73b3c76ec3ead6f21/internal-import-file/import-file-stix)
- [ImportFileStix README](https://github.com/OpenCTI-Platform/connectors/blob/b70a94b526574a040953cba73b3c76ec3ead6f21/internal-import-file/import-file-stix/README.md)
- [Document AI connector README](https://github.com/OpenCTI-Platform/connectors/blob/b70a94b526574a040953cba73b3c76ec3ead6f21/internal-import-file/import-document-ai/README.md)

No upstream source was copied. The adapter is a small clean-room implementation of the public
GraphQL contract. PyCTI is not a runtime dependency because the pinned client defaults TLS
verification off; this gateway requires verified TLS, controlled CA selection, pinned destination
resolution, bounded responses, and blocked redirects.

## Compatibility profile

The profile permits these object types:

`attack-pattern`, `identity`, `location`, `intrusion-set`, `malware`, `vulnerability`, `tool`,
`channel`, `report`, `marking-definition`, `extension-definition`, `relationship`,
`autonomous-system`, `domain-name`, `email-addr`, `file`, `ipv4-addr`, `ipv6-addr`, `mac-addr`,
`url`, and `windows-registry-key`.

The profile contains an explicit property allowlist for every type, allowed source/type/target
relationship tuples, a dependency-depth limit of 32, and artifact limits of 1,000 objects and
5 MiB. The checker fails closed on unsupported types, unsupported or custom properties, version
mismatches, illegal relationships, missing references, dependency cycles, and size/depth limits.
`marking-definition` and `extension-definition` are control/dependency objects; they are not
independently analyst-approved intelligence.

TLP:RED is blocked by default using both known standard marking-definition IDs in the profile.
Upload markings are derived only from the approved artifact, must be present in the destination
probe, and are translated from standard IDs to OpenCTI internal IDs before upload.

## Exact artifact and provenance

Artifact construction reads the persisted case only. It verifies the hash-chained audit history,
source digest, candidate raw/canonical digests, validator/schema digest, policy digest, exact source
span slices, and the current approval snapshot. PASS objects are eligible; REVIEW/ABSTAIN objects
require an explicit eligible analyst acceptance; REJECT/QUARANTINE objects are excluded. Required
dependencies and control objects are included only when safe. A zero-dangling-reference check is a
hard gate.

Every artifact adds a stable gateway provenance `report` that records the case, source, candidate,
validation, policy, review snapshot, profile, graph, and artifact digests plus the assurance
disclaimer. Canonical JSON bytes are fixed before planning. Delivery recomputes them from the
immutable stored artifact and verifies their exact size and SHA-256 before submission.

## Plan and delivery state model

A plan fingerprints the normalized destination origin, expected platform version, import connector
UUID and connector name, host allowlist digest, optional CA-bundle digest, bounded delivery options,
artifact, approvals, profile, markings, and ordered operations. Its full SHA-256 is the execution
confirmation. Equivalent plans share one
logical key. An expired PREPARED plan may be refreshed only when no delivery attempt exists.

Live execution requires all of the following:

- `CTI_GATEWAY_OPENCTI_ENABLED=true` and a non-placeholder token;
- `--execute` plus the complete 64-character `--confirm-plan-sha256` value;
- an unexpired, untampered, PREPARED or previously SUCCEEDED plan;
- a current approval/artifact snapshot matching the persisted plan;
- the exact configured destination fingerprint;
- a successful probe of version `7.260715.0`, the configured active UUIDv4 connector with type
  `INTERNAL_IMPORT_FILE`, exact configured name, `application/json` scope, and all artifact marking
  IDs.

SQLite uses a unique logical plan key and an immediate write reservation so concurrent executors
cannot both begin. A successful equivalent execution produces a local `NOOP`; this is local
idempotency, not an exactly-once guarantee across OpenCTI or network failures.

The adapter invokes `draftWorkspaceAdd`, then multipart `uploadAndAskJobImport` with the artifact as
`variables.file`, `fileMarkings`, the selected connector, `validationMode: draft`, `draftId`, and
`noTriggerImport: false`. It polls the returned work. A timeout or connection loss after submission
becomes `UNKNOWN` or `PARTIAL`, blocks blind retry, and requires `reconcile ATTEMPT_ID`. If remote
state cannot be established, an operator must inspect the Draft/import work and clean up manually.
The gateway never claims atomicity or exactly-once delivery.

## Configuration

All values come from environment variables. CLI URL/token flags are intentionally absent.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CTI_GATEWAY_OPENCTI_ENABLED` | `false` | Master switch for live execution |
| `CTI_GATEWAY_OPENCTI_URL` | empty | Base origin only; HTTPS is mandatory |
| `CTI_GATEWAY_OPENCTI_TOKEN` | empty | Bearer token; held as a secret and never rendered |
| `CTI_GATEWAY_OPENCTI_IMPORT_CONNECTOR_ID` | empty | Exact ImportFileStix UUIDv4 |
| `CTI_GATEWAY_OPENCTI_IMPORT_CONNECTOR_NAME` | `ImportFileStix` | Exact connector name |
| `CTI_GATEWAY_OPENCTI_EXPECTED_VERSION` | `7.260715.0` | Exact platform version |
| `CTI_GATEWAY_OPENCTI_HOST_ALLOWLIST` | empty | Comma-separated exact hostnames/IPs |
| `CTI_GATEWAY_OPENCTI_CA_BUNDLE` | empty | Optional non-symlink CA bundle |
| `CTI_GATEWAY_OPENCTI_ALLOW_PRIVATE` | `false` | Opt in to private addresses for HTTPS |
| `CTI_GATEWAY_OPENCTI_ALLOW_LOOPBACK` | `false` | Opt in to loopback addresses; HTTPS still required |
| `CTI_GATEWAY_OPENCTI_MAX_OBJECTS` | `1000` | Local object bound |
| `CTI_GATEWAY_OPENCTI_MAX_BYTES` | `5242880` | Local canonical artifact byte bound |
| `CTI_GATEWAY_OPENCTI_CONNECT_TIMEOUT` | `10` | Connect timeout in seconds |
| `CTI_GATEWAY_OPENCTI_READ_TIMEOUT` | `30` | Read timeout in seconds |
| `CTI_GATEWAY_OPENCTI_MAX_RESPONSE_BYTES` | `1048576` | Maximum GraphQL response body |
| `CTI_GATEWAY_OPENCTI_POLL_ATTEMPTS` | `10` | Bounded work polls |
| `CTI_GATEWAY_OPENCTI_POLL_INTERVAL` | `2` | Seconds between polls |
| `CTI_GATEWAY_OPENCTI_PLAN_TTL` | `900` | Plan validity in seconds |

## CLI workflow

```bash
cti-trust opencti check CASE_ID
cti-trust opencti plan CASE_ID --output plan.json
cti-trust opencti probe
cti-trust opencti deliver PLAN_ID
cti-trust opencti deliver PLAN_ID --execute --confirm-plan-sha256 FULL_64_HEX_SHA256
cti-trust opencti status PLAN_ID
cti-trust opencti history --case-id CASE_ID
cti-trust opencti reconcile ATTEMPT_ID
```

The first `deliver` command is a dry run. `probe` is useful for configuration validation but does
not replace the execution-time probe.

## API and UI boundary

The unauthenticated API can only create/read plans and read attempt history:

- `POST /api/v1/opencti/plans/{case_id}`
- `GET /api/v1/opencti/plans?case_id=...`
- `GET /api/v1/opencti/plans/{plan_id}`
- `GET /api/v1/opencti/plans/{plan_id}/history`

There is no live-delivery, probe, or reconcile HTTP endpoint. The case UI shows readiness and the
exact warning: “Live OpenCTI delivery is CLI-only in this unauthenticated research beta.”

## Network and secret controls

Destination parsing rejects credentials, paths, queries, fragments, invalid ports, and hosts not
on the exact IDNA-normalized allowlist. DNS resolution validates every returned address and blocks
metadata, link-local, multicast, unspecified, reserved, and private/loopback networks unless the
specific opt-in applies. The connection uses a prevalidated address while TLS verifies the original
hostname with SNI. System trust or an explicit CA bundle is used; redirects, proxies, TLS bypass,
unbounded bodies, and automatic delivery retries are not used. Authorization values and raw remote
error bodies are not persisted or printed, and persisted messages are redacted and bounded.

## Tests and non-goals

The Phase 1 test registry contains 19 original synthetic English, Arabic, and mixed fixtures covering
supported observables/entities, legal and illegal relationships, custom properties, missing and
cyclic dependencies, version mismatch, and TLP:RED. It is used by deterministic offline contract
tests and is intentionally excluded from the wheel. No real reports, destination token, or OpenCTI
database data is included.

No disposable OpenCTI instance was available for this implementation run, so the GraphQL/Draft
path is verified by pinned-source research and offline contract doubles, not by a live platform.
This phase therefore makes no production-readiness, live interoperability, atomicity, or
exactly-once claim. A disposable instance, authenticated UI/API, external durable audit store, and
operator-approved cleanup automation remain future work.

The UI/API remain an unauthenticated research beta with no RBAC or CSRF protection. Live delivery
is CLI-only, contract-tested against pinned sources, and never auto-promotes a Draft to the live
graph.
