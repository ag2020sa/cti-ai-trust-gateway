# OpenCTI Phase 1 independent audit and hardening handoff

## Audit status

This document is the evidence register for an independent review of the uncommitted
`feature/opencti-approved-delivery` worktree. It is not a release record and does not certify live
OpenCTI interoperability. The package version remains `0.1.0b2`; the recommended next feature
prerelease, after all release-owner checks, is `0.2.0b1`.

## Pre-correction finding register

The following failures were reproduced or established from executable code before corrective edits.
Line references describe the pre-correction worktree and are preserved by the external pre-edit diff
capture recorded below.

| ID | Severity | Finding | Pre-correction evidence | Required disposition |
| --- | --- | --- | --- | --- |
| AUD-001 | P1 | Canonical JSON accepted non-finite numbers. | `core/canonical.py` called `json.dumps` without `allow_nan=False`; an isolated probe produced `{"x":NaN}`. | Reject NaN and infinities everywhere canonical bytes or digests are created; add regressions. |
| AUD-002 | P1 | The confirmation digest did not bind the plan identity or expiry. | `delivery/service.py:_plan_digest_payload` excluded `id` and `expires_at`; isolated probes showed both a forged ID and a one-year expiry extension still passed `verify_plan_hash`. | Bind immutable timing data, enforce content-addressed ID invariants, and test field-by-field tampering. |
| AUD-003 | P1 | Execution-affecting destination options were absent from the confirmed fingerprint. | Connect/read timeout, response bound, polling policy, private/loopback policy, and plan TTL were omitted from `DestinationFingerprint`. | Persist and hash a bounded delivery-options snapshot. |
| AUD-004 | P1 | A configured platform version could diverge from the immutable compatibility profile. | Planning accepted any non-empty `expected_version` and the probe compared only against that mutable configuration. | Require the exact profile platform version during planning and execution. |
| AUD-005 | P1 | Delivery attempt transitions were unrestricted and non-CAS. | `Repository.update_delivery_attempt` accepted arbitrary source/target states; terminal reversal and stale `PROCESSING` states were possible. | Add an atomic transition table, compare-and-set predicates, stale-claim handling, and transition tests. |
| AUD-006 | P1 | A transport failure during request submission could be misclassified as safely retryable. | The request path set its submission flag only after `connection.request()` returned. | Treat failure from the first possible request-byte boundary as ambiguous and block blind retry. |
| AUD-007 | P1 | The OpenCTI custom `channel` representation was treated as if it were an OASIS standard type. | The compatibility profile and fixture accepted a bare `channel`; the pinned OpenCTI connector contract uses the `new-sdo` extension definition `extension-definition--be4ebfff-c203-4698-8853-4797fa138ec7`. | Validate the exact pinned custom representation separately from the 57 immutable OASIS schemas. |
| AUD-008 | P1 | Duplicate-ID semantics and order-only equivalence were not deterministic. | Validation rejected every duplicate, artifact indexing was last-write-wins, and canonicalization preserved semantically irrelevant input ordering. | Allow only byte-identical duplicates, reject conflicts, and normalize set-like STIX arrays before hashing. |
| AUD-009 | P1 | Policy/artifact markings could be mixed with arbitrary configured file markings. | Plan creation unioned artifact markings with `CTI_GATEWAY_OPENCTI_FILE_MARKING_IDS`. | Derive upload markings only from the approved artifact and its policy/profile contract. |
| AUD-010 | P1 | Crash and persistence-failure recovery was underspecified. | Reservation committed `PROCESSING` before network work; a crash or callback persistence error could leave an unreconcilable state with no safe automatic recovery. | Persist explicit phases conservatively and ensure uncertainty never causes an automatic resend. |
| AUD-011 | P2 | Frozen Pydantic models were not deeply immutable. | An isolated probe mutated `DeliveryPlan.exclusion_reasons` in place despite `frozen=True`. | Replace nested mutable mappings with immutable, canonical representations or validate defensive copies. |
| AUD-012 | P2 | Read/history interfaces and review text were not consistently bounded. | OpenCTI API/CLI list routes and repository methods returned unbounded rows; request strings lacked explicit maxima. | Add validated pagination and bounded request fields. |
| AUD-013 | P2 | The production wheel intentionally included test-only fixture data and omitted required notice verification. | `pyproject.toml` force-included the 19-case test registry; the isolated verifier depended on it. | Remove test fixtures from wheel package data and verify license/notice resources independently. |
| AUD-014 | P2 | CI gates were weaker than the audit contract. | Overall branch threshold was 85%, critical aggregate was 90%, and no per-critical-file 90% check existed. | Enforce overall >=89%, critical aggregate >=95%, and every named critical file >=90%. |
| AUD-015 | P2 | Release wording conflated historical `v0.1.0b2` artifacts with the unreleased Phase 1 diff. | README and the original handoff advertised OpenCTI work next to published `0.1.0b2` installation instructions and called repo `dist` outputs final. | Clearly separate historical release instructions from non-release local audit artifacts. |

## Preserved pre-edit evidence

Before any audit correction, repository state and the complete tracked diff were captured outside the
repository at:

`%TEMP%\cti-opencti-audit-0728b0565e2b4a4087e1d64ee20dbd25`

The capture includes porcelain status, tracked name/status and stat output, the complete tracked diff,
untracked file inventory, and ignored-file status. At that point the branch was
`feature/opencti-approved-delivery` at
`861e234bfe99b6950328a97d985dfe0f9acd2aa9`; no merge, rebase, cherry-pick, revert, or bisect was in
progress. The pre-correction suite passed 189 tests on Python 3.13.5, which established that the
existing tests did not cover the reproduced failures above.

## Correction and final verification

Decision: **AUDITED_AND_HARDENED**. All confirmed P0/P1 findings are closed. This decision is for
the reviewed local implementation and pinned offline contract only; it is not a production-readiness
or live-OpenCTI certification.

### Final disposition of findings

| ID | Severity | Correction and regression evidence | Status |
| --- | --- | --- | --- |
| AUD-001 | P1 | Strict canonical type/Unicode/finite-number validation; NaN/Infinity regressions. | Closed |
| AUD-002 | P1 | Full stored-plan digest binds ID, creation/expiry, payload and content-addressed ID invariant; field-tamper tests. | Closed |
| AUD-003 | P1 | Immutable `DeliveryOptions` binds every network/poll/TTL setting; stale-option tests. | Closed |
| AUD-004 | P1 | Planning and execution require profile version `7.260715.0`; mismatch regressions. | Closed |
| AUD-005 | P1 | SQLite `BEGIN IMMEDIATE`, explicit transition table and optional expected-state CAS; valid/invalid transition tests. | Closed |
| AUD-006 | P1 | Mutation uncertainty starts before `connection.request`; malformed/timeout/GraphQL regressions preserve `UNKNOWN`/`PARTIAL`. | Closed |
| AUD-007 | P1 | Exact OpenCTI `channel` new-SDO extension contract is validated separately from OASIS schemas. | Closed |
| AUD-008 | P1 | Identical duplicates are deterministic, conflicting IDs block, and set-like STIX order is normalized. | Closed |
| AUD-009 | P1 | The arbitrary marking environment field was removed; upload markings come only from the approved artifact. | Closed |
| AUD-010 | P1 | Reservation is durably `PREPARED`; mutation boundary is `SUBMITTED`; pre-network crash can be abandoned, uncertainty cannot resend. | Closed |
| AUD-011 | P2 | Nested mappings use mutation-blocking `FrozenDict`; deep-mutation regressions pass. | Closed |
| AUD-012 | P2 | Repository/API/CLI pagination and request strings are bounded. | Closed |
| AUD-013 | P2 | Wheel fixture force-include removed; isolated install proves fixtures absent and notices present. | Closed |
| AUD-014 | P2 | CI now enforces overall 89%, combined critical 95%, and every critical module/path 90%. | Closed |
| AUD-015 | P2 | Historical release and unreleased Phase 1 artifacts are explicitly separated; next version is `0.2.0b1`. | Closed |
| AUD-016 | P1 | Unmodeled assertion properties and candidate Report narrative could bypass claim-level review. Artifact construction now excludes assertion-smuggling fields and rewrites provenance. | Closed |
| AUD-017 | P1 | Raw mutable case state was incompletely bound to review/artifact decisions. Semantic analysis/review snapshots and raw/canonical candidate digests now fail closed on tampering. | Closed |
| AUD-018 | P1 | Direct transport invocation did not independently revalidate artifact/plan/destination, and remote values were too permissive. The adapter now verifies all inputs and bounded token-safe remote IDs. | Closed |
| AUD-019 | P1 | A CA path could change between fingerprinting and TLS use. The adapter now caches one bounded regular-file trust snapshot and binds its digest to the plan. | Closed |
| AUD-020 | P1 | Concurrent review/audit read-modify-write operations could lose events. They now serialize under `BEGIN IMMEDIATE`; two-process chain preservation passes. | Closed |

### Reviewed inventory and traceability

The complete pre-edit tracked diff and untracked inventory remain in the external evidence capture.
The final feature inventory is 41 files: 17 tracked modifications and 24 untracked feature files.
Reviewed tracked paths are `.env.example`, `.github/workflows/ci.yml`, `CHANGELOG.md`, `README.md`,
`THIRD_PARTY_NOTICES.md`, `pyproject.toml`, `scripts/verify_release_install.py`, API/CLI, claims,
core service, domain models, evidence engine, repository, STIX validator, case template, and
`tests/unit/test_stix.py`. Reviewed new paths are both handoffs, this Phase 1 guide, the critical
coverage script, compatibility package, canonical/snapshot helpers, the pinned profile, all six
delivery package files, both adversarial suites, the 19-case fixture registry and README, the
OpenCTI interface integration suite, and the three focused unit suites. The 57 OASIS schema bytes
were read/verified and not rewritten.

| Requirement | Code | Primary regression evidence |
| --- | --- | --- |
| Four independent gates | `domain/models.py`, `delivery/artifact.py`, API/CLI/UI | compatibility, artifact, interface and hardening suites |
| Exact approved graph and evidence closure | `delivery/artifact.py`, `core/snapshots.py` | assertion smuggling, narrative Report, dependency/cycle/order/tamper tests |
| Plan binding and explicit execution | `delivery/service.py`, `delivery/config.py`, CLI | full-field tamper, stale plan/version/options and full-digest tests |
| Pinned Draft GraphQL contract | `delivery/transport.py` static operations | multipart variables, connector, marking, work-state and forbidden-call tests |
| TLS/SSRF/DNS/secret controls | `delivery/security.py`, `delivery/transport.py` | all-answer DNS, mapped IPv6, HTTPS, origin, CA snapshot, redirect/token tests |
| Ledger/idempotency/recovery | `storage/repository.py`, `delivery/service.py` | state matrix, ambiguity, persistence failure, two-process reservation/audit tests |
| Local-only API/UI | `api/app.py`, `web/templates/case.html` | route inventory and network-forbidden interface tests |
| Package/runtime resources | `pyproject.toml`, verifier, notices | outside build, Twine and isolated install |

### Pinned contract and four-gate result

Official source review used OpenCTI commit `148ceb414d1338d7c10ff79f0302d0a03dae332f`,
PyCTI `7.260715.0`, and connectors commit
`b70a94b526574a040953cba73b3c76ec3ead6f21`. The profile digest is
`d3bb230c922ec7fbbc7cc4c915382ac6717de91e59821c8d8215c069979dce3f`. The exact custom Channel
representation uses `type: channel` with new-SDO extension definition
`extension-definition--be4ebfff-c203-4698-8853-4797fa138ec7`; it is not labeled standard OASIS
STIX. Unknown types, properties, versions and illegal relationship tuples fail closed.

`VALID_STIX`, `OPENCTI_COMPATIBLE`, `EVIDENCE_VERIFIED`, and `DELIVERY_AUTHORIZED` are separate
immutable booleans on assessments, artifacts and plans, are returned by local API/CLI paths, and
are displayed independently in the UI. Negative tests cover valid-but-incompatible STIX, custom
Channel handling, evidence absence, policy/size rejection, ungrounded relationships, schema
unavailability, invalid STIX, unknown custom objects, and illegal endpoint tuples.

### Artifact, plan and Draft transport result

The artifact is content-addressed canonical JSON, deeply immutable after validation, and fails
closed for non-finite values, invalid Unicode, conflicting duplicate IDs, assertion smuggling,
unapproved dependencies, graph limits and snapshot drift. Candidate Report narrative is excluded;
a deterministic gateway Report references approved objects only and contains integrity/provenance
facts rather than unverified analysis. TLP:RED is blocked and `fileMarkings` is derived only from
approved artifact markings.

The 64-character confirmation is a canonical SHA-256 digest, not a signature. It binds the stored
plan ID/logical key, case/source/candidate/validation/policy/review/profile/artifact/graph digests,
exact payload size and IDs, origin, expected version, connector ID/name, markings, all delivery
options, creation/expiry and operations. Secrets are excluded. Execution reloads the authoritative
stored plan and rejects prefixes, foreign digests, caller changes and stale snapshots.

The clean-room adapter uses static GraphQL documents and variables for `draftWorkspaceAdd`, then
official multipart `uploadAndAskJobImport` with `validationMode: draft`, `draftId`,
`noTriggerImport: false`, connector configuration and artifact-derived markings. Polling is bounded.
Production code contains no reachable live-graph CRUD, `draftWorkspaceValidate`, `stixBundlePush`,
RabbitMQ, auto-approval, auto-promotion, rollback or validation-bypass path. This is contract-tested,
not live-verified.

### Network, ledger and interface result

HTTPS is mandatory, including loopback. URL credentials/paths/query/fragment, non-allowlisted
authorities, mixed DNS answers, unsafe/private classes without exact opt-in, alternate/mapped IP
forms and redirects fail closed. The socket connects to a vetted address while TLS verifies the
original hostname/SNI; `http.client` does not inherit environment proxies. The CA file is a bounded,
non-symlink snapshot whose digest is plan-bound. Tokens and raw remote errors are neither returned
nor persisted. Post-request-boundary failures remain ambiguous and prohibit blind retry.

SQLite uses `NullPool`, bounded busy timeout, unique logical keys, immediate write transactions and
atomic state predicates. Two independent processes cannot reserve the same plan, and concurrent
audit writers preserve both events and a valid chain. `PREPARED`, `SUBMITTED`, `PROCESSING`,
`SUCCEEDED`, `FAILED`, `PARTIAL`, `UNKNOWN` and `NOOP` transitions are explicitly constrained;
blocked plans remain `BLOCKED`. Reconciliation is status-only and never resends or promotes.

The CLI exposes exactly the documented OpenCTI check/plan/probe/deliver/status/history/reconcile
workflow. Live execution requires environment enablement, `--execute`, and the exact full stored
digest. API route inventory proves planning/history/read operations are local only; there is no
probe/deliver/reconcile/generic outbound API route. The unauthenticated UI shows readiness, four
gates, profile/artifact digests, included/excluded counts, history and the CLI-only warning.

### Final verification evidence

All results below were freshly reproduced on Windows with Python 3.13.5:

| Gate | Result |
| --- | --- |
| Ruff format and lint | Pass |
| strict mypy | Pass, 39 source files |
| Bandit | Pass |
| pip-audit `--local` | No known vulnerabilities; local unpublished package skipped |
| Full suite | 224 passed |
| Independent adversarial suite | 150 passed |
| Overall branch-aware coverage | 90.44% (minimum 89%) |
| Critical-path suite/report | 102 passed; combined 96.07% (minimum 95%) |
| Synthetic benchmark | 100 mutations, 0 mismatches |
| Started API `/health` | HTTP 200: `{"status":"ok","mode":"local-demo","version":"0.1.0b2"}` |
| `git diff --check` | Pass; only line-ending notices |

Branch-aware statement+branch results from the final coverage JSON:

| Critical path | Covered/total | Percent |
| --- | ---: | ---: |
| `compatibility/checker.py` | 227/240 | 94.58% |
| `compatibility/profile.py` | 104/104 | 100.00% |
| `core/canonical.py` | 67/69 | 97.10% |
| `core/snapshots.py` | 21/21 | 100.00% |
| `delivery/artifact.py` | 316/325 | 97.23% |
| `delivery/config.py` | 120/126 | 95.24% |
| `delivery/security.py` | 126/131 | 96.18% |
| `delivery/service.py` | 210/223 | 94.17% |
| `delivery/transport.py` | 272/280 | 97.14% |
| `storage/repository.py` delivery paths | 198/210 | 94.29% |

Schema verification and the isolated installed-wheel verifier both proved 57 JSON schemas, commit
`c4f8d589acf2bdb3783655c89e0ffb6e150006ae`, and aggregate digest
`43c2bf45bbaeeb44e5852553abffdebeaaa1584111d92d8a8d3a3101d8bd220f`.

### Packaging, provenance and scan result

Build output went to a unique `%TEMP%\cti-opencti-package-<id>` directory outside the repository;
repository `dist/` was untouched. Build and Twine passed. The wheel contains 112 files: all 57
schemas, one pinned OpenCTI profile, policy files, templates/static resources, package license and
`THIRD_PARTY_NOTICES.md`. It contains zero OpenCTI test fixtures and no database, `.env`, cache,
coverage, Git or temporary file. The sdist contains 415 files. An isolated wheel install outside the
checkout passed schema/profile/notices validation, invalid-schema fail-closed flow, CLI help, and
the five-verdict demo (`PASS`, `REJECT`, `QUARANTINE`, `ABSTAIN`, `REVIEW`).

The 19 English/Arabic/mixed fixtures are original test-only data and remain only in the sdist/source
test tree, not the wheel. OpenCTI mappings and operations are independently authored from pinned
public interface facts; no upstream implementation or fixture was copied. Exact upstream links and
license distinction are in `THIRD_PARTY_NOTICES.md`.

Gitleaks was unavailable, so no gitleaks-pass claim is made. A clearly labeled fallback scan for
common cloud/GitHub/OpenAI tokens, private-key blocks and long Bearer credentials passed with no
matches. Package inventory additionally found no forbidden paths or fixture data.

### Exact limitations and release blocker

- No real or disposable OpenCTI instance was contacted; no live interoperability claim is made.
- Docker and Python 3.12 were unavailable locally. Python 3.12/3.13 and Docker build/health remain
  mandatory, SHA-pinned CI gates.
- SQLite provides conservative local idempotency, not distributed exactly-once delivery.
- Authentication, RBAC, CSRF protection, external durable/signed audit retention and production
  operational hardening remain out of scope; this is a research beta.
- One upstream Starlette/FastAPI test-client deprecation warning remains non-failing.

Release blocker: these local `0.1.0b2` distributions differ from the published release and must
never replace or attach to `v0.1.0b2`. The next feature release must use a new version; recommended
`0.2.0b1`. The version was not bumped during this audit. Published `v0.1.0b2` was not modified,
replaced, deleted or republished.

No commit, push, PR, tag, release, upload, Dependabot interaction, GitHub mutation, external OpenCTI
read/write, or other remote mutation occurred. Final branch is
`feature/opencti-approved-delivery`; HEAD remains
`861e234bfe99b6950328a97d985dfe0f9acd2aa9`, with the intended dirty feature tree preserved.
