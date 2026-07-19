# OpenCTI Phase 1 implementation handoff

> Historical pre-audit snapshot. Its counts, profile digest, package inventory, and security claims
> describe the implementation before independent hardening and must not be used as current proof.
> The authoritative current record is `HANDOFF_OPENCTI_PHASE1_AUDIT.md`; in particular, test-only
> fixtures are no longer packaged and repository `dist/` files are not release artifacts.

## Outcome

The local `feature/opencti-approved-delivery` worktree now implements evidence-gated, exact-byte
delivery of an approved STIX graph to an OpenCTI Draft. The network boundary is disabled and dry-run
by default, all plan/read interfaces remain offline, and live execution is CLI-only with a full plan
SHA-256 confirmation. A separate OpenCTI analyst approval remains mandatory.

This is an uncommitted local implementation. No commit, merge, rebase, tag, release, pull request,
push, fetch, pull, or other remote mutation was performed.

## Repository and release anchors

| Item | Verified value |
| --- | --- |
| Repository | `https://github.com/ag2020sa/cti-ai-trust-gateway.git` |
| Local branch | `feature/opencti-approved-delivery` |
| Authorized base/HEAD | `861e234bfe99b6950328a97d985dfe0f9acd2aa9` |
| Existing annotated release tag | `v0.1.0b2` |
| Existing release anchor | `4d9d016d5d0c186f85386100657a2cd1ab59b73a` |
| Package/API version | `0.1.0b2` (unchanged; no release performed) |
| OASIS schema commit | `c4f8d589acf2bdb3783655c89e0ffb6e150006ae` |
| OASIS schema digest | `43c2bf45bbaeeb44e5852553abffdebeaaa1584111d92d8a8d3a3101d8bd220f` |

Preflight confirmed the authorized five-commit chain, annotated tag target, read-only CI permissions,
pinned action SHAs, 57 bundled schemas, the schema aggregate digest, and a clean baseline before the
local feature branch was created. The release anchor and existing tag were not changed.

## OpenCTI research pins

| Component | Exact pin |
| --- | --- |
| OpenCTI platform | `148ceb414d1338d7c10ff79f0302d0a03dae332f` |
| PyCTI | `7.260715.0` |
| OpenCTI connectors | `b70a94b526574a040953cba73b3c76ec3ead6f21` |
| Compatibility profile | `opencti-7.260715.0` |
| Profile SHA-256 | `390ba9a91654d1f484a8558f286928522ffa3c1e5dbe0037443ae1c19daebabb` |

The pinned Draft schema, UI creation/import path, backend file path, PyCTI client, ImportFileStix,
and Document AI sources are linked in `docs/opencti-phase1.md`. The runtime uses a clean-room
standard-library HTTP adapter instead of PyCTI so verified TLS, SNI, custom CA selection,
prevalidated destination resolution, redirect blocking, and strict response bounds are mandatory.
No upstream source code was copied.

## Requirement matrix

| Requirement | Implementation evidence | Status |
| --- | --- | --- |
| Pinned offline compatibility | Strict YAML profile loader, embedded digest, 21 type/property rules, 38 relationship tuples | Complete |
| Mission-type support | Claims, exact evidence spans, STIX validation, compatibility rules for observables/entities/report/tool/channel/location | Complete |
| Dependency-safe graph | Reference closure, missing dependency/cycle/depth checks, control objects, zero dangling refs | Complete |
| Approval-only artifact | Persisted case, validator/policy/audit/span/review revalidation; mixed accept/reject handling | Complete |
| Exact reproducible bytes | Canonical JSON, source/candidate/validation/policy/review/profile/graph/artifact hashes | Complete |
| Provenance | Stable gateway provenance report and explicit source-only assurance disclaimer | Complete |
| Offline deterministic planning | Persisted plan and ordered operations; no DNS/network from check/plan/status/history/API | Complete |
| Expiry and concurrency | TTL, safe refresh only before any attempt, unique logical key, SQLite immediate reservation | Complete |
| Explicit execution | Disabled by default, `--execute`, full 64-hex plan hash, fresh snapshot/destination/capability gates | Complete |
| OpenCTI Draft contract | `draftWorkspaceAdd`, multipart `uploadAndAskJobImport`, markings/connectors/draft validation/work poll | Complete against pinned offline contract |
| Destination security | Exact IDNA allowlist, all-answer DNS validation, SSRF controls, HTTPS default, verified TLS/SNI, no redirects/proxies | Complete |
| Secret/error safety | Environment-only token, `SecretStr`, no token output, bounded/redacted persisted messages | Complete |
| Idempotency/recovery | Local duplicate NOOP, no blind retry, PARTIAL/UNKNOWN, explicit status-limited reconciliation | Complete; no exactly-once claim |
| Interface boundary | Seven CLI commands; API create/read only; UI readiness card and CLI-only warning | Complete |
| Offline fixtures | 19 original English/Arabic/mixed cases with exact pins/provenance, packaged in wheel | Complete |
| Operator documentation | README, `.env.example`, changelog, third-party notice, detailed Phase 1 guide | Complete |
| Live disposable OpenCTI | No suitable instance was available in this environment | Not run; limitation documented |

## Implementation map

- `src/cti_trust_gateway/compatibility/`: fail-closed profile loader and graph checker.
- `src/cti_trust_gateway/data/opencti/profiles/`: exact integrity-pinned compatibility profile.
- `src/cti_trust_gateway/core/canonical.py`: shared canonical bytes and SHA-256 helpers.
- `src/cti_trust_gateway/delivery/artifact.py`: persisted approval snapshot and exact artifact builder.
- `src/cti_trust_gateway/delivery/config.py`: bounded environment-only configuration.
- `src/cti_trust_gateway/delivery/security.py`: URL, allowlist, DNS, SSRF, and redaction controls.
- `src/cti_trust_gateway/delivery/transport.py`: strict GraphQL/Draft transport and work polling.
- `src/cti_trust_gateway/delivery/service.py`: planning, execution gates, state transitions, and reconciliation.
- `src/cti_trust_gateway/storage/repository.py`: normalized plans/attempts, reservations, and audit events.
- `src/cti_trust_gateway/cli/main.py`: `opencti check|plan|probe|deliver|status|history|reconcile`.
- `src/cti_trust_gateway/api/app.py`: network-free plan creation/read/history endpoints only.
- `src/cti_trust_gateway/web/templates/case.html`: Draft readiness and exact unauthenticated-UI warning.
- `tests/fixtures/opencti_phase1/`: authoritative 19-case synthetic registry; force-included in the wheel.
- `tests/unit/test_opencti_*.py`, `tests/adversarial/test_opencti_delivery.py`, and
  `tests/integration/test_opencti_interfaces.py`: profile, artifact, security, state, contract, CLI,
  API, and UI verification.

Existing policy, review, audit, manifest, candidate, and export boundaries remain intact. The
package/API version and existing OASIS schema data were not changed.

## Final local verification

All commands ran with Python `3.13.5` on Windows.

| Gate | Result |
| --- | --- |
| Ruff format/check | Pass |
| mypy strict | Pass, 38 source files |
| Bandit | Pass |
| pip-audit | No known vulnerabilities; local project itself is not on PyPI and is skipped |
| Full suite | 189 passed |
| Full branch-aware coverage | 89.70%, required 85% |
| Independent adversarial suite | 115 passed |
| OpenCTI critical-path suite | 65 passed |
| OpenCTI critical-path coverage | 95.97%, required 90% |
| Synthetic benchmark | 100 executed, 0 mismatches |
| Build | Wheel and sdist built successfully |
| Twine | Both distributions passed |
| Wheel contents | Profile plus 19-case registry and README present under package data |
| Isolated wheel install | Pass outside source checkout; 57 schemas, schema/profile digests, 19 fixtures, validation, API version, CLI help, and five-case demo verified |
| `git diff --check` | Pass; only Windows LF-to-CRLF informational warnings |

One third-party deprecation warning is emitted by the installed FastAPI test-client compatibility
layer (`httpx`/Starlette); it does not fail tests and is not caused by the OpenCTI code.

The final local distributions are:

- `dist/cti_ai_trust_gateway-0.1.0b2-py3-none-any.whl`
- `dist/cti_ai_trust_gateway-0.1.0b2.tar.gz`

The isolated verifier prints:

```text
release_install_ok version=0.1.0b2 schemas=57 schema_sha256=43c2bf45bbaeeb44e5852553abffdebeaaa1584111d92d8a8d3a3101d8bd220f opencti_profile_sha256=390ba9a91654d1f484a8558f286928522ffa3c1e5dbe0037443ae1c19daebabb opencti_fixtures=19 validation=EXECUTED
```

## Reproduction commands

```powershell
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\python.exe -m bandit -q -c pyproject.toml -r src
.\.venv\Scripts\python.exe -m pip_audit --local
.\.venv\Scripts\python.exe -m pytest tests\adversarial -q
.\.venv\Scripts\python.exe -m pytest --cov --cov-branch --cov-report=term --cov-fail-under=85
.\.venv\Scripts\python.exe -m pytest tests\unit\test_opencti_compatibility.py tests\unit\test_opencti_artifact.py tests\unit\test_opencti_security.py tests\adversarial\test_opencti_delivery.py --cov=cti_trust_gateway.compatibility --cov=cti_trust_gateway.delivery --cov-branch --cov-report=term --cov-fail-under=90
.\.venv\Scripts\python.exe scripts\run_synthetic_benchmark.py
.\.venv\Scripts\python.exe -m build
.\.venv\Scripts\python.exe -m twine check dist\*
```

Then create a new temporary virtual environment outside the checkout, install only the wheel, copy
`scripts/verify_release_install.py` into that temporary directory, and run it from there. Run
`cti-trust --help` and `cti-trust demo` from the same isolated environment.

## Environment-limited checks and remaining work

- Python 3.12 was not installed locally. CI is configured for both 3.12 and 3.13.
- Docker was not installed locally. CI retains a Docker build and live healthcheck job.
- A disposable OpenCTI `7.260715.0` platform plus ImportFileStix connector was not available, so no
  live Draft was created. Do not describe the adapter as live-certified or production ready.
- The UI and API remain intentionally unauthenticated and cannot perform live delivery. Production
  use requires authentication/authorization, durable signed audit storage, operational monitoring,
  and an operator-owned cleanup/runbook process.
- OpenCTI Draft approval is deliberately outside the gateway. PARTIAL/UNKNOWN states require
  operator inspection and explicit reconciliation; the implementation makes no atomicity or
  exactly-once guarantee.

## Safe next step

Review this local diff, run the configured Python 3.12 and Docker CI jobs, and execute the documented
disposable OpenCTI contract test with a synthetic token and synthetic fixture only. If those pass,
an authorized maintainer can decide how to split commits and whether to open a pull request. This
handoff intentionally performs none of those remote or release actions.
