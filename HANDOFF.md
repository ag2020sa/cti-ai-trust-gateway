# CTI AI Trust Gateway handoff

> **Post-audit note (2026-07-17):** This file began as the pre-audit MVP handoff. The independent
> results, fixes, and current command evidence are in `AUDIT_REPORT.md` and `HANDOFF_PHASE2.md`.
> Deterministic source checks, optional semantic verification, human review, unavailable checks,
> and security heuristics are separate assurance states. PASS now requires executed mandatory
> validation; REJECT/QUARANTINE cannot be accepted or exported. This remains a local demo, not a
> production or compliance claim.

## Project path

The repository root is the directory containing this file.

The directory is an initialized Git repository on `main` with no commits. Nothing was committed,
pushed, published, or sent to GitHub.

## Implemented features

- Safe TXT, Markdown, and PDF parsing with SHA-256, upload limits, filename checks, UTF-8 handling,
  language detection, page text, page/character offsets, PDF span metadata, and immutable original
  evidence.
- Explainable visible/hidden instruction checks, Unicode controls, tiny/near-white/out-of-bounds
  PDF text, duplicate text layers, and declared suspicious hidden-text metadata.
- STIX 2.1 JSON and supported-object validation using integrity-checked OASIS schemas pinned for
  offline use, explicit EXECUTED/SKIPPED/UNAVAILABLE/ERROR capability state, typed object parsing,
  required properties, IDs, timestamps, patterns, duplicates, aliases, relationships, and dangling
  references.
- Atomic observable, hash, CVE, ATT&CK, entity, confidence, and relationship claims retaining
  their source STIX IDs.
- Exact IOC evidence; case-insensitive, normalized, and labeled fuzzy entity search; page/offset
  spans; near-match correction; format checks; coverage; unknown-actor contradiction; bilingual
  attribution review. Co-occurrence never proves relationships.
- Default no-network semantic provider, fake test provider, and opt-in OpenAI-compatible provider
  with structured result parsing and safe abstention.
- YAML policies producing PASS, REVIEW, REJECT, QUARANTINE, and ABSTAIN with fired-rule reasons.
- SQLAlchemy/SQLite case snapshots, eligible accept/reject decisions, rejected in-place edits, and
  SHA-256 hash-chained audit events. Hard findings require correction and complete re-analysis.
- FastAPI health/case/finding/review/manifest/export endpoints, validation errors, security headers,
  and a local responsive analyst UI with RTL evidence and no external CDN.
- Typer verify/show/export/demo commands and approved-only STIX, findings, manifest, and audit
  artifacts. Relationships are excluded when either endpoint is not approved.
- Ten original English/Arabic/mixed base reports and 100 deterministic, category-specific
  mutations with provenance, license, expected verdict, and expected finding categories.
- Apache-2.0 license, notices, threat model, ADRs, architecture/evidence/policy/data documentation,
  screenshots, Docker/Compose, CI, Makefile, pre-commit, examples, and contributor guidance.

## Architecture summary

The application is a local modular monolith under `src/cti_trust_gateway`. One `GatewayService`
orchestrates parsing, security scanning, STIX validation, claim extraction, evidence verification,
optional semantics, policy evaluation, persistence, review, audit, and export. API, CLI, UI, demo,
and tests all use this path. Runtime documents, SQLite databases, exports, coverage output, the
environment file, and virtual environments are ignored.

## Important files

- `README.md` — problem, examples, architecture, screenshots, setup, API/CLI, Arabic, policy,
  manifest, security, data policy, and roadmap.
- `src/cti_trust_gateway/core/service.py` — pipeline orchestration.
- `src/cti_trust_gateway/domain/models.py` — typed domain model and verdicts.
- `src/cti_trust_gateway/parsers/document.py` and `scanners/document_security.py` — source trust
  boundary.
- `src/cti_trust_gateway/validators/stix.py`, `core/claims.py`, and `evidence/engine.py` — core
  verification.
- `policies/default.yml` — conservative default policy.
- `src/cti_trust_gateway/api/app.py`, `cli/main.py`, and `web/` — user surfaces.
- `src/cti_trust_gateway/exporters/exporter.py` — approved-only export.
- `scripts/build_synthetic_benchmark.py` and `scripts/run_synthetic_benchmark.py` — reproducible
  corpus generation and execution.
- `docs/decisions/` — architectural records.
- `SECURITY.md` — threat model and production requirements.

## Install and run

Declared versions (Python 3.12 and 3.13; only 3.13 was available locally):

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m uvicorn cti_trust_gateway.api.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`.

With `uv`:

```powershell
uv venv --python 3.12
uv pip install -e ".[dev]"
uv run uvicorn cti_trust_gateway.api.app:app --host 127.0.0.1 --port 8000
```

## Reproduce demos and benchmark

```powershell
.\.venv\Scripts\cti-trust.exe demo
.\.venv\Scripts\cti-trust.exe verify examples\demo-report.txt examples\demo-candidate.json
.\.venv\Scripts\python.exe scripts\build_synthetic_benchmark.py
.\.venv\Scripts\python.exe scripts\run_synthetic_benchmark.py
```

Observed demo verdicts:

- exact source: PASS
- wrong attribution / mutated IP / inflated confidence: REJECT
- prompt injection: QUARANTINE
- unavailable relationship semantics under abstention policy: ABSTAIN
- Arabic/English inconsistency: REVIEW

The benchmark result was: `Executed 100 deterministic mutations; failures=0`.

## Pre-audit baseline verification results (superseded)

The results below preserve the original baseline evidence. They must not be read as current audit
results; see `HANDOFF_PHASE2.md` for the post-fix test and coverage totals.

Executed on 2026-07-17 with the available Python 3.13.5 interpreter (at baseline the project
declared Python 3.12+ and CI/Docker covered only 3.12):

```text
Ruff format --check: passed (39 files)
Ruff check: passed
mypy: passed, no issues in 27 source files
pytest: 33 passed, 1 third-party Starlette deprecation warning
coverage: 85.22% total (80% gate passed)
benchmark: 100 mutations, 0 failures
demo: PASS / REJECT / QUARANTINE / ABSTAIN / REVIEW as expected
/health: 200 {"status":"ok","mode":"local-demo","version":"0.1.0b1"}
multipart upload: 201 PASS, evidence coverage 1.0
manifest: 200
approved STIX export: 200, one expected object
browser review: IOC rejection recorded and audit event appended
```

Re-run all local checks:

```powershell
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\python.exe -m pytest --cov --cov-report=term --cov-report=html
```

## Known and security limitations

- This local demo has no authentication, authorization, CSRF protection, rate limiting, malware
  scanning, worker sandbox, or hardened object storage. Bind only to localhost.
- PDF hidden-text and prompt-injection checks are explainable heuristics, not guarantees. Production
  must isolate and constrain PDF processing.
- The installed `stix2-validator` 3.3.1 wheel omitted the schema tree its code expects. The project
  now bundles the official OASIS STIX 2.1 schema commit
  `c4f8d589acf2bdb3783655c89e0ffb6e150006ae`, verifies aggregate integrity, and fails closed if the
  backend is unavailable, modified, or errors. The gateway never downloads schemas at runtime.
- External semantic verification is disabled by default and was intentionally not called in tests.
  Its optional `openai` extra was not installed or live-tested.
- Docker could not be built or validated because the `docker` executable is not installed on this
  host. `Dockerfile` and `docker-compose.yml` were reviewed but not executed.
- `uv` and Python 3.12 were not installed on this host, so local verification used a standard venv
  with Python 3.13.5. CI now declares 3.12 and 3.13; the container currently uses 3.12.
- The test warning comes from FastAPI's compatibility import noting that Starlette's use of
  `httpx` test transport is deprecated; it does not affect runtime behavior.

## Decisions and tradeoffs

- A modular monolith keeps the verification path auditable for the MVP and avoids network trust
  boundaries. Adapters allow later extraction.
- SQLite stores full case snapshots for local simplicity. Audit events are hash chained but not
  externally signed or independently append-only.
- Exact observables may pass deterministically. Entity normalization is search-only. Relationships
  remain review/abstain unless contradicted, semantically verified, or accepted by an analyst.
- Third-party reports and CTIBench are not vendored. Only original Apache-2.0 synthetic text and
  links/metadata are stored.

## Incomplete items and next increment

Public release remains conditional on a green remote CI run for Python 3.12, Python 3.13, and the
Docker build/health job. Production deployment additionally requires authentication, authorization,
CSRF and rate-limit controls, an isolated parser service, durable signed audit retention, and a
reviewed dependency lock/update process. Live external semantics remains optional and unverified.

Recommended next increment: isolate document parsing in a resource-limited worker, add authenticated
role-based review queues and externally signed audit storage, then integrate an approval-gated MISP
or OpenCTI adapter with idempotent export and end-to-end tests.
