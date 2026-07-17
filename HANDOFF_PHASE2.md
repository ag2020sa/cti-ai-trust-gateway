# Phase 2 independent audit handoff

## Outcome

**GO for a public GitHub research-beta source release; NO-GO for production deployment.** The three
baseline critical bypasses were reproduced and fixed. Python 3.12, Python 3.13, packaging, and the
Docker build/health job are verified in GitHub Actions. Python 3.12 and Docker remain unavailable
on the audit host and are not represented as locally verified.

The scoped primary statement is now independently supported: corrupted/unsupported objects do not
leave REJECT or QUARANTINE cases as verified exports, invalid or unexecuted STIX validation blocks
export, and unproved relationships require semantic evidence or an explicit eligible analyst
decision. This does not mean the intelligence is globally true or that the MVP is safe to expose.

## Files changed

- Assurance core: `domain/models.py`, `validators/stix.py`, `core/service.py`, `core/claims.py`,
  `evidence/engine.py`, `providers/semantic.py`, `policies/default.yml`.
- Authorization/export: `storage/repository.py`, `exporters/exporter.py`, `api/app.py`, and the case
  template.
- Input/security: `parsers/document.py`, `scanners/document_security.py`, security headers, JSON/PDF
  and multipart controls.
- Offline validation data: 57 official OASIS schema files plus license, provenance, per-file hashes,
  and aggregate integrity pin under `src/cti_trust_gateway/data/stix2.1/`.
- Independent evidence: `tests/adversarial/` and `tests/fixtures/offline/`.
- Compatibility/tooling: `pyproject.toml`, `.github/workflows/ci.yml`, `.dockerignore`.
- Corrections/deliverables: `README.md`, `HANDOFF.md`, `THIRD_PARTY_NOTICES.md`,
  `AUDIT_REPORT.md`, `docs/verification-matrix.md`, and this file.

The initial release commit and a cross-platform filename-validation fix were pushed to the private
staging repository. No tag or hosted release existed when this handoff was updated. Existing
unrelated files were preserved.

## Defects fixed

1. Mandatory schema unavailability previously produced apparent validity. Validation capability is
   now explicit (`EXECUTED`, `SKIPPED`, `UNAVAILABLE`, `ERROR`), recorded in the manifest, checked
   against a pinned schema digest, and enforced before PASS/export.
2. An unauthenticated `accept` could export a corrupted IOC from a REJECT case. The repository now
   rejects hard-case/hard-finding accepts and requires correction plus full re-analysis.
3. QUARANTINE previously did not gate export. REJECT, QUARANTINE, invalid STIX, and unexecuted
   mandatory validation now return an empty export bundle.
4. Relationships can export only when endpoints are approved and the relationship is supported or
   explicitly accepted in an eligible REVIEW/ABSTAIN case.
5. Provider exceptions now become `SEMANTIC-ERROR` and ABSTAIN rather than disappearing as `None`.
6. Candidate size/depth/node limits, MIME/cardinality checks, empty input behavior, PDF page/text
   limits, security headers, and document attack handling were completed.
7. Exact matching now handles token boundaries, IPv6 alternate text, hash case/length, Unicode
   controls, Arabic punctuation, ATT&CK name/status checks, and relationship negation conservatively.
8. CI now declares Python 3.12/3.13 and a Docker build/health job. The development-only pytest
   dependency was raised to `>=9.0.3` after the online vulnerability query flagged 8.4.2.

## Verification results

Audit host: Windows 11 `10.0.26200`, Python 3.13.5.

```text
Ruff format --check: 48 files already formatted
Ruff lint: passed
mypy: success, 28 source files
Bandit 1.9.4: no findings (B105 excluded as the literal PASS verdict false positive)
pytest 9.1.1: 122 passed, 1 third-party Starlette TestClient deprecation warning
coverage: 87.82% branch-aware total; 80% gate passed
independent adversarial directory: 87 passed
manual catalog: 56 cases across 7 required categories
synthetic benchmark: 100 mutations, 0 mismatches
CLI demo: PASS / REJECT / QUARANTINE / ABSTAIN / REVIEW
pip-audit 2.10.1 online query: no known vulnerabilities after pytest upgrade;
  local project skipped because it is not a PyPI package
```

The final API evidence flow returned:

```text
PASS upload: HTTP 201; validation EXECUTED; 1 object; value unchanged 203.0.113.9
REJECT hard accept: HTTP 409; export 0 objects
QUARANTINE export: 0 objects
```

Wheel evidence on Python 3.13: 57 schema JSON files, provenance and templates were present; an
installed wheel validated a bundle with status `EXECUTED`, the exact pinned commit, and zero
findings.

## Compatibility and container status

| Target | Status | Evidence |
|---|---|---|
| Python 3.13 | **VERIFIED locally and in CI** | Full quality, 122 tests, coverage, benchmark, CLI/API, wheel install |
| Python 3.12 | **VERIFIED in CI** | Mandatory quality/test job passed; interpreter absent from audit host |
| Dockerfile static review | **VERIFIED statically** | `python:3.12-slim`, non-root user, healthcheck, no embedded secret, ignored runtime files |
| Compose static review | **VERIFIED statically** | localhost bind, `no-new-privileges`, all capabilities dropped, persistent runtime-only volume |
| Docker runtime/build | **VERIFIED in CI** | Image build and live healthcheck passed; Docker unavailable on audit host |
| `uv` | **NOT VERIFIED / unavailable** | Executable absent; pip/venv workflow verified |
| Optional external semantic provider | **NOT LIVE-VERIFIED** | Disabled by default; error/offline behavior tested without network |

## Remaining blockers and residual risk

- Require the final documentation commit to pass the same complete GitHub Actions workflow before
  tagging, then enable and verify GitHub Private Vulnerability Reporting.
- Do not deploy publicly: there is no authentication, role authorization, CSRF protection, rate
  limiting, malware scanner, encrypted storage, or production secret management.
- Move PDF parsing to a separately sandboxed, resource-constrained service. In-process byte/page/text
  limits do not bound all CPU and native-library risks.
- SQLite audit records are hash chained but mutable and not externally signed or append-only.
- The ATT&CK offline set is intentionally tiny; unknown/deprecated mappings REVIEW rather than claim
  full catalog verification.
- Dependency ranges are constrained but not locked. Establish a reviewed lock/update and recurring
  vulnerability-audit process before deployment.
- The Starlette TestClient compatibility warning remains third-party test-only technical debt.

## Recommended next step

Publish after the final reviewed commit passes the configured CI matrix and Docker job and Private
Vulnerability Reporting is verified. Keep the release explicitly labeled local/demo. The next engineering increment should add an
authenticated role boundary and move document parsing into an isolated service before any external
integration or network exposure.
