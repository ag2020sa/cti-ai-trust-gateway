# Independent security and CTI assurance audit

> **Historical pre-publication audit.** This report preserves the evidence and conclusions captured
> before the first public prerelease. Statements about tag or publication state are point-in-time
> records; see `RELEASE_READINESS.md` and `docs/releases/` for current release status.

## Audit status

**Complete on 2026-07-17.** The baseline sections below are deliberately retained as reproduction
evidence. Post-fix results and the final recommendation follow them.

## Final executive conclusion

**CONDITIONAL GO for public GitHub source release; NO-GO for production deployment.** The scoped
primary statement is now supported by independent tests: the gateway prevents unsupported or
corrupted candidate CTI from being exported *as source-verified intelligence* through the audited
local paths. REJECT/QUARANTINE cases, structurally invalid STIX, and unexecuted mandatory validation
all produce empty exports; hard findings cannot be converted through unauthenticated Accept.

The condition is concrete: a public tag should wait for an observed green CI run on Python 3.12,
Python 3.13, and the Docker build/health job. Only Python 3.13 was available locally, and Docker was
absent. This verdict is not approval for network exposure or production use.

## Executive conclusion — initial baseline

**NO-GO.** The primary statement, “The gateway prevents unsupported or corrupted AI-generated CTI
from being exported as verified intelligence,” is **FALSE** in the inspected baseline.

Two independently reproduced bypasses are decisive:

1. A REJECT case containing mutated IPv4 `203.0.113.58` initially exported no objects. Posting an
   unauthenticated `accept` review for that object returned HTTP 200, after which the export endpoint
   emitted the corrupted IPv4 unchanged.
2. A QUARANTINE case containing visible prompt injection and an otherwise exact IP exported that IP
   immediately, without an analyst decision.

The baseline also silently converted unavailable OASIS schema validation into apparent success.
`stix2-validator` 3.3.1 had no bundled schema directory, `CTI_GATEWAY_STIX_SCHEMA_DIR` was unset,
and the code deliberately suppressed the resulting “Cannot locate a schema” errors. A case could
therefore receive PASS without the mandatory schema capability having executed.

## Baseline environment

| Item | Evidence |
|---|---|
| OS | Windows 11 `10.0.26200`, 64-bit |
| Local Python | 3.13.5 |
| Python 3.12 | NOT AVAILABLE (`py -0p` listed only 3.13) |
| `uv` | NOT AVAILABLE |
| Docker / Compose | NOT AVAILABLE; runtime and compose validation not performed |
| `stix2` | 3.0.2 |
| `stix2-validator` | 3.3.1 |
| OASIS schema tree | UNAVAILABLE: package contained no `schemas-2.1/schemas`, no configured path |
| FastAPI / Pydantic / SQLAlchemy | 0.139.2 / 2.13.4 / 2.0.51 |
| PyMuPDF | 1.28.0 |

## Original claim verification table — unmodified baseline

| Original claim | Baseline status | Independent evidence |
|---|---|---|
| Corrupted AI CTI cannot be exported | **FALSE** | HTTP review accepted a hard-rejected mutated IP; subsequent export contained `203.0.113.58`. |
| Unsupported AI CTI cannot be exported | **FALSE** | Export authorization trusts unauthenticated analyst `accept`; no role or hard-block boundary exists. |
| QUARANTINE prevents export | **FALSE** | Prompt-injection QUARANTINE exported exact IP without review. |
| Invalid STIX cannot be exported | **NOT VERIFIED** | High findings normally exclude object IDs, but analyst accept bypasses high/critical findings. Dedicated exploit test pending. |
| OASIS STIX 2.1 schema validation runs | **FALSE** | Schemas absent; missing-schema messages are suppressed in `validators/stix.py`. |
| STIX fallback is safe | **FALSE** | Capability state is not represented and schema unavailability can result in PASS. |
| Evidence manifest is machine-readable | **VERIFIED** | Manifest endpoint returned JSON with case/source/candidate/verdict/claims/findings/policy fields. |
| Manifest records validation capability and provenance | **FALSE** | Baseline manifest has no validator name/version/status/schema source/hash/errors. |
| Exact IOC evidence is enforced before automatic approval | **PARTIALLY VERIFIED** | Mutated IP creates `EVIDENCE-IOC-002` and is initially excluded; review bypass defeats the invariant. |
| Co-occurrence does not automatically prove a relationship | **VERIFIED** | Existing service and test emit `EVIDENCE-REL-001`; relationship remains UNKNOWN. |
| Rejected relationship endpoint blocks relationship export | **PARTIALLY VERIFIED** | Export checks endpoint membership, but analyst accept can add hard-rejected endpoints. |
| Default provider makes no network call | **PARTIALLY VERIFIED** | Deterministic provider returns `None`; current test does not globally prevent network access. |
| Provider failures safely abstain | **FALSE** | Provider exceptions return `None`; service adds no semantic capability finding, so failure and not-configured are indistinguishable. |
| Audit is immutable-style / hash chained | **VERIFIED** | Repository hashes canonical event payload with previous event hash. Storage remains mutable SQLite. |
| UI/API analyst accept/edit/reject works | **VERIFIED** | HTTP review returned 200 and appended a decision; security authorization is absent by design. |
| Stored XSS is prevented | **PARTIALLY VERIFIED** | Jinja autoescape is expected and JS uses no `innerHTML`; adversarial runtime tests pending. |
| Upload size and filename checks exist | **PARTIALLY VERIFIED** | Source size/suffix/basename checks exist; candidate size, MIME agreement, empties, PDF limits need audit. |
| Security headers exist | **VERIFIED** | Health response includes nosniff, DENY frame policy, no-referrer, and restrictive CSP. |
| Ten base reports and 100 mutations exist | **VERIFIED** | Manifest has 110 records and runner reports 100 executed, zero expected mismatches. |
| Benchmark independently proves assurance | **NOT VERIFIED** | Generator and expectations are repository-authored and use production behavior; independent suite absent. |
| 33 tests pass | **VERIFIED** | `pytest` collected and passed 33 tests. |
| Coverage is 85.22% with an 80% gate | **VERIFIED** | Independent run reported 85.22%; only Python `web/` package is omitted. Core logic is included. |
| Coverage proves the security invariants | **FALSE** | High aggregate coverage did not exercise schema-unavailable PASS or review/export bypasses. |
| Ruff and mypy pass | **VERIFIED** | Ruff format/lint and mypy completed successfully. Mypy excludes scripts and ignores missing third-party imports. |
| Python 3.12 is verified | **NOT VERIFIED** | Runtime unavailable locally; existing CI is configured only for 3.12 but has no run evidence in this repository. |
| Python 3.13 is verified | **VERIFIED** | Local quality, tests, demo, and benchmark ran on 3.13.5. |
| Docker is verified | **NOT VERIFIED** | Docker executable unavailable. Static inspection only. |
| Nothing was pushed or published | **VERIFIED** | Repository has no commits and all files are untracked; no remote publication action was performed. |

## Baseline reproduction commands

```powershell
git status --short --branch
py -0p
uv --version
docker --version
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\python.exe -m pytest --cov --cov-report=term-missing --cov-report=html
.\.venv\Scripts\python.exe scripts\run_synthetic_benchmark.py
.\.venv\Scripts\cti-trust.exe demo
.\.venv\Scripts\python.exe -m uvicorn cti_trust_gateway.api.app:app --host 127.0.0.1 --port 8010
```

Baseline outputs:

```text
Ruff format: 40 files formatted
Ruff lint: passed
mypy: no issues in 27 source files
pytest: 33 passed; coverage 85.22%
benchmark: 100 mutations; failures=0
demo: PASS / REJECT / QUARANTINE / ABSTAIN / REVIEW
health: HTTP 200
REJECT export before review: 0 objects
unauthenticated accept of corrupted IP: HTTP 200
REJECT export after review: ipv4-addr 203.0.113.58
QUARANTINE export without review: ipv4-addr 203.0.113.9
```

## Initial findings

### Critical

- **C-01 — Hard-rejected objects become exportable through unauthenticated Accept.** Baseline
  exporter treats any `accept` review as approval before considering finding severity.
- **C-02 — QUARANTINE does not block export.** Export authorization is object/claim based and does
  not enforce the case verdict.
- **C-03 — Mandatory STIX schema validation fails open.** Missing schemas are silently suppressed;
  capability state is absent from policy and manifest.

### High

- **H-01 — Structurally invalid STIX may be review-overridden without authentication or roles.**
  Dedicated exploit test and remediation are required.
- **H-02 — Semantic provider errors are indistinguishable from “not configured” and do not create
  a fail-closed capability result.**
- **H-03 — Existing benchmark is not independent evidence.** No hand-authored adversarial suite
  exists.

### Medium

- **M-01 — Candidate upload and parser resource limits are incomplete.** Candidate byte limit,
  JSON depth, PDF page count, and extracted-text limits are not enforced.
- **M-02 — CI tests only Python 3.12 and has no Docker build/health job.**
- **M-03 — MIME/extension consistency and empty-document behavior are not enforced.**

### Low

- **L-01 — Aggregate coverage and benchmark language overstate assurance despite untested security
  invariants.** Documentation correction is required.

## Coverage integrity assessment

The 85.22% figure is not produced by mocking core validators or omitting core Python modules.
Coverage configuration omits `*/web/*`, which contains templates/static assets rather than Python
verification logic. However, the figure is weak assurance evidence: security-critical branches and
authorization invariants were absent from the test design, and scripts are outside mypy scope.

## STIX validator root cause and remediation

The baseline `stix2-validator` 3.3.1 installation contained the Python package but no
`schemas-2.1/schemas` directory. This is consistent with a packaging/submodule failure, not with an
OASIS design that treats schema validation as optional:

- The official [cti-stix-validator README](https://github.com/oasis-open/cti-stix-validator)
  describes JSON Schema checks as the implementation of mandatory STIX requirements and documents
  `validate_string`.
- Its official [.gitmodules](https://github.com/oasis-open/cti-stix-validator/blob/master/.gitmodules)
  points `schemas-2.1` to the OASIS `cti-stix2-json-schemas` repository.
- The official [schema pinning procedure](https://github.com/oasis-open/cti-stix-validator/blob/master/pinning-schema.md)
  identifies STIX 2.1 schema commit `c4f8d589acf2bdb3783655c89e0ffb6e150006ae`.
- The official [schema repository](https://github.com/oasis-open/cti-stix2-json-schemas) warns that
  JSON schemas alone do not implement every specification rule, which is why the gateway retains
  typed and custom checks in addition to schema execution.

The audit verified validator tag `v3.3.1` at commit
`07b3030ed3e3a2fd4485b232e2ed5de85e554953`; its `schemas-2.1` gitlink points to exactly
`c4f8d589acf2bdb3783655c89e0ffb6e150006ae`. The 57 JSON schema files from that official commit are
now vendored offline with BSD-3-Clause license, per-file SHA-256 values, update instructions, and
aggregate digest `43c2bf45bbaeeb44e5852553abffdebeaaa1584111d92d8a8d3a3101d8bd220f`.
Normal analysis performs no schema download.

`ValidationCapability` records validator name/version, STIX version, schema source/version/hash,
status, and errors. Bundled integrity mismatch or missing schemas yields `UNAVAILABLE`; an exception
yields `ERROR`; both policy outcomes ABSTAIN and make the candidate invalid. A service invariant
prohibits PASS unless status is `EXECUTED`. Relevant evidence:

- `src/cti_trust_gateway/domain/models.py:45` and `:52` — explicit capability state/model.
- `src/cti_trust_gateway/validators/stix.py:27` — official commit and digest pins.
- `src/cti_trust_gateway/validators/stix.py:163` — fail-closed validation execution.
- `src/cti_trust_gateway/validators/stix.py:390` — validity requires EXECUTED and no findings.
- `src/cti_trust_gateway/core/service.py:119` — PASS invariant.
- `src/cti_trust_gateway/core/service.py:221` — capability in every evidence manifest.

A separately built wheel contained all 57 schemas, provenance and templates. Installing that wheel
into a fresh Python 3.13 environment produced `EXECUTED`, the exact pinned commit, a valid candidate,
and zero findings.

## Post-fix original claim verification

| Original claim | Final status | Independent evidence |
|---|---|---|
| Gateway blocks corrupted candidate CTI from verified export | **VERIFIED within audited scope** | One-character IPv4, IPv6 textual differences, hash case, Unicode and endpoint cases reject; all hard-case exports are empty. |
| Unsupported CTI cannot be exported automatically | **VERIFIED within audited scope** | Unsupported entities/relationships produce REVIEW/ABSTAIN/REJECT; relationship export requires support or an eligible explicit review. |
| QUARANTINE prevents export/override | **VERIFIED** | API accept returns HTTP 409 and export contains zero objects. |
| Structurally invalid STIX cannot export | **VERIFIED** | Schema/manual failures make candidate invalid and the export case gate returns an empty bundle. |
| OASIS schema validation actually runs | **VERIFIED on Python 3.13** | Local editable install and installed wheel record EXECUTED with the pinned commit/digest. |
| Missing/failed validation cannot PASS | **VERIFIED** | Missing path, validator exception, and integrity mismatch tests all ABSTAIN and export nothing. |
| Manifest records validation capability/provenance | **VERIFIED** | Manifest model and API contain all required fields and error list. |
| Exact IOC evidence precedes automatic approval | **VERIFIED** | Boundary, corruption, normalization, Unicode, hash, domain and Arabic cases pass/reject as manually expected. |
| Co-occurrence does not prove a relationship | **VERIFIED** | Separate and same-paragraph entity cases remain REVIEW; relationships never automatically PASS. |
| Rejected endpoint blocks relationship | **VERIFIED** | Endpoint and relationship export invariants are tested; REJECT case gate is empty. |
| Default provider makes no network call | **VERIFIED** | A test replaces socket connect with a failure and completes default analysis. |
| Provider failures safely abstain | **VERIFIED for simulated failures; live provider NOT VERIFIED** | Typed provider error becomes `SEMANTIC-ERROR`/ABSTAIN; no live external request was made. |
| Audit is hash chained | **VERIFIED, with storage limitation** | Review event retains previous hash, original verdict, comment, actor and timestamp; SQLite is not immutable storage. |
| Stored XSS is prevented | **VERIFIED** | Runtime source/analyst payloads are HTML-escaped, JS contains no `innerHTML`, and CSP/security headers are asserted. |
| Upload and parser bounds exist | **VERIFIED for implemented controls** | Traversal, absolute paths, double extension, MIME mismatch, duplicate fields, empty/oversize/deep inputs, malformed PDF, links, and page limit are tested. |
| Synthetic benchmark executes 100 mutations | **VERIFIED** | Final run: 100 executed, zero expectation mismatches. It remains secondary evidence. |
| Independent adversarial evidence exists | **VERIFIED** | 56 manually enumerated catalog cases plus dedicated security/fixture tests; 87 adversarial tests pass. |
| Ruff, mypy, tests and coverage pass | **VERIFIED on Python 3.13** | 120 tests; 87.94% branch-aware coverage; Ruff/mypy clean. |
| Python 3.12 works | **NOT VERIFIED locally** | Interpreter absent. CI declaration is not execution evidence. |
| Python 3.13 works | **VERIFIED** | Full local suite, benchmark, CLI/API, coverage and wheel install. |
| Docker works | **NOT VERIFIED at runtime** | Static Docker/Compose review passed; executable absent; CI job not yet run. |
| Nothing was pushed or published | **VERIFIED** | No commits, no configured remote output, and no external write action. |

## Finding register and fix status

### Critical — 3

| ID | Finding | Status | Post-fix evidence |
|---|---|---|---|
| C-01 | Hard-rejected objects export after unauthenticated Accept | **FIXED** | Repository blocks REJECT/QUARANTINE, invalid validation, high/critical findings, missing rationale, and edits (`storage/repository.py:97-121`). API returns 409. |
| C-02 | QUARANTINE did not gate export | **FIXED** | Export case gate at `exporters/exporter.py:21-39`; direct/API tests return empty bundle. |
| C-03 | Mandatory STIX validation failed open | **FIXED** | Pinned offline schemas, integrity check, capability state, ABSTAIN policies and PASS invariant. |

### High — 3

| ID | Finding | Status | Post-fix evidence |
|---|---|---|---|
| H-01 | Structurally invalid STIX could be review-overridden | **FIXED** | Invalid candidate is a hard review/export gate; correction and rerun required. |
| H-02 | Provider errors disappeared as “not configured” | **FIXED** | Sanitized `SemanticProviderError` becomes `SEMANTIC-ERROR` and ABSTAIN (`core/service.py:164-186`). |
| H-03 | Benchmark lacked independent assurance | **FIXED** | `tests/adversarial/` has 56 manual oracle cases, no generator import, reasons, and dedicated security controls. |

### Medium — 4

| ID | Finding | Status | Post-fix evidence |
|---|---|---|---|
| M-01 | Candidate/JSON/PDF resource bounds incomplete | **FIXED within process** | Both byte limits, JSON depth/nodes, PDF pages/text enforced. True CPU/memory isolation remains residual. |
| M-02 | CI omitted Python 3.13 and Docker health | **CONFIGURATION FIXED; EXECUTION PENDING** | CI matrix lists 3.12/3.13 and Docker build/health job. No remote run exists. |
| M-03 | MIME agreement, empty input and multipart cardinality absent | **FIXED** | API/parser rejects mismatches, empty text and duplicate file fields. |
| M-04 | Development pytest 8.4.2 flagged by current vulnerability data | **FIXED** | `pip-audit` identified `PYSEC-2026-1845`; constraint raised to `pytest>=9.0.3,<10`, installed 9.1.1, repeat query found no known vulnerabilities. |

### Low — 1

| ID | Finding | Status | Post-fix evidence |
|---|---|---|---|
| L-01 | Documentation overstated assurance and fallback safety | **FIXED** | README/HANDOFF now distinguish deterministic, semantic, human-reviewed, unavailable and heuristic states and state production requirements. |

Finding totals: **3 critical, 3 high, 4 medium, 1 low**. All code/document defects are fixed; M-02
retains an external execution condition.

## Independent adversarial suite

The suite under `tests/adversarial/` does not import mutation-generation code and does not derive
expectations from production validators. Each catalog record provides source text, explicit
candidate objects, expected verdict, category, and rationale. Catalog distribution:

```text
56 total: observable 10, grounding 11, ATT&CK/CVE 7, STIX 6,
Arabic/bilingual 11, document 7, policy 4
```

Dedicated tests add schema unavailable/error/integrity, unsupported version, hard review gates,
ABSTAIN review audit, network denial, upload attacks, XSS, SQL input, active PDF links, PDF page
limits, and three offline fixture tests. Result: **87 passed**.

## Security audit results

- **Uploads:** traversal and parser-level absolute paths reject; browser multipart path stripping is
  verified; double extensions, unsupported types, MIME mismatch, oversize/empty files, malformed
  PDF/JSON, deep JSON, and duplicate multipart fields reject.
- **Application:** Jinja autoescape and `textContent` prevent tested stored XSS; no permissive CORS
  middleware exists; SQLAlchemy parameterization treats injection strings as IDs; evidence snippets
  are bounded; CSP, nosniff, frame denial, referrer, permissions and no-store headers are present.
- **Provider:** default is offline; tests prevent a socket connection; errors expose only exception
  type, not API keys/response bodies; provider result cannot bypass case export authorization.
- **PDF:** PyMuPDF text/dict APIs do not execute embedded content or follow links in the tested path;
  byte/page/text limits apply. Native parser compromise and adversarial CPU/memory use require a
  separate production sandbox.
- **Bandit 1.9.4:** no findings after excluding B105 solely because `PASS = "PASS"` is a verdict,
  not a password. No source line was suppressed with `nosec`.
- **pip-audit 2.10.1:** online vulnerability data was reachable. The initial query found one
  development-only pytest advisory, which was fixed; the repeat query found no known installed
  dependency vulnerabilities. The local unpublished project itself was skipped as absent from PyPI.
  This is a dated query, not continuing assurance.

## Offline fixture evidence

`tests/fixtures/offline/` contains a repository-authored OASIS-example-based indicator, a four-row
MITRE ATT&CK subset with the required designation, one small public-domain NVD/CISA-shaped record,
and original English/Arabic/mixed reports. The fixture README records upstream URLs, snapshot date,
terms, NVD non-endorsement notice, and limits. No Saudi CERT or commercial report is copied.

## Final reproduction commands and results

```powershell
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\python.exe -m bandit -q -c pyproject.toml -r src
.\.venv\Scripts\python.exe -m pytest --cov --cov-report=term-missing --cov-report=html
.\.venv\Scripts\python.exe -m pytest tests/adversarial -q
.\.venv\Scripts\python.exe scripts\run_synthetic_benchmark.py
.\.venv\Scripts\cti-trust.exe demo
.\.venv\Scripts\python.exe -m pip_audit --local --progress-spinner off
```

```text
Ruff format: 45 files already formatted
Ruff lint: passed
mypy: no issues in 27 source files
Bandit: no findings
pytest: 120 passed, 1 third-party Starlette TestClient deprecation warning
coverage: 87.94% (80% gate passed)
adversarial: 87 passed
benchmark: 100 mutations, 0 mismatches
demo: PASS / REJECT / QUARANTINE / ABSTAIN / REVIEW
pip-audit after upgrade: no known vulnerabilities; local unpublished package skipped
```

Final API evidence:

```text
PASS upload: HTTP 201; manifest validation EXECUTED; 1 object; IOC unchanged
REJECT accept attempt: HTTP 409; 0 exported objects
QUARANTINE: 0 exported objects
```

## Compatibility and Docker evidence

| Target | Final audit status |
|---|---|
| Python 3.13.5 | **VERIFIED locally**, including installed wheel and 120-test suite |
| Python 3.12 | **NOT VERIFIED locally**; CI configured, no run evidence |
| Dockerfile | **STATICALLY VERIFIED**: slim base, non-root, healthcheck, no secret, runtime paths ignored |
| Compose | **STATICALLY VERIFIED**: localhost bind, dropped capabilities, no-new-privileges, runtime volume |
| Docker build/health | **NOT VERIFIED locally**; CI job configured but not executed |
| `uv` | **UNAVAILABLE / NOT VERIFIED** |

## Residual risk and release recommendation

The release remains a local, unauthenticated demonstration. It lacks authenticated roles, CSRF,
rate limits, malware scanning, encrypted storage, a parser sandbox, externally signed append-only
audit retention, a complete ATT&CK catalog, and a dependency lock/update process. Optional live
semantic verification was not exercised. The TestClient deprecation warning remains.

Therefore:

- **Public GitHub source release: CONDITIONAL GO**, after the configured Python 3.12/3.13 and Docker
  CI jobs are observed green and their logs are retained as release evidence.
- **Production or public network deployment: NO-GO** until the residual controls above are designed,
  implemented and independently tested.
