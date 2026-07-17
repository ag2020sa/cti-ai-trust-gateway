# Verification matrix

This matrix describes the post-audit behavior. “Mandatory” means the check must execute and pass
before PASS. Optional semantic results can strengthen a relationship decision, but their absence
cannot be represented as deterministic proof.

| Check | Implementation | Test evidence | Failure behavior | Manifest field | Status |
|---|---|---|---|---|---|
| Source byte integrity | `parsers/document.py` hashes the original upload | document parser unit tests; offline fixtures | Input rejected on empty/oversize/unsupported content | `source_sha256` | Mandatory |
| Candidate byte integrity | `GatewayService.analyze` hashes and bounds the candidate | API and deep/oversize adversarial tests | HTTP 413/422 or analysis error | `candidate_sha256` | Mandatory |
| OASIS STIX 2.1 JSON Schema | `validators/stix.py` uses the pinned offline schema tree | missing/error/integrity tests; wheel-install test | UNAVAILABLE/ERROR → ABSTAIN; schema errors → REJECT | `validation.*` | Mandatory |
| Validator provenance | `ValidationCapability` records tool, version, source, commit, digest, status, errors | manifest and fail-closed tests | PASS invariant raises if status is not EXECUTED | `validation.name`, `version`, `schema_source`, `schema_version`, `schema_sha256`, `status`, `errors` | Mandatory |
| Supported STIX version | `parse_candidate` accepts only 2.1 | unsupported-version adversarial test | Input rejected before case creation | Validation/input error | Mandatory |
| STIX IDs, required fields, timestamps, patterns | `validators/stix.py`, `stix2.parse` | unit tests; malformed pattern, duplicate ID catalog cases | High structural finding → REJECT | `findings[]` | Mandatory |
| Relationship references and endpoint types | `validators/stix.py` | dangling/wrong-type/rejected-endpoint catalog cases | High structural finding → REJECT | `findings[]` | Mandatory |
| Exact observable grounding | `evidence/engine.py` boundary-aware search | IPv4, IPv6, hash, domain, Arabic punctuation, Unicode cases | Corruption/not found → REJECT | `claims[].evidence`, `claims[].status`, `findings[]` | Mandatory for observable PASS |
| Hash/IP/CVE/ATT&CK format | `evidence/engine.py` | invalid hash/CVE and mapping cases | Invalid format or name mismatch → REJECT | `findings[]` | Mandatory when applicable |
| ATT&CK reference subset | pinned four-record offline subset | wrong-name/deprecated/unknown tests | Wrong name → REJECT; deprecated/unknown → REVIEW | `findings[]` | Mandatory subset check; catalog completeness limited |
| Entity mention grounding | `evidence/engine.py` exact/bounded entity search | invented/reference-only/partial tests | Unsupported entity → REVIEW | `claims[].status`, `findings[]` | Mandatory when applicable |
| Relationship semantics | deterministic contradiction/co-occurrence rules plus optional provider | relationship, uncertainty, negation, provider tests | Contradiction → REJECT; unproved → REVIEW/ABSTAIN | `claims[].status`, `findings[]`, `policy` | Mandatory decision; provider optional |
| Optional semantic provider | `providers/semantic.py`, disabled by default | socket-denial and provider-error tests | Provider error → ABSTAIN; provider cannot authorize export | `findings[]`, `policy` | Optional capability |
| Arabic/bilingual evidence | Unicode-preserving parser and bilingual heuristics | 11 hand-authored Arabic/bilingual cases plus fixtures | Contradiction → REJECT/REVIEW; exact IOC may PASS | claims/findings/policy | Mandatory when applicable; heuristic semantics |
| Document instruction/hidden-content scan | `scanners/document_security.py` | visible/hidden/role/fabrication/zero-width/benign-control cases | High/critical → QUARANTINE | `findings[]`, `policy` | Mandatory heuristic scan |
| Upload name/type/cardinality | API and parser boundaries | traversal, absolute, double extension, MIME, duplicate multipart tests | HTTP 413/422 | HTTP error, no manifest | Mandatory API boundary |
| PDF resource limits | 10 MB, 200 pages, 2M extracted characters | malformed/active-link/page-limit tests | Input rejected; no links executed/followed | HTTP/input error | Mandatory in-process limit; not a sandbox |
| JSON resource limits | byte, 64-depth, 50,000-node checks | corrupt/deep/oversize tests | Input rejected | HTTP/input error | Mandatory |
| Policy evaluation | `policies/default.yml`, precedence engine | PASS/REVIEW/REJECT/QUARANTINE/ABSTAIN tests | Highest matching verdict wins | `policy`, `verdict` | Mandatory |
| Review authorization | `Repository.add_review` validates case, object, finding, rationale and hard blocks | quarantine/reject/invalid tests | Hard accept/edit → HTTP 409 or `ReviewNotAllowed` | `reviews[]`, `audit[]` | Mandatory for reviewed export |
| Export case gate | `exporters/build_export` blocks REJECT, QUARANTINE, invalid/unexecuted validation | hard-block and API flow tests | Empty bundle with exclusion list | export custom disclaimer | Mandatory |
| Export object/relationship gate | supported claims, hard findings, endpoints, and relationship decision | catalog plus explicit ABSTAIN review test | Object/relationship excluded | `x_cti_gateway_verdict`, coverage, review state | Mandatory |
| Stored XSS/browser controls | Jinja autoescape, `textContent`, CSP and headers | stored-XSS/security-header test | Untrusted HTML escaped; scripts restricted | Not applicable | Mandatory UI boundary |
| Audit chain | canonical payload hash with previous hash | integration and reviewed-ABSTAIN tests | Original verdict and decision remain in case/audit | `reviews[]`, `audit[]` | Mandatory for review events |
| External network default | deterministic provider and offline schema/fixtures | socket connection denial test | No call; unproved semantics remain REVIEW | provider-related findings/policy | Mandatory default behavior |

Residual production controls—authentication, authorization roles, CSRF, rate limiting, parser
process isolation, malware scanning, encrypted storage, signed external audit retention, and
controlled model egress—are intentionally outside this local MVP and must not be inferred from a
PASS verdict.
