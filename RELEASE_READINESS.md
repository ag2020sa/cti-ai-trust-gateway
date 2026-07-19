# Post-publication verification record: 0.2.0b1

Prepared on 2026-07-19 and finalized after publication of the GitHub prerelease
`v0.2.0b1 — OpenCTI Draft Delivery Research Beta`.

## Decision

**PUBLISHED RESEARCH PRERELEASE; independently reverified and not production-ready.**

The audited OpenCTI Phase 1 implementation and release metadata pass the complete local source,
security, adversarial, coverage, schema, benchmark, package, installed-wheel, CLI, and API gates.
The pull-request, final-`main`, and tag GitHub Actions checks passed. Exact-clean-commit artifacts,
public release metadata, and anonymous downloads were verified after publication.

> **OpenCTI Draft delivery is EXPERIMENTAL, disabled by default, contract-tested, and not live-verified.**

## Scope and assurance boundary

This research beta verifies AI-produced CTI against the supplied source and policy before export.
OpenCTI Phase 1 can place only the deterministic, approved dependency-closed STIX graph into an
isolated Draft. `VALID_STIX`, `OPENCTI_COMPATIBLE`, `EVIDENCE_VERIFIED`, and
`DELIVERY_AUTHORIZED` remain independent gates.

The API and UI are unauthenticated, local-evaluation interfaces and cannot initiate live delivery.
CLI delivery requires environment enablement, `--execute`, and the full stored SHA-256 integrity
digest. The digest is not a signature. OpenCTI human validation remains mandatory; there is no
automatic live-graph promotion, blind retry, atomic cross-system transaction, or exactly-once
guarantee. Ambiguous outcomes remain `UNKNOWN` or `PARTIAL` until explicit status-only
reconciliation.

## Version and publication record

- Active package, API, CLI resource verifier, citation, test, and container-test version:
  `0.2.0b1`.
- Pull request: [#8](https://github.com/ag2020sa/cti-ai-trust-gateway/pull/8).
- Feature commit: `c5d9e65b15611639d4d5e1c8a7b6e951df91a2bb`.
- Squash/main and release target commit: `cc22d2ea0eabf2eeff041f8b3c2c4b4e61731ac7`.
- Annotated tag object: `b4a88a8bc169a45d318304c6eed5c160a4f88985`.
- GitHub Release ID: `356229510`; `draft=false`, `prerelease=true`, `immutable=false`.
- `v0.1.0b1` and `v0.1.0b2`, their annotations, release notes, checksums, and public assets remain
  unchanged historical releases.
- No package-index or container-registry publication occurred.
- A future `v0.2.0b2` is reserved for work following an isolated live OpenCTI Draft test; no stable
  release commitment exists.

Public release assets were downloaded anonymously and matched these SHA-256 values:

| Asset | Size (bytes) | SHA-256 |
| --- | ---: | --- |
| `cti_ai_trust_gateway-0.2.0b1-py3-none-any.whl` | 165340 | `8eab71b67f09a8dc60fda94e6b0019c51226d57daba8e03f38dc939015d3f304` |
| `cti_ai_trust_gateway-0.2.0b1.tar.gz` | 355159 | `42ae70ee577efa3b29e9a2ad1c33f79b5b8d60b5d7acfde1b60c2768682c733a` |
| `SHA256SUMS.txt` | 214 | `3dd11ed4db1acb50fd27bfbb000efb0e8a84ff913776ff0c882bc8b997219de8` |

## Local verification record

Reproduced on Windows with Python 3.13.5:

| Gate | Required result |
| --- | --- |
| Ruff format and lint | Pass |
| strict mypy | Pass, 39 source files |
| Bandit | Pass |
| pip-audit `--local` | No known dependency vulnerabilities; unpublished local project skipped |
| Full suite | 224 passed |
| Independent adversarial suite | 150 passed |
| Overall branch-aware coverage | 90.44%, minimum 90% |
| OpenCTI critical-path coverage | 95.95% combined; lowest critical module/path 94.17% |
| Synthetic benchmark | 100 deterministic mutations, zero mismatches |
| Schema integrity | 57 files; exact commit and aggregate digest below |
| API health | HTTP 200 and version `0.2.0b1` |
| CLI | Help and five-verdict non-network demo pass |
| Distribution | Build, Twine, isolated install, resources and inventory pass outside checkout |

Python 3.12 and Docker were unavailable locally and were therefore mandatory GitHub Actions gates.
All four required jobs succeeded in each recorded run:

| CI context | Run | Commit | Conclusion |
| --- | --- | --- | --- |
| Pull request #8 | [29667718944](https://github.com/ag2020sa/cti-ai-trust-gateway/actions/runs/29667718944) | `c5d9e65b15611639d4d5e1c8a7b6e951df91a2bb` | success |
| Final `main` | [29667840318](https://github.com/ag2020sa/cti-ai-trust-gateway/actions/runs/29667840318) | `cc22d2ea0eabf2eeff041f8b3c2c4b4e61731ac7` | success |
| Annotated tag | [29668179792](https://github.com/ag2020sa/cti-ai-trust-gateway/actions/runs/29668179792) | `cc22d2ea0eabf2eeff041f8b3c2c4b4e61731ac7` | success |

The jobs cover Python 3.12 and 3.13 quality/tests, isolated distribution build and verification,
and Docker build and live health. They retain Ruff, strict mypy, Bandit, pip-audit, adversarial
tests, full branch coverage, per-critical-path coverage, schema/resource verification, and the
synthetic benchmark.

## Schema, profile, and compatibility provenance

- Exactly 57 immutable OASIS STIX schema files are packaged.
- Upstream schema commit:
  `c4f8d589acf2bdb3783655c89e0ffb6e150006ae`.
- Aggregate schema SHA-256:
  `43c2bf45bbaeeb44e5852553abffdebeaaa1584111d92d8a8d3a3101d8bd220f`.
- OpenCTI compatibility profile: `opencti-7.260715.0`, independently implemented from pinned
  public interface information.
- The 19 original English/Arabic/mixed OpenCTI contract fixtures are test-only and excluded from
  the wheel.
- No copied proprietary Ariane or OpenCTI Enterprise code or fixture is included.

`THIRD_PARTY_NOTICES.md` records exact public upstream references, licenses, attribution, and the
boundary between OASIS schemas and independently authored OpenCTI compatibility data.

## Package and repository hygiene

Release distributions are built in a unique temporary directory outside the repository. The wheel
must contain package code, 57 schemas, the pinned OpenCTI profile, policy files, web resources,
license, and third-party notices. It must not contain test-only OpenCTI fixtures, databases, `.env`,
coverage, caches, Git state, workstation paths, temporary data, or existing release artifacts.

The source distribution may contain the documented tests and original synthetic fixtures. Both
archives must pass Twine, inventory, private-path, secret-pattern, and extracted-content checks.
The isolated wheel verifier must validate installed metadata/version, schema/profile/notices,
invalid-schema fail-closed behavior, CLI help, the five-verdict demo, and API health outside the
checkout.

## Security and privacy review

`gitleaks` is not installed on this host, so no gitleaks-pass claim is made. The established audited
fallback scan checks tracked release content and extracted artifacts for private-key blocks,
common cloud/GitHub/OpenAI/Slack credentials, long Bearer values, private workstation paths,
private network addresses, internal domains, and non-authorized email addresses. This scan is a
documented fallback, not proof against every secret format.

`.env.example` contains only safe placeholders. Runtime secrets are environment-only and excluded
from serialization and logs. The feature commit and annotated tag used
`172840487+ag2020sa@users.noreply.github.com`. GitHub's final squash commit records
`ag2020.sa@gmail.com`; that address was already intentionally public in `CODE_OF_CONDUCT.md`.
Not all final Git metadata uses the noreply address. No Git history or release tag was rewritten.

The delivery transport requires verified TLS, an exact host-and-port allowlist, direct connections
without inherited proxies, blocked redirects, all-answer DNS validation, SSRF controls, bounded
responses, token redaction, explicit reconciliation, and conservative no-retry handling.

## Workflow and publication controls

The workflow keeps `permissions: contents: read`, uses full-SHA-pinned actions, has no
`pull_request_target`, tests Python 3.12 and 3.13, and preserves package and Docker health gates.
The full branch-coverage floor is 90%, combined critical-path floor is 95%, and every critical
module/path must remain at least 90%.

Publication followed this audited order:

1. The reviewed Phase 1 and release-preparation diff was committed as
   `c5d9e65b15611639d4d5e1c8a7b6e951df91a2bb` on `feature/opencti-approved-delivery`.
2. PR #8 passed all required checks and was squash-merged through protected `main` without an
   admin bypass or force push.
3. Final `main` CI passed at `cc22d2ea0eabf2eeff041f8b3c2c4b4e61731ac7`; artifacts were rebuilt
   from that exact clean commit outside the checkout.
4. Annotated tag `v0.2.0b1` was created without signing and points to the exact release commit.
5. GitHub prerelease 356229510 was published with only the verified wheel, source distribution,
   and `SHA256SUMS.txt`.
6. Anonymous downloads, checksums, tag/merge history, release metadata, clean local state, and
   remote feature-branch cleanup were verified after publication.

No Dependabot interaction, old-release mutation, PyPI upload, container-registry publication,
force push, protection bypass, or live OpenCTI contact is authorized.

## Limitations

- No real or disposable OpenCTI instance was contacted; no live interoperability claim is made.
- The project has no authentication, RBAC, CSRF protection, malware sandbox, parser-process
  isolation, rate limiting, production monitoring, signed audit retention, or automatic cleanup.
- Do not use production credentials, sensitive reports, private indicators, or customer data.
- OpenCTI compatibility pins will age and require independent revalidation.
- This research beta is not a compliance certification.

**OpenCTI and STIX names are used solely for compatibility identification; no endorsement is implied.**
No endorsement by Filigran/OpenCTI or OASIS is implied.

Historical release details remain in `docs/releases/v0.1.0b1.md` and
`docs/releases/v0.1.0b2.md`.
