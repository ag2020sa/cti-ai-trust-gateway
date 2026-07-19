# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow Python packaging
version semantics.

## [Unreleased]

No unreleased changes.

## [0.2.0b1] - 2026-07-19

### Added

- Added an integrity-pinned OpenCTI `7.260715.0` compatibility profile, deterministic graph and
  dependency checks, 19 original bilingual/mixed test-only contract fixtures, and packaged-install
  checks that prove those fixtures are excluded from the wheel.
- Added persisted, exact-byte approved artifacts and offline Draft delivery plans with source,
  candidate, validation, policy, approval, profile, graph, artifact, and destination digests.
- Added `cti-trust opencti check|plan|probe|deliver|status|history|reconcile`, network-free plan/read
  API routes, and an OpenCTI Draft readiness card in the analyst UI.

### Changed

- Expanded supported claim/evidence and STIX validation paths for the Phase 1 OpenCTI mission
  types while preserving exact source spans and existing fail-closed export behavior.
- Raised the full branch-coverage gate to 90% and added a 95% combined OpenCTI critical-path gate
  with a 90% minimum for every critical module/path.

### Security

- Live delivery is disabled and dry-run by default, requires explicit CLI execution plus the full
  plan SHA-256, and revalidates approval, artifact, destination, platform, connector, and marking
  capabilities immediately before submission.
- Added exact host allowlisting, IDNA normalization, all-answer DNS/SSRF controls, verified TLS and
  SNI, optional CA pinning, blocked redirects/proxies, bounded responses and polling, secret-safe
  errors, concurrency reservation, duplicate suppression, and explicit ambiguous-state
  reconciliation without blind retry.

### Known limitations

- Delivery stages data only in an OpenCTI Draft and still requires separate OpenCTI analyst
  approval; it does not claim atomic or exactly-once behavior.
- The pinned GraphQL contract is covered by deterministic offline doubles. No disposable OpenCTI
  instance was available for a live end-to-end run in this implementation environment.

## [0.1.0b2] - 2026-07-17

### Changed

- Corrected Apache-2.0 license attribution to the project contributors.
- Reconciled release-readiness and historical documentation with the published `v0.1.0b1`
  prerelease, and added corrective `v0.1.0b2` release notes and verified-release install guidance.
- Updated package, API, citation, test, and CI container metadata to `0.1.0b2`.

### Security

- Disabled blank public issues and added private vulnerability-reporting guidance that prohibits
  sensitive CTI in public issues.
- Hardened `main` governance with pull requests, conversation resolution, up-to-date branches, four
  mandatory CI checks, and deletion/force-push protection.

There is no core gateway behavior change in this corrective beta.

## [0.1.0b1] - 2026-07-17

### Added

- Local source-evidence gateway with PASS, REVIEW, REJECT, QUARANTINE, and ABSTAIN verdicts.
- Offline, integrity-pinned OASIS STIX 2.1 schemas and manifest validation provenance.
- TXT, Markdown, and PDF parsing; bilingual evidence; policy, review, audit, API, CLI, and UI paths.
- 56-case hand-authored adversarial catalog, offline fixtures, synthetic benchmark, and audit reports.
- Python 3.12/3.13 CI matrix, distribution verification, Docker health job, and community templates.
- Policy-aware case UI that disables empty REJECT/QUARANTINE exports while retaining the evidence manifest.

### Security

- Fail-closed validation for missing, skipped, corrupted, or failed schema capability.
- Hard export gates for REJECT, QUARANTINE, structurally invalid STIX, and rejected relationships.
- Upload, JSON, PDF, browser, provider-error, and review-authorization hardening.
- Repository-relative synthetic-manifest paths with absolute-path and traversal rejection.

### Known limitations

- Research beta only; not production ready and not a compliance certification.
- Python 3.12, Python 3.13, packaging, and Docker build/health are verified in GitHub Actions.
- Optional external semantic-provider behavior is not live-verified.
