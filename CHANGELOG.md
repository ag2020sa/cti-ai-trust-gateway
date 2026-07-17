# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow Python packaging
version semantics.

## [Unreleased]

No unreleased changes.

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

### Known limitations

- Research beta only; not production ready and not a compliance certification.
- Python 3.12, Python 3.13, packaging, and Docker build/health are verified in GitHub Actions.
- Optional external semantic-provider behavior is not live-verified.
