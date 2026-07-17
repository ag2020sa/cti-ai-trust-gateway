# Release record and corrective readiness: 0.1.0b2

Prepared on 2026-07-17. The annotated `v0.1.0b1` tag and public GitHub prerelease have been
published with a source distribution, universal wheel, and SHA-256 checksum manifest. This record
also defines the narrowly scoped corrective `v0.1.0b2` beta. Neither release was uploaded to a
package index or container registry.

## Decision

**READY FOR A CORRECTIVE PUBLIC RESEARCH-BETA RELEASE**; **not production ready**.

The local source, package, schema-integrity, security, adversarial, API, CLI, and benchmark gates
pass. Mandatory Python 3.12, Python 3.13, package, and Docker build/health jobs are enforced in
GitHub Actions. The repository is public, and GitHub Private Vulnerability Reporting, secret
scanning, and push protection are enabled. Every corrective prerelease remains gated on a green
final `main` run and artifact verification from that exact commit.

## Repository boundary and safety

- True Git root: `.` — the directory containing this file and `.git`.
- Public-safe root name: `cti-ai-trust-gateway`. The user-specific absolute host prefix is
  intentionally excluded from this public document.
- `.git` exists only at this root; its parent is not a Git worktree.
- Branch: `main`; remote: `https://github.com/ag2020sa/cti-ai-trust-gateway`.
- The immutable annotated `v0.1.0b1` tag and public GitHub prerelease exist. `v0.1.0b2` supersedes
  it for new downloads without moving or replacing the historical tag or assets.

### Previous outside-root schema activity

Read-only inspection found the earlier temporary hierarchy at
`../src/cti_trust_gateway/data/stix2.1/schemas/`. It contains eight empty directories and zero
files. The prior schema import had moved the actual files into the intended package tree and
removed the temporary files, leaving only those empty directories. They are outside the Git root,
were not modified or deleted during release preparation, and are not release content.

The correct release source is `src/cti_trust_gateway/data/stix2.1/`: 57 JSON schemas plus OASIS
license/provenance/manifest files. The build confirmed that all 57 JSON files are present in the
wheel under `cti_trust_gateway/data/stix2.1/`.

One disposable virtual environment and working directory were created under the operating-system
temporary directory solely for the required outside-checkout wheel test. Their generated path was
verified as a dedicated temporary child and removed after the successful test. No persistent
outside-root modification remains.

## Release content hygiene

- `.gitignore` excludes virtual environments, Python caches, coverage output, build output,
  editable metadata, local environment files, databases, runtime uploads/exports, logs, and IDE
  state while preserving `.env.example`.
- `.dockerignore` excludes Git/CI metadata, development caches, coverage, distributions, runtime
  data, tests, docs, examples, logs, databases, and local environment files.
- The existing `.venv`, caches, coverage report, local SQLite databases, exports, and other runtime
  artifacts are ignored and were not included in either distribution.
- The sdist/wheel inventory contained no Git state, virtual environment, caches, coverage output,
  runtime database, upload, export, log, or build directory. `.env.example` is intentionally in the
  sdist and contains only empty/safe defaults; it is not in the runtime wheel.
- Examples, generated benchmark cases, fixtures, and screenshots use synthetic content and reserved
  documentation IP space. The detailed screenshot was regenerated locally after the indicator
  cleanup and contains no personal or operational CTI.
- Public documentation uses relative project paths and does not expose a private local filesystem
  prefix.

## Version and package metadata

- Distribution: `cti-ai-trust-gateway`
- Import package: `cti_trust_gateway`
- Current version: `0.1.0b2` in `pyproject.toml`, `cti_trust_gateway.__version__`, FastAPI metadata, health
  response, tests, Docker image label in CI, changelog, citation metadata, and release notes.
- Python requirement: `>=3.12,<3.14`, with classifiers for 3.12 and 3.13.
- Console entry point: `cti-trust = cti_trust_gateway.cli.main:app`.
- License: Apache-2.0 with `LICENSE`, `THIRD_PARTY_NOTICES.md`, OASIS schema provenance, and MITRE
  attribution.
- Repository URL: `https://github.com/ag2020sa/cti-ai-trust-gateway`.

## Historical `v0.1.0b1` distribution and installed-wheel evidence

Before `v0.1.0b1` publication, the previous `dist/` directory was verified as an exact child of the
repository and removed. That clean historical build produced exactly:

- `dist/cti_ai_trust_gateway-0.1.0b1.tar.gz`
- `dist/cti_ai_trust_gateway-0.1.0b1-py3-none-any.whl`

`python -m build` and `python -m twine check dist/*` passed. The wheel contains 99 entries,
including 57 schema JSON files and both bundled YAML policies. Metadata reports version `0.1.0b1`
and Python `>=3.12,<3.14`.

A fresh Python 3.13 environment installed the wheel—not an editable checkout—and executed from an
operating-system temporary directory. Evidence:

- import path resolved under the fresh environment's `site-packages`;
- installed metadata and `__version__` both reported `0.1.0b1`;
- `cti-trust --help` exposed `verify`, `show`, `export`, and `demo`;
- `cti-trust demo` returned PASS, REJECT, QUARANTINE, ABSTAIN, and REVIEW;
- FastAPI application import and version assertion passed;
- bundled `default.yml` and `abstain.yml` loaded without the source tree;
- schema count, commit, and aggregate digest matched;
- valid exact evidence produced PASS with validation status EXECUTED;
- invalid STIX and a missing schema directory produced no PASS and no exported objects.

## Schema and fail-closed evidence

- Schema source: bundled OASIS STIX 2.1 schema tree.
- Pinned commit: `c4f8d589acf2bdb3783655c89e0ffb6e150006ae`.
- Aggregate SHA-256: `43c2bf45bbaeeb44e5852553abffdebeaaa1584111d92d8a8d3a3101d8bd220f`.
- Packaged schema JSON count: 57.
- PASS path: validation status EXECUTED, exact commit and digest recorded.
- Invalid STIX path: not PASS; export empty.
- Missing schema path: validation status UNAVAILABLE, not PASS; export empty.
- Existing adversarial tests cover missing, corrupted, failed, skipped, and bypass-attempt states;
  none can yield PASS.

## Reproduced quality and security gates

| Gate | Result |
|---|---|
| Ruff format | PASS, 48 files checked |
| Ruff lint | PASS |
| strict mypy | PASS, 28 source files |
| Bandit | PASS |
| Full pytest | PASS, 122 tests |
| Branch-aware coverage | PASS, 87.82% against 80% minimum |
| Independent adversarial directory | PASS, 87 tests |
| Synthetic benchmark | PASS, 100 mutations, zero mismatches |
| Distribution build | PASS, sdist and wheel |
| Twine metadata/readme check | PASS, both artifacts |
| Fresh installed-wheel verification | PASS on Python 3.13.5 |
| `pip-audit --local` | PASS, no known dependency vulnerabilities; local unpublished project skipped |
| Historical `v0.1.0b1` API health endpoint | PASS, HTTP 200 with `0.1.0b1` |
| API upload/analyze/review/export integration | PASS |

The adversarial directory passed once on its own and again inside the full suite. Tests use isolated
temporary databases and fixtures; no suite outcome relies on the independently executed run.
External LLM access was disabled, normal validation used packaged local schemas, and the test suite
made no live model/schema/data calls. Network-denial and provider-failure adversarial cases enforce
the offline boundary. Package installation, isolated build dependency installation, and the
vulnerability database query were the only intentional tool-network operations.

### Export invariants reproduced

- REJECT exports no candidate objects.
- QUARANTINE exports no candidate objects.
- Structurally invalid STIX exports no candidate objects.
- Missing or unavailable mandatory schema capability exports no candidate objects.
- A PASS exact observable preserves its original value in export.
- Review rejection removes the object from a previously eligible PASS export.
- Hard-rejected findings and cases cannot be accepted through review; edits require full re-analysis.

## Secrets and privacy scan

`gitleaks` is not installed on this host, so no gitleaks result is claimed. A repository-content
pattern scan excluding ignored generated state and vendored schema JSON checked for common private
key headers, AWS/GitHub/OpenAI/Slack token signatures, private absolute user paths, email addresses,
private IPv4 ranges, and internal/local domains. It returned no matches. `.env.example` was manually
checked and contains no value for the optional model API key.

This pattern scan is a documented fallback, not proof that every possible secret format is absent.
Repository security features should remain enabled where GitHub makes them available.

## Python and Docker compatibility

- Python 3.13.5: **VERIFIED locally** through quality, coverage, benchmark, API/CLI, build, and fresh
  wheel-install checks, and **VERIFIED in CI**.
- Python 3.12: **VERIFIED in CI**; no 3.12 interpreter is installed on this host.
- Dockerfile/Compose: **STATIC PASS** for a slim 3.12 image, non-root user, loopback-published Compose
  port, dropped capabilities, no-new-privileges, isolated runtime volume, and healthcheck.
- Docker build/runtime: **VERIFIED in CI** through an image build and live healthcheck; no Docker
  CLI/daemon is installed on this host.

No unavailable runtime is described as passing.

## CI and workflow security

The workflow has mandatory jobs for Python 3.12 and 3.13 quality/coverage/adversarial tests, clean
package build plus outside-checkout wheel installation, and Docker build plus actual healthcheck.
It has read-only default contents permission, concurrency cancellation, external LLM disabled,
full-length SHA-pinned official checkout/setup actions, no allowed failures, and explicit Ruff,
mypy, Bandit, dependency-audit, coverage, and packaging gates. Dependabot covers pip, GitHub Actions,
and Docker updates.

The mandatory [GitHub Actions workflow](https://github.com/ag2020sa/cti-ai-trust-gateway/actions/workflows/ci.yml)
has exact jobs for Python 3.12 and 3.13 quality/tests, clean package build and outside-checkout
installation, and Docker build/health. Checked-in documentation uses the stable workflow URL;
hosted release notes record the exact final run for each prerelease.

## Public documentation and community files

The public-facing set includes `README.md`, `LICENSE`, `THIRD_PARTY_NOTICES.md`, `SECURITY.md`,
`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `CITATION.cff`, issue forms, a pull request
template, Dependabot configuration, architecture/threat/evidence/policy docs, release notes, and
this readiness record. The README states research-beta status, threat/assurance boundaries,
install/run/API/CLI/demo steps, schema provenance, bilingual behavior, benchmark/data licensing,
known limitations, screenshots, security warnings, and roadmap.

## Corrective release controls

1. Observe the complete workflow green on the final `main` commit.
2. Rebuild release artifacts on that exact commit and repeat the installed-wheel and archive scans.
3. Create and verify a new annotated tag and GitHub prerelease with checksums.

The historical `v0.1.0b1` tag and assets remain immutable. Package-index or container-registry
publication, if ever desired, is a separate explicitly authorized action.

## Publication sequence

```text
1. Merge the reviewed corrective pull request through the protected `main` branch.
2. Observe all mandatory jobs green on the exact final `main` commit.
3. Rebuild and verify release artifacts from that green commit.
4. Create a new annotated tag and GitHub prerelease with checksums.
5. Verify the public repository, tag, release assets, links, and reporting channel.
6. Do not upload to a package index or container registry without separate explicit authorization.
```

## Final statement

The tree is a coherent, installable, locally and remotely verified research beta and is **READY FOR
A CORRECTIVE PUBLIC RESEARCH-BETA RELEASE** after the controls above pass. It is not production
ready. `v0.1.0b2` changes attribution, documentation, version metadata, and repository governance;
it does not change core gateway functionality.
