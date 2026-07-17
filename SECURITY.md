# Security policy

## Supported versions

| Version | Support status |
|---|---|
| `0.1.0b1` | Research-beta security reports accepted on a best-effort basis |
| Earlier snapshots | Unsupported |

This project is a research MVP and is **not approved for production deployment or public network
exposure**. It has no authentication, role authorization, CSRF protection, malware scanner, or
sandboxed parser service.

## Private vulnerability reporting

Do not open a public issue for a suspected vulnerability and never attach real CTI, credentials,
customer data, private indicators, or exploit material to an issue.

Use GitHub Private Vulnerability Reporting through the repository's
[Security → Report a vulnerability](https://github.com/ag2020sa/cti-ai-trust-gateway/security/advisories/new)
page. This channel must be enabled and verified before the beta tag is created. Do not use the
conduct-reporting address for vulnerabilities.

Include only a minimal synthetic reproduction, affected version, impact, and suggested mitigation.
The maintainers will acknowledge reports when available, but this beta carries no response-time or
support-level commitment.

## Trust boundary

Both the source document and candidate STIX are hostile input. The gateway extracts text without
following links or intentionally executing attachments, constrains upload and JSON/PDF resources,
performs offline schema validation, binds claims to source evidence, and applies fail-closed export
policy. The default semantic provider makes no network call.

These controls do not make arbitrary PDF parsing safe. Production use would require isolated and
resource-constrained parsing, malware scanning, authenticated users, role-based authorization,
CSRF and rate-limit controls, encrypted storage, signed audit retention, monitoring, and controlled
egress. API keys are read only from the environment and provider exceptions are sanitized.

## Sensitive CTI

Use only synthetic fixtures and reserved documentation IP/domain ranges in public reports and test
cases. If a vulnerability can only be demonstrated with sensitive information, describe the shape
of the input privately without transmitting the underlying report.
