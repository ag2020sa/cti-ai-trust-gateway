# Threat model

See [SECURITY.md](../SECURITY.md) for the deployment-facing threat model. The principal attacker
controls document bytes, PDF layout and metadata, filenames, candidate JSON/STIX, Unicode content,
and claim confidence. The attacker may seek prompt injection, parser compromise, resource
exhaustion, path traversal, secret leakage, false attribution, audit confusion, or unsafe export.

The gateway validates size and filename, accepts three formats, never follows document links,
uses safe JSON/YAML loaders, scans PDF spans, keeps external semantics disabled, and exports only
objects with evidence or analyst acceptance. Residual PDF parser and denial-of-service risk means
the MVP remains local and single-user.
