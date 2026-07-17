## Summary

Describe the change and its assurance impact.

## Verification

- [ ] Ruff format and lint pass.
- [ ] mypy passes.
- [ ] Bandit passes.
- [ ] The installed-dependency audit passes.
- [ ] Full tests and the 80% branch-coverage gate pass.
- [ ] Independent adversarial tests pass.
- [ ] Packaging/docs were updated where relevant.
- [ ] No live-network test, secret, real CTI, database, upload, or generated export is included.
- [ ] Any unavailable check is disclosed explicitly.

## Security and data handling

Explain changes to trust boundaries, validation capability, review authorization, export behavior,
or data egress. Security vulnerabilities must use the private process in `SECURITY.md`.
