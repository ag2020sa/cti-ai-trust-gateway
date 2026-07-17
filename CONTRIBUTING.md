# Contributing

Thanks for helping improve this research MVP. Contributions should preserve its conservative,
source-evidence-first behavior.

## Development setup

Python 3.12 and 3.13 are declared targets. Pull requests to `main` must pass mandatory Python 3.12
and 3.13 quality/test jobs, distribution verification, and the Docker build/live-health job in
GitHub Actions. Python 3.13 is also verified locally; Python 3.12 and Docker are not installed on
the audit host and are therefore not represented as locally verified.

The public project home is
[github.com/ag2020sa/cti-ai-trust-gateway](https://github.com/ag2020sa/cti-ai-trust-gateway).

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
python -m ruff format --check .
python -m ruff check .
python -m mypy src
python -m bandit -q -c pyproject.toml -r src
python -m pip_audit --local
python -m pytest --cov --cov-branch --cov-fail-under=80
```

Add deterministic tests for every verification rule. Changes to trust boundaries, verdict
semantics, schema provenance, or export authorization should include an ADR under
`docs/decisions/` and relevant adversarial cases.

## Data and privacy

Never commit real reports, credentials, runtime databases, generated exports, private indicators,
personal data, or proprietary threat intelligence. Fixtures must be synthetic or clearly licensed,
use reserved documentation ranges where possible, and state provenance and license.

Do not report security vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md).

## Pull requests

- Keep changes focused and explain the assurance impact.
- Run all local quality gates and disclose unavailable checks.
- Do not weaken fail-closed behavior to make a test pass.
- Update documentation and release notes when behavior or packaging changes.
- Do not add live-network tests or production secrets.

Original contributions are licensed under Apache-2.0 when submitted to this project.
