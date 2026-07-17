# ADR 0001: Local modular monolith

- Status: accepted
- Date: 2026-07-17

## Decision

Build a local-first modular monolith with one Python package. FastAPI, Typer, the analyst UI,
verification pipeline, and SQLite repository share typed domain models but are separated by
module boundaries. Runtime uploads and exports live under an ignored `data/runtime` directory.

## Rationale

The MVP needs a single auditable verification path more than distributed scalability. This
keeps deterministic behavior testable and permits later extraction of provider or storage
adapters without introducing network trust boundaries today.

## Consequences

The demo has no authentication and must bind to localhost by default. SQLite and in-process
analysis are not suitable for untrusted multi-tenant production use.
