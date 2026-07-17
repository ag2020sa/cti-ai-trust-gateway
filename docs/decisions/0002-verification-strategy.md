# ADR 0002: Evidence-first verification with explicit abstention

- Status: accepted
- Date: 2026-07-17

## Decision

Exact observables are checked deterministically against immutable source text. Entity mentions
may use case-insensitive, Unicode-normalized, or labeled fuzzy matching. Co-occurrence never
proves a relationship. Relationships require a configured semantic verifier or remain REVIEW /
ABSTAIN. Policy selection happens after findings are produced and records every fired rule.

## Rationale

Separating extraction from verification prevents a fluent AI assertion from being treated as
evidence. Explicit abstention makes missing verification capability visible.

## Consequences

The default no-network mode intentionally produces conservative outcomes for semantic claims.
Analysts can approve or reject them, with every decision appended to the audit chain.
