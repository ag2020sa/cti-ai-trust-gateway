# Policy engine

Policies are ordered YAML rules with an ID, a simple `when` selector, a verdict, and a reason.
Selectors match finding category, severity, or rule ID. Every matching rule is recorded. Final
verdict precedence is QUARANTINE, REJECT, REVIEW, ABSTAIN, then PASS. Findings keep their own
evidence and recommended action, while the policy explains case disposition.

The default policy quarantines critical document instructions, rejects invalid STIX and corrupted
observables, reviews unproven relationships and confidence inflation, and passes only when no rule
fires. `abstain.yml` demonstrates an alternate stance for unavailable semantic verification.
