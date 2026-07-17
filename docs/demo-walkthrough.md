# Demo walkthrough

Run `cti-trust demo`. Five deterministic cases are stored locally:

1. PASS: exact IP and CVE evidence.
2. REJECT: invented APT28 attribution, unsupported relationship, one-digit IP corruption, and
   inflated confidence.
3. QUARANTINE: visible instruction injection.
4. ABSTAIN: two entities co-occur but no semantic verifier can prove a relationship, using the
   explicit abstention policy.
5. REVIEW: mixed Arabic/English attribution context needs an analyst.

Open `http://127.0.0.1:8000`, inspect evidence offsets, record a review, then export the evidence
manifest and approved STIX. Rejected relationships are absent from export.
