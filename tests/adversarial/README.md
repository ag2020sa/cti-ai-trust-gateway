# Independent adversarial suite

`cases.py` contains manually enumerated source text, candidate objects, expected
verdicts, and a plain-language reason for every expectation. It does not import
the synthetic benchmark or any mutation-generation function, and it never asks
production validation code to calculate the expected answer.

The catalog covers observable integrity, grounding and relationship semantics,
ATT&CK/CVE mapping, STIX structure, Arabic and bilingual language, document
attacks and false-positive controls, and all primary policy outcomes. Separate
security tests in this directory cover ABSTAIN, unavailable validators, review
override attempts, malformed inputs, XSS, uploads, and export invariants.
