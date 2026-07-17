# License-safe offline fixtures

These small files are checked into the repository so tests never need network
access. They are not a mirror of any upstream corpus.

- `oasis-indicator.json` is repository-authored and structurally based on the
  OASIS STIX 2.1 “Indicator for Malicious URL” example. It uses reserved
  `.invalid` data and new identifiers. Source consulted:
  https://oasis-open.github.io/cti-documentation/stix/examples.html
- `mitre-attack-subset.json` contains four identifier/name/status records for
  test mapping only. MITRE terms permit research, development, and commercial
  use with the included designation: “© 2026 The MITRE Corporation. This work
  is reproduced and distributed with the permission of The MITRE Corporation.”
  Source and terms: https://attack.mitre.org/resources/terms-of-use/
- `vulnerability-subset.json` is a tiny repository-authored selection of
  structured fields used by CISA KEV and NVD. It is not a current KEV feed and
  must not be used for prioritization. NIST states its publications are public
  domain and requests this notice: “This product uses data from the NVD API but
  is not endorsed or certified by the NVD.” Sources:
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog and
  https://nvd.nist.gov/general/FAQ-Sections/General-FAQs
- `report-en.txt`, `report-ar.txt`, and `report-mixed.txt` are original text
  written for this repository and released under the repository license.

Snapshot date: 2026-07-17. All values are static. Update only through an
explicit, reviewed change that rechecks upstream terms and attribution.
