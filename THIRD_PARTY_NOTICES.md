# Third-party notices

This project depends on FastAPI, Pydantic, SQLAlchemy, Typer, stix2, stix2-validator, PyMuPDF,
Jinja2, PyYAML, Uvicorn, pytest, Ruff, and mypy. Their respective license texts and source links
are available from their distributions. Dependency installation does not copy their source into
this repository.

MITRE ATT&CK® identifiers may appear in synthetic examples. ATT&CK is a registered trademark of
The MITRE Corporation; use is for identification and does not imply endorsement. OASIS STIX,
CISA, NVD, Saudi NCA/CERT, MITRE, and CTIBench links in the registry are references only. No
organization endorses this project. CTIBench is not vendored because it is CC BY-NC-SA. External
reports are not redistributed.

## OASIS STIX 2.1 JSON Schemas

The offline schema set under `src/cti_trust_gateway/data/stix2.1` is from
`oasis-open/cti-stix2-json-schemas`, pinned to commit
`c4f8d589acf2bdb3783655c89e0ffb6e150006ae`, and distributed under the
BSD 3-Clause License. The complete upstream license and integrity manifest are
included beside the schema files.

## MITRE ATT&CK test subset

The four-record offline test subset is used under the MITRE ATT&CK terms:
“© 2026 The MITRE Corporation. This work is reproduced and distributed with
the permission of The MITRE Corporation.” MITRE ATT&CK® is a registered
trademark of The MITRE Corporation. No endorsement is implied.

## NVD test data

The repository includes one small public-domain, schema-shaped NVD/CISA test
record. “This product uses data from the NVD API but is not endorsed or
certified by the NVD.” It is a static fixture, not a current vulnerability feed.

## OpenCTI public interface research

The OpenCTI Phase 1 compatibility profile and clean-room adapter were researched from public
interface facts in the Apache-2.0-licensed OpenCTI repositories. No upstream implementation code,
fixtures, or GraphQL source text is copied into this repository; the short GraphQL operations here
were independently authored to call the documented schema. The exact research pins are:

- OpenCTI platform commit `148ceb414d1338d7c10ff79f0302d0a03dae332f`:
  <https://github.com/OpenCTI-Platform/opencti/tree/148ceb414d1338d7c10ff79f0302d0a03dae332f>
- PyCTI release/version `7.260715.0` within that repository.
- OpenCTI connectors commit `b70a94b526574a040953cba73b3c76ec3ead6f21`:
  <https://github.com/OpenCTI-Platform/connectors/tree/b70a94b526574a040953cba73b3c76ec3ead6f21>
- OpenCTI Apache-2.0 license:
  <https://github.com/OpenCTI-Platform/opencti/blob/148ceb414d1338d7c10ff79f0302d0a03dae332f/LICENSE>

The exact interface files used for compatibility research are linked in
`docs/opencti-phase1.md`. The 19 bilingual/mixed OpenCTI contract fixtures are original test-only
data authored for this project and are excluded from release wheels.

OpenCTI and related names and marks belong to their respective owners. Compatibility references
are for identification and interoperability research only and do not imply sponsorship,
certification, partnership, or endorsement by Filigran or the OpenCTI project.
