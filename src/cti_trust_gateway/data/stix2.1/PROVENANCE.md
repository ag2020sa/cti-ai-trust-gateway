# Bundled OASIS STIX 2.1 JSON Schemas

- Upstream: https://github.com/oasis-open/cti-stix2-json-schemas
- Branch: `stix2.1`
- Pinned commit: `c4f8d589acf2bdb3783655c89e0ffb6e150006ae`
- Imported: 2026-07-17
- License: BSD-3-Clause (see `LICENSE`)
- Aggregate SHA-256: `43c2bf45bbaeeb44e5852553abffdebeaaa1584111d92d8a8d3a3101d8bd220f`

The aggregate digest is calculated by sorting relative POSIX paths, then hashing
a length-prefixed path followed by a length-prefixed file payload for every
`*.json` file. Runtime validation recomputes this digest and records it in
the evidence manifest. Normal analysis is offline and never downloads schemas.

Update procedure:

1. Review an upstream OASIS schema commit and its license.
2. Replace only this schema tree with files from that exact commit.
3. Update the commit and per-file hashes in this directory.
4. Update `SCHEMA_COMMIT` in `validators/stix.py`.
5. Run the complete unit, integration, adversarial, and wheel-install tests.
