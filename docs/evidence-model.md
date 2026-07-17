# Evidence model

An evidence span stores the source document ID, page when available, immutable character start and
end offsets, a surrounding snippet, match type, and suspicious-content flag. Search normalization
uses NFKC and removal of formatting controls without mutating original evidence.

Observables require exact byte-decoded text matches. A near match creates a rejection finding and
reports the closest source value. Entities may be case-insensitive, normalized, or explicitly
labeled fuzzy. The evidence coverage ratio excludes confidence-only claims. A relationship keeps
both endpoint spans but remains unknown unless semantics or an analyst supports it.
