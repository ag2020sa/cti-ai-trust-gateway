# Data strategy

Repository-owned test data is synthetic, bilingual, deterministic, licensed Apache-2.0, and
explicitly marked as fictional. `scripts/build_synthetic_benchmark.py` creates ten base reports
and at least 100 mutations. Runtime uploads, SQLite data, and exports are ignored.

The source registry stores only links and usage metadata. It does not redistribute full CISA,
Saudi CERT, commercial, or other third-party reports. MITRE and OASIS material must retain their
own attribution and licenses if a user downloads it. CTIBench must be evaluated separately under
CC BY-NC-SA; it is never vendored into this Apache-2.0 core.
