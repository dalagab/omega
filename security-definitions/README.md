# Secondary security definitions

This tree is the small, reviewable source-controlled input surface for SigmaScope's optional secondary security engines. Everything is supplemental evidence; it never replaces SigmaScope severity, capability, artifact identity, source attribution, or review-coverage logic.

- `yara/`: reviewed first-party/curated YARA rules and the mandatory provenance/false-positive policy. Rules are disabled unless their metadata explicitly enables them after review.
- `clamav/`: documentation only. Official CVD/CLD databases are refreshed only at the daily Definitions boundary and transported as content-addressed release assets rather than committed to Git.

Continuous SigmaScope workers do **not** update secondary definitions. Large ClamAV assets and enabled engine executables are identity-pinned; mismatches result in unavailable secondary evidence rather than mutable fallback behavior.
