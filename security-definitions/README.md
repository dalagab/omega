# Secondary security definitions

This tree is SigmaScope's small, reviewable source-controlled Definitions input surface. Everything is supplemental evidence; it never replaces SigmaScope severity, capability, artifact identity, source attribution, or review-coverage logic.

- `packs/`: reviewed/experimental/local SRL Definition Pack source. Daily compilation freezes exact pack provenance, fixtures and active compiled rules without letting source YAML float at worker runtime.
- `yara/`: reviewed first-party/curated YARA rules and the mandatory provenance/false-positive policy. Rules are disabled unless their metadata explicitly enables them after review.
- `clamav/`: documentation only. Official CVD/CLD databases are refreshed only at the daily Definitions boundary and transported as content-addressed release assets rather than committed to Git.
- `external-analysis/`: license-gated research-source registry for public analyzer projects that may inform native SigmaScope detector development. It is never a runtime rule feed or SRL authority.
- `semantic-flow/`: frozen source/sink/sanitizer vocabulary for SigmaScope's bounded neutral data-flow observations. It supplies scanner semantics only; SRL/Stigma-1 remains the interpretation and finding authority.

Continuous SigmaScope workers do **not** update secondary definitions. Large ClamAV assets and enabled engine executables are identity-pinned; mismatches result in unavailable secondary evidence rather than mutable fallback behavior.
