# Omega client security

## Reporting a vulnerability

Use GitHub private vulnerability reporting for `dalagab/omega` when available, or contact the maintainers privately. Do not publish a vulnerability that could put users at risk before a fix is available.

## Client trust boundary

The Omega client consumes a bounded SQLite marketplace database through `catalog/catalog-endpoint.json`. Downloaded catalog bundles are hash-checked and SQLite integrity-checked before replacement; a failed update keeps the last-known-good local database.

The client displays SigmaScope-derived information but does not execute SigmaScope or DeltaScope. Repository-side scanner implementation, evidence publication, catalog generation, and developer audits are maintained on the `sigmascope` branch.

Third-party plugins remain executable software. Omega security information is evidence for an informed decision, not an endorsement or guarantee. The complete user-facing risk disclosure is in `EULA.md`.
