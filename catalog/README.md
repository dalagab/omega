# Catalog data

Omega's production marketplace catalog is a SQLite database built by GitHub Actions.
See [`WORKFLOW.md`](WORKFLOW.md) for the complete lifecycle.

The repository intentionally commits only small human-maintained inputs and human-readable status
files. Large generated intermediate JSON files are Actions artifacts; the generated SQLite database is a
release asset rather than a binary committed to `main`.

Published assets under `catalog-latest`:

- `omega-catalog.sqlite.zip` — compressed production database.
- `omega-catalog.sqlite.zip.sha256` — transport checksum.
- `catalog.json` — descriptor containing semantic Catalog/Security Revisions plus separate SQLite and ZIP SHA-256 hashes.
- `catalog-report.json` — counts and generation metadata for operators.
- `security-report.json` — summary of the most recent security-scanner batch.
- `compaction-report.json` — before/after size, integrity, semantic publication decision, and projection-preservation report for the published compacted database.
- `security-scan-ledger.json` — small operational freshness ledger used to avoid repeated timestamp-only rescans; it does not define the semantic Security Revision.

Omega 0.8 consumes only the SQLite database. Intermediate JSON files may be imported by the online builder
but are not runtime catalog formats.

### Revision identity and changelog

`catalog_meta` stores the current `catalog_revision` and `security_revision`. These are semantic troubleshooting identifiers, not transport checksums. `catalogSha256` verifies the exact SQLite bytes and `bundleSha256` verifies the downloaded ZIP; the semantic revisions ignore operational timestamps and packaging-only changes.

`catalog_changelog` is retained inside the production database. A row is added only when the logical Catalog Revision changes and includes the previous/current Catalog and Security Revisions plus bounded counts for plugin, source, security, finding, and dependency changes. No-op security revalidation therefore does not manufacture a new database identity or changelog entry.

Timestamp-only revalidation freshness lives in `security-scan-ledger.json` instead of forcing a new database release. The scanner consults that ledger when deciding whether an unchanged artifact is due again. The compactor publishes only the ledger on semantic no-op runs.

### Security and dependency intelligence

`plugin_security_scans` stores append-only scan history for exact catalog variants and artifact hashes. `plugin_security_findings` stores structured rule results and bounded evidence. `plugin_security_current` points each active variant at its latest scan summary so the runtime projection can display security information without expensive aggregation in the game client.

Detailed dependency, import, managed-metadata, IL call-site, reachability, permission, dependency-resolution, component, compatibility/advisory, lineage, drift, and source/artifact-comparison evidence is normalized into dedicated tables. The database compactor therefore does not need to retain duplicate multi-megabyte copies of that same evidence inside `report_json`: historical and current report payloads are reduced to the bounded `omega.plugin-security.scan-summary.v1` form while normalized evidence and scan history remain intact.

Soft and optional dependencies remain distinct from required dependencies. The compactor validates SQLite integrity, foreign keys, preserved row counts, and an exact hash of the runtime catalog projection before a compacted database can replace the production release.
