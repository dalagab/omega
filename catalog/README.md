# Catalog data

Omega's production marketplace catalog is a SQLite database built by GitHub Actions.
See [`WORKFLOW.md`](WORKFLOW.md) for the complete lifecycle.

The repository intentionally commits only small human-maintained inputs and human-readable status
files. Large generated intermediate JSON files are Actions artifacts; the generated SQLite database is a
release asset rather than a binary committed to `main`.

Published assets under `catalog-latest`:

- `omega-catalog.sqlite.zip` — compressed production database.
- `omega-catalog.sqlite.zip.sha256` — transport checksum.
- `catalog.json` — descriptor containing separate SQLite and ZIP SHA-256 hashes.
- `catalog-report.json` — counts and generation metadata for operators.

Omega 0.8 consumes only the SQLite database. Intermediate JSON files may be imported by the online builder
but are not runtime catalog formats.

### Security and dependency intelligence

`plugin_security_scans` stores append-only scan history for exact catalog variants and artifact hashes. `plugin_security_findings` stores structured rule results and bounded evidence. `plugin_security_current` points each active variant at its latest scan summary so the runtime projection can display security information without expensive aggregation in the game client.

The external scanner also maintains normalized dependency, import, managed-metadata, IL call-site, reachability, dependency-resolution, component, compatibility/advisory, lineage, drift, and source/artifact-comparison tables. These records remain keyed to the exact scan and catalog variant so enrichment can improve over time without changing the identity of the marketplace entry. Soft and optional dependencies remain distinct from required dependencies.
