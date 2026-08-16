# Catalog data

Omega's repository pipeline publishes two SQLite databases with separate roles. See [`WORKFLOW.md`](WORKFLOW.md) for the complete lifecycle.

The repository commits only small human-maintained inputs and human-readable status files. Generated SQLite databases and large intermediate data are release assets or GitHub Actions artifacts rather than binaries committed to `main`.

Database-processing changes are self-applying. A `main` push touching `tools/catalog/**`, source definitions, the bootstrap database, or any of the three database-pipeline workflow files starts the catalog builder, which then hands off to the security scanner and compactor/projector. This ensures schema/normalization/sanitation changes are applied to existing state automatically.

## Client marketplace release

Published under `catalog-latest`:

- `omega-marketplace.sqlite.zip` — small production marketplace database; this is the only online database Omega downloads.
- `omega-marketplace.sqlite.zip.sha256` — transport checksum.
- `catalog.json` — marketplace descriptor containing Catalog, Security, and Evidence Revisions plus exact SQLite/ZIP hashes.
- `marketplace-projection-report.json` — projection size and runtime-equivalence validation.
- `catalog-report.json` — catalog build summary when available.

The ZIP contains an internal `omega-catalog.sqlite` entry so the client can keep its established local filename and atomic replacement behavior.

## Server-side evidence release

Published under `security-evidence-latest`:

- `omega-security-evidence.sqlite.zip` — detailed static-analysis evidence database used by repository automation and auditing.
- `omega-security-evidence.sqlite.zip.sha256` — evidence transport checksum.
- `evidence.json` — evidence database descriptor and Evidence Revision.
- `security-report.json` — most recent scanner batch summary when available.
- `compaction-report.json` — evidence compaction, integrity, revision, and publication report.
- `security-scan-ledger.json` — operational scan freshness used to avoid repeated timestamp-only rescans.

The Omega plugin has no endpoint for this release and never downloads the evidence database.

## Revision identity and changelog

`catalog_meta` stores `catalog_revision`, `security_revision`, and `evidence_revision`. These are semantic troubleshooting identifiers, not transport checksums:

- Catalog Revision identifies the logical marketplace plus current user-facing security state.
- Security Revision identifies normalized current static-analysis conclusions and incorporates scanner semantics.
- Evidence Revision identifies the detailed server-side evidence state.

Exact SQLite and ZIP bytes are verified separately with SHA-256 values. Operational timestamps and packaging-only changes do not advance semantic revisions.

`catalog_changelog` records logical Catalog Revision changes with previous/current Catalog, Security, and Evidence Revisions plus bounded change counters. A detailed evidence-only change can advance Evidence Revision without manufacturing a new logical Catalog Revision; the small marketplace projection is refreshed so its Evidence Revision remains an exact troubleshooting reference.

Timestamp-only revalidation freshness lives in `security-scan-ledger.json`, so normal rechecks do not create false semantic revisions or unnecessary database replacements.

## Marketplace security projection

The marketplace database carries only current compact security information required by Omega: status, artifact hash, scanner version, severity/counts, observed capabilities, automation classification, bounded findings/evidence, a bounded deduplicated dependency summary (up to 30 components plus total count), source provenance, and errors. Detailed `plugin_security_*` forensic tables are physically absent.

## Detailed evidence storage

The evidence database retains append-only scan history and normalized dependency/import/permission/automation evidence, managed assembly metadata, managed symbols, IL call sites, bounded local reachability, dependency graph/version intelligence, public dependency-advisory matches, lineage, drift, and source/artifact comparisons. Bounded static endpoint/path evidence and cross-source artifact-hash findings are retained as review context without asserting runtime behavior.

The compactor bounds redundant report JSON while preserving normalized rows and verifies SQLite integrity, foreign keys, and the full runtime projection. The marketplace projector then creates the physically smaller client database and verifies the same logical runtime projection before publication.
