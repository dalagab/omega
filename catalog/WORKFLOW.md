# Omega SQLite catalog workflow

Omega 0.8 uses one production catalog file: `omega-catalog.sqlite`.

The game client does not crawl the public plugin ecosystem. GitHub Actions discovers sources,
normalizes manifests, enriches public project pages, updates the SQLite database, validates it,
compresses it for transport, and publishes it under the stable `catalog-latest` release.

## What remains JSON

JSON is intentionally retained where it is useful to humans and automation:

- `sources/curated-sources.json` — human-maintained authoritative/preseed source list.
- workflow artifacts `raw-sources.json`, `enriched-sources.json`, and
  `website-enrichment.json` — inspectable stage outputs and import inputs.
- `catalog/catalog-endpoint.json` — tiny client pointer to the release descriptor.
- `catalog/latest-report.json` — human-readable build summary.

None of those files is the runtime marketplace database.

## Production database

`omega-catalog.sqlite` contains source provenance, logical plugins, repository/API variants,
tags, screenshots, public website enrichment/cache state, presentation scoring, first/last-seen
timestamps, original normalized manifest JSON, and a normalized search table.

The previous published database is downloaded at the beginning of a build and used as the seed.
That preserves first-seen timestamps and last-known-good enrichment across transient failures.

## Scheduled stages

1. **Collect** — `collect_sources.py` combines `curated-sources.json`, the current Puni.sh
   repository directory, and GitHub code search results.
2. **Enrich manifests** — `enrich_metadata.py` loads the previous SQLite source state and sends
   `If-None-Match` / `If-Modified-Since` when ETag or Last-Modified values are available. HTTP 304
   keeps the previous variants active without downloading/parsing the manifest again. Changed feeds
   are normalized into a JSON artifact; transient failures retain the previous good DB rows.
3. **Enrich websites** — `scrape_websites_incremental.py` reads successful website metadata and all
   active project URLs from the previous SQLite database. Fresh results are reused; only new/stale
   project pages are sent to `scrape_websites.py`. Project URLs from 304 manifest feeds therefore
   continue aging and are still rechecked when stale. The GitHub token stays on the runner.
4. **Build SQLite** — `build_sqlite_catalog.py` imports the JSON artifacts into the seeded DB,
   preserves last-known-good rows on failures, recalculates presentation metadata and search text,
   runs `ANALYZE`, `VACUUM`, and `PRAGMA integrity_check`, then writes the release descriptor.
5. **Hand off base catalog** — the catalog builder uploads the normalized catalog bundle and descriptor as the `omega-sqlite-catalog` Actions artifact. It does not replace the production release.
6. **Security enrichment** — `security-scanner.yml` consumes that exact builder artifact, adds bounded static security and dependency intelligence, computes candidate semantic Catalog/Security Revisions, validates the result, and emits `omega-security-catalog`. The uncompacted security database is never published as the runtime catalog.
7. **Compact and compare** — `catalog-compaction.yml` consumes the successful security artifact, rewrites redundant security JSON snapshots to bounded summaries, runs `ANALYZE` and `VACUUM INTO`, verifies preserved history/evidence and the complete `runtime_plugin_variants` projection, then compares the candidate semantic revisions with the previous production database.
8. **Record changelog** — when the semantic Catalog Revision changed, the compactor appends one `catalog_changelog` row containing previous/current revision IDs and bounded change counters. Timestamp-only revalidation does not create a changelog entry.
9. **Publish final catalog when required** — only a semantic catalog change or an explicit compactor representation migration can replace `catalog-latest`. Unchanged successful runs finish without release replacement.
10. **Verify** — the published ZIP and extracted DB are downloaded again; transport hashes, semantic revisions, SQLite integrity, foreign keys, compactor metadata, and report-size ceilings are verified after publication.

## Workflow and Python regression testing

The repository keeps workflow orchestration and validation logic separately testable. Complex SQLite, hash, security-enrichment, and compaction checks are implemented in importable `tools/catalog/validate_*.py` modules. The GitHub workflow files call those modules rather than embedding large Python programs directly in YAML.

`tools/tests/` contains deterministic standard-library `unittest` coverage for source collection, manifest normalization, HTTP 304/cache behavior, website-cache continuity, version compatibility, archive safety, scanner resource ceilings, compaction invariants, and the catalog/security/compaction validators. Workflow-contract tests verify exact upstream workflow names, success gates, permissions, artifact names, publication ownership, command arguments, and the release regression gate.

An offline handoff fixture builds a small SQLite catalog, applies the security schema/enrichment path without network scans, sends the resulting artifact through the compactor, and validates the final database. This catches schema or transport-contract regressions between workflows without touching `catalog-latest`.

The dedicated `.github/workflows/regression-tests.yml` workflow runs these Python tests plus the existing scanner, hardening, compactor, SQLite, and Windows/.NET regression suites on relevant pushes and pull requests. The production catalog/security/compaction workflows also run the Python suite before doing publication work.

## Semantic revisions and publication

The final descriptor and SQLite metadata expose **Catalog Revision** (`cat-v1-…`) and **Security Revision** (`sec-<scanner-version>-…`). Catalog Revision hashes the logical marketplace plus current security state. Security Revision hashes normalized current security evidence and includes the scanner version because a change in analysis semantics is meaningful. Neither revision is based on generated/scanned/compacted timestamps.

The exact SQLite and bundle SHA-256 values remain separate transport-integrity identifiers. A physical representation change can therefore alter `catalogSha256`/`bundleSha256` while leaving the semantic revisions unchanged. This is used when a new compactor representation must be deployed without claiming that plugin security intelligence changed.

The compactor is the only production catalog publisher. It compares the candidate against the previous `catalog-latest` database and emits a fail-closed publication decision. No semantic change means no release replacement and no new `catalog_changelog` row.

Operational scan freshness is intentionally separate from semantic identity. `security-scan-ledger.json` tracks successful revalidation time, scanner version, artifact URL/version, and artifact hash per variant. The scanner can therefore suppress another timestamp-only rescan even when the no-op database candidate was not published. On a semantic no-op the compactor updates only that small ledger asset; on a real catalog publication it ships the ledger alongside the database.

## Runtime update contract

Omega downloads only `catalog.json` during a catalog check. If its `catalogSha256` is already
applied, no database download occurs. If changed, Omega downloads the compressed SQLite bundle,
verifies `bundleSha256`, extracts `omega-catalog.sqlite`, validates the schema and
`PRAGMA integrity_check`, then atomically swaps it into the plugin configuration directory.

If the network or candidate DB fails, the existing local SQLite database remains untouched.
There is no public-repository fan-out fallback inside the FFXIV process.

## Website enrichment

Website enrichment is presentation-only. It never changes which repository Dalamud installs from.
A successful indexed public project page may provide descriptions, README excerpts, topics,
repository statistics, and presentation images. Omega marks those listings with a star to mean
"richer indexed project information", not endorsement or security review.

The previous SQLite DB stores source ETag/Last-Modified/content hashes plus `last_success_utc` and
full normalized website metadata. A daily run therefore avoids redownloading unchanged manifests
and does not re-scrape every successful project. The default website reuse window is seven days and
can be changed from workflow dispatch.

## Importing older/generated JSON manually

The builder intentionally accepts the inspectable stage documents:

```bash
python tools/catalog/build_sqlite_catalog.py \
  --raw-sources catalog/raw-sources.json \
  --enriched-sources catalog/enriched-sources.json \
  --website-enrichment catalog/website-enrichment.json \
  --seed catalog/seed/omega-catalog.sqlite.zip \
  --out catalog/dist \
  --download-url https://example.invalid/omega-catalog.sqlite.zip \
  --descriptor-url https://example.invalid/catalog.json
```

This is an import path for tooling and data recovery, not a compatibility path in the Omega client.

## Security enrichment and compaction

After the normal catalog builder has refreshed manifests and public project metadata, `security-scanner.yml` enriches only variants that are new, changed, previously incomplete, produced by an older scanner, or due for periodic revalidation. The scanner job has read-only repository permission and emits the security-enriched database as an Actions artifact instead of publishing the large intermediate database directly.

`catalog-compaction.yml` runs after a successful security workflow. It preserves scan rows, findings, dependency history, normalized dependency data, managed metadata, IL call-site evidence, reachability evidence, and the current per-variant security projection. Redundant `report_json` copies are rewritten to the bounded `omega.plugin-security.scan-summary.v1` form before SQLite is vacuumed into a fresh database. The workflow hashes the complete `runtime_plugin_variants` view before and after compaction and refuses publication if client-visible data changes.

Only the compacted security-enriched database is published to `catalog-latest`. `compaction-report.json` records database bytes before/after, bytes saved, payload-size changes, integrity/foreign-key results, and the runtime projection hash. The game client therefore receives security intelligence through the normal catalog update path; it never downloads third-party artifacts for scanning itself.
