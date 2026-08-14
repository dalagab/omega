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
5. **Publish** — the workflow uploads `omega-catalog.sqlite.zip`, its SHA-256 file, `catalog.json`,
   and the human-readable report to the stable `catalog-latest` release.
6. **Verify** — the published ZIP and extracted DB are downloaded again; both hashes and SQLite
   integrity are verified after publication.

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
