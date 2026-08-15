# Omega catalog and security evidence workflow

Omega publishes two physically separate SQLite databases with different purposes:

- `catalog-latest/omega-marketplace.sqlite.zip` is the small client marketplace database. Omega downloads this database.
- `security-evidence-latest/omega-security-evidence.sqlite.zip` is the detailed static-analysis evidence store. Repository automation uses it; the Omega plugin does not have an endpoint for it and never downloads it.

The game client does not crawl public plugin repositories and does not download third-party plugin packages for analysis. GitHub Actions performs discovery, enrichment, static analysis, evidence retention, marketplace projection, validation, and publication.

## What remains JSON

JSON is intentionally retained where it is useful to humans and automation:

- `sources/curated-sources.json` — human-maintained authoritative/preseed source list.
- workflow artifacts `raw-sources.json`, `enriched-sources.json`, and `website-enrichment.json` — inspectable build inputs.
- `catalog/catalog-endpoint.json` — tiny client pointer to the marketplace release descriptor.
- `catalog/latest-report.json` — human-readable catalog build summary.
- `security-scan-ledger.json` — operational scan freshness stored with the evidence release.
- `catalog.json` / `evidence.json` — transport descriptors for the marketplace and evidence databases respectively.

None of the intermediate JSON documents is the runtime marketplace database.

## Database roles

### Marketplace database

The client database contains source provenance, logical plugins, repository/API variants, tags, screenshots, public website enrichment, presentation/search data, current security summaries, current automation summaries, semantic revision identifiers, and the embedded catalog changelog.

Detailed historical scanner tables are physically absent from this database. In particular, managed symbols, IL call sites, reachability graphs, detailed scan history, and full normalized forensic evidence are not shipped to Omega clients.

### Security evidence database

The server-side evidence database contains the complete catalog state needed by the scanner plus scan history, normalized findings, dependency evidence, permission candidates, automation evidence, managed assembly metadata, managed symbols, IL call sites, reachability, lineage, drift, and source/artifact comparison records.

This database can be substantially larger because it is repository infrastructure rather than a client payload. The marketplace database records the Evidence Revision that corresponds to its security summaries, so support and audit tooling can identify the detailed evidence state without teaching Omega how to download it.

## Automatic pipeline

The catalog builder runs daily, can be dispatched manually, and also starts on `main` whenever `tools/catalog/**`, `sources/**`, `catalog/bootstrap/**`, or any of the catalog-builder/security-scanner/catalog-compaction workflow definitions change. Scanner and compactor push triggers are intentionally not duplicated: they run from the builder/scanner `workflow_run` chain. This means a change to any database collection, normalization, schema, migration, security, compaction, or projection implementation reprocesses the existing state from the beginning instead of relying on an operator to remember a follow-up Action.

1. **Preflight** — run deterministic Python/workflow regressions plus the catalog/projector self-tests.
2. **Collect** — `collect_sources.py` combines curated sources, the current Puni.sh repository directory, and bounded GitHub source discovery.
3. **Enrich manifests** — `enrich_metadata.py` uses the previous small marketplace database as an HTTP/cache seed and preserves previous good rows across transient failures. PluginMaster feeds may use trailing commas before `]`/`}`; that narrow community-format extension is accepted without relaxing other malformed JSON.
4. **Enrich websites** — `scrape_websites_incremental.py` reuses fresh successful enrichment and refreshes only new/stale project pages.
5. **Build authoritative catalog state** — `build_sqlite_catalog.py` imports the intermediate documents into the previous full evidence database when available, preserving scanner history while refreshing marketplace/source data. On the first split migration it can consume the legacy `catalog-latest/omega-catalog.sqlite.zip` database.
6. **Hand off builder artifact** — the builder uploads `omega-sqlite-catalog`. It does not publish either production database.
7. **Security enrichment** — `security-scanner.yml` consumes the exact builder artifact, statically scans new/changed/due variants, writes normalized evidence, derives current security and automation summaries, updates candidate semantic revisions, and emits `omega-security-catalog`. The scanner has read-only repository permission and publishes no release assets.
8. **Compact evidence** — `compact_sqlite_catalog.py` applies additive schema migrations, bounds redundant report JSON, preserves normalized history/evidence, runs `ANALYZE`/`VACUUM INTO`, and validates integrity, foreign keys, and the full runtime projection.
9. **Project marketplace database** — `project_marketplace_catalog.py` creates a new small SQLite database, retains only the compact current security projection needed by Omega, derives a bounded dependency summary from current dependency/resolution/issue/advisory evidence before physically removing the detailed scanner tables, and verifies that the pre-existing runtime projection is unchanged apart from the new bounded dependency fields.
10. **Resolve publication** — `publication_decision.py` compares semantic and representation revisions with the previously published state. Timestamp-only scans do not force database publication.
11. **Publish evidence when required** — the detailed evidence bundle is published to `security-evidence-latest` and verified remotely.
12. **Publish marketplace when required** — Catalog Revision, Evidence Revision, or marketplace representation changes can require the small client database to advance. If Evidence Revision must advance, marketplace publication waits for successful evidence publication first. The small client bundle is then published to `catalog-latest` and verified remotely.
13. **No-change scan** — when neither database needs replacement, only `security-scan-ledger.json` may advance on the evidence release so scan freshness is retained without causing a client download.

## Workflow and Python regression testing

Complex SQLite, hash, scanner, revision, projection, and publication checks are implemented in importable `tools/catalog/*.py` modules rather than large inline workflow scripts. `tools/tests/` exercises those modules directly and also statically checks GitHub Actions contracts such as permissions, exact upstream workflow names, success gates, artifact names, publication ownership, and release ordering.

The workflow regression contract also requires the broad `tools/catalog/**` builder trigger and verifies that downstream scanner/compactor workflows do not duplicate the same push. New catalog-processing Python modules placed under `tools/catalog/` are therefore covered automatically.

The offline handoff fixture builds a small catalog, applies the security schema without external network scans, runs evidence compaction, projects the marketplace database, and validates both outputs. Legacy-schema regression coverage verifies that the current production evidence database can be upgraded before strict validation, including creation of newer automation tables/columns.

`.github/workflows/regression-tests.yml` runs the Python tests, SQLite/scanner/hardening/compactor/projector self-tests, and the Windows/.NET Omega regression build on relevant pushes and pull requests. Production workflows run the Python regression gate before performing network or publication work.

Run the repository-side Python suite locally with:

```bash
python -m unittest discover -s tools/tests -p 'test_*.py' -v
```

## Semantic revisions and changelog

The marketplace database exposes three troubleshooting identifiers:

- **Catalog Revision** (`cat-v1-…`) identifies the logical marketplace plus current user-facing security state.
- **Security Revision** (`sec-<scanner-version>-…`) identifies normalized current static-analysis conclusions. Scanner-version changes are meaningful because analysis semantics may change.
- **Evidence Revision** (`ev-v1-…`) identifies detailed server-side forensic evidence, including managed symbols, IL call sites, and reachability material.

These are not transport hashes. `catalogSha256`/`bundleSha256` and evidence database/bundle SHA-256 values verify exact bytes. Timestamps, VACUUM layout changes, and ZIP representation alone do not advance semantic revisions.

A detailed evidence-only change can advance Evidence Revision without changing user-facing Security Revision. Because the marketplace database displays the Evidence Revision for troubleshooting, that small database is refreshed when Evidence Revision changes even if Catalog Revision stays stable. A meaningful current capability/finding/dependency change advances Security Revision and therefore Catalog Revision.

`catalog_changelog` is embedded in the marketplace/evidence state. A row is appended only when Catalog Revision changes. It records previous/current Catalog, Security, and Evidence Revisions plus bounded change counters. Operational scan freshness is kept separately in `security-scan-ledger.json`, so revalidation timestamps do not create false changelog entries or unnecessary client downloads.

## Runtime update contract

Omega reads only `catalog.json` from `catalog-latest` during an update check. If its `catalogSha256` is already applied, no database download occurs. If the catalog changed, Omega downloads `omega-marketplace.sqlite.zip`, verifies `bundleSha256`, extracts the internal `omega-catalog.sqlite`, validates the expected marketplace schema and `PRAGMA integrity_check`, then atomically swaps the candidate into the plugin configuration directory.

The marketplace descriptor contains an Evidence Revision for troubleshooting, but no evidence database download URL. Omega source code has no `security-evidence-latest` or `omega-security-evidence.sqlite.zip` endpoint.

If the network or candidate marketplace DB fails validation, the existing local SQLite database remains untouched. There is no public-repository fan-out fallback inside the FFXIV process.

## Static automation intelligence

Scanner 2.0 derives bounded automation capability summaries from managed call-site, local reachability, source/import, dependency, and known IPC evidence. Current capability families include:

- game UI callbacks and menu manipulation;
- synthetic game UI clicks;
- character targeting;
- action execution;
- world/NPC interaction;
- teleport/travel invocation;
- movement/navigation;
- camera control;
- inventory/vendor/retainer control;
- keyboard/mouse input injection;
- indirect automation through known IPC providers.

Automation is summarized as observational, UI/menu automation, character control, or full gameplay automation. Confidence and reachability are stored separately. Static evidence shows capability or a reachable mechanism; it does not prove that a runtime branch executes during normal use.

The marketplace database contains only those compact summaries, a bounded set of human-readable evidence examples, and up to 30 deduplicated dependency components per variant with a total-count field. The complete methods, symbols, call sites, reachability records, and scan lineage remain in the evidence database.

## Website enrichment

Website enrichment is presentation-only. It never changes which repository Dalamud installs from. A successful indexed public project page may provide descriptions, README excerpts, topics, repository statistics, and presentation images. Omega marks those listings with a star to mean richer indexed project information, not endorsement or security review.

The previous marketplace database stores source ETag/Last-Modified/content hashes plus successful normalized website metadata. A daily run therefore avoids redownloading unchanged manifests and does not re-scrape every successful project. The default website reuse window is seven days and can be changed from workflow dispatch.

## Importing intermediate data manually

The builder still accepts inspectable intermediate documents for recovery/testing:

```bash
python tools/catalog/build_sqlite_catalog.py \
  --raw-sources catalog/raw-sources.json \
  --enriched-sources catalog/enriched-sources.json \
  --website-enrichment catalog/website-enrichment.json \
  --seed catalog/seed/omega-security-evidence.sqlite.zip \
  --out catalog/dist \
  --download-url https://example.invalid/catalog-latest/omega-marketplace.sqlite.zip \
  --descriptor-url https://example.invalid/catalog-latest/catalog.json
```

This is a repository-tooling path, not a compatibility/fallback path in the Omega client.

## Presentation metadata sanitation

Project-page enrichment is presentation-only and must never surface transport/debug failures as plugin copy. GitHub deep links such as `/tree/<branch>` are resolved to the repository identity and enriched through the GitHub repository API. HTTP diagnostic text such as 404/500 failure blocks is rejected from user-facing website descriptions and README excerpts. The builder also sanitizes previously seeded website rows before recomputing presentation, so a contaminated historical cache is cleaned during the next successful catalog build. Diagnostic errors remain available in source/website health fields instead of appearing under **About this plugin**.
