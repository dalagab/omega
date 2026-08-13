# Omega catalog builder

Omega keeps runtime repository traffic deliberately small. GitHub Actions does the expensive discovery and validation work outside the game process and publishes a prebuilt database that uses the same repository-record layout as `CatalogDatabase` schema 1.

## Pipeline

1. `catalog/candidates.json` is the durable work queue. It is initially seeded from the three user-supplied discovery batches under `sources/discovery/` and is extended by GitHub code search.
2. `tools/catalog/discover_sources.py` searches public GitHub code for likely Dalamud repository-index filenames. Discovery never means trusted/accepted; it only adds candidates.
3. Before validation, the workflow downloads the previous `catalog-latest` database when one exists. `tools/catalog/build_catalog.py` walks every curated source plus every candidate, reuses the previous per-source ETag/Last-Modified validators, and only downloads a full JSON body when the server reports that source changed. Runner validation is parallel and bounded; runtime Omega remains conservative/sequential.
4. Every successfully fetched candidate is SHA-256 hashed. If its content is deterministically not a repository index, the hash is added to `catalog/known-bad-hashes.json`. Future runs skip that exact content immediately. If the upstream file changes, its hash changes and it is evaluated again.
5. DNS failures, timeouts, rate limits and HTTP failures are transient. They are reported but never added to the bad-content hash list. If the previous release contained a validated record for that source, the new bundle retains that last-known-good record instead of dropping the plugin metadata.
6. Valid discovered repositories that are not already in the hand-maintained curated list are written to `catalog/generated-sources.json`.
7. The runner publishes `omega-catalog-db.zip`, its SHA-256 checksum, `sources.json`, `catalog-report.json`, the generated-source list, and the bad-hash list both as a GitHub Actions artifact and as replaceable assets on the stable `catalog-latest` release. That release becomes the seed for the next run.

## Preloading Omega

`omega-catalog-db.zip` contains:

- `catalog-db/*.json` — records compatible with Omega's local `CatalogDatabase` schema 1;
- `sources.json` — source definitions represented by the bundle;
- `catalog-report.json` — validation result for every candidate/source;
- `bundle-manifest.json` — bundle schema and generation time.

Omega 0.7.1.0 can import this file with zero repository traffic when it is present as `omega-catalog-db.zip` either next to the plugin assembly (for a catalog-preloaded release build) or in Omega's plugin configuration directory (for a manually downloaded database). Local records newer than the bundle are preserved.

The catalog builder never installs plugins and never registers all discovered repositories with Dalamud. It only prepares marketplace metadata. Dalamud remains the installation and lifecycle authority.

## Runtime central descriptor

The runner also emits `catalog.json`:

```json
{
  "schema": "omega.catalog.v1",
  "schemaVersion": 1,
  "generatedAtUtc": "...",
  "catalogSha256": "...",
  "bundleSha256": "...",
  "size": 123456,
  "downloadUrl": "https://.../omega-catalog-db.zip"
}
```

Omega normally downloads only this small descriptor. `catalogSha256` is a semantic fingerprint of repository URLs, manifest content hashes, and source definitions, so operational timestamp/ETag-only bundle changes do not force clients to redownload. A matching catalog hash means the locally applied central catalog is current. Only a changed catalog hash causes the ZIP to be downloaded, and `bundleSha256` verifies the exact downloaded bytes. The workflow additionally emits `catalog-endpoint.json`; in the real repository it contains the stable `catalog-latest/catalog.json` URL and is committed so future plugin builds inherit the correct endpoint. If the descriptor or bundle cannot be used, Omega falls back to building the same database from its local source definitions.
