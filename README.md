# Omega

**Omega** is a Dalamud API 15 plugin marketplace by the **Dalagab Group**.

It consumes standard Dalamud PluginMaster-compatible repositories and adds richer discovery/filtering, visible API compatibility, installed-state awareness, and an experimental-repository integration layer that can register feeds with Dalamud so Dalamud remains responsible for servicing installed plugins.

## Current build

- Version: `0.7.1.0`
- Build stamp: `omega-online-catalog-with-local-fallback-20260813`
- Dalamud SDK: `Dalamud.NET.Sdk/15.0.0`
- Assembly/internal identity: `DalagabOmega`
- Namespace: `Dalagab.Omega`
- Command: `/omega`

## Build

```powershell
dotnet build .\Omega.sln -c Debug
```

Expected plugin DLL: `Omega\bin\Debug\DalagabOmega.dll`.

See `DESIGN.adoc` and `UI_DESIGN.adoc` for the authoritative behavior/design description.

## Experimental feed endpoint

This build implements the full Omega → Dalamud repository registration path, but intentionally does not ship a fake Dalagab repository URL. Enter a real HTTPS PluginMaster URL in **Repositories → Add experimental repository**; **Register with Dalamud** is enabled by default.





### 0.7.1.0 central catalog + local fallback

Omega now has two catalog acquisition paths that converge into the same file-backed database:

1. **Preferred online database.** Omega checks a tiny `catalog.json` descriptor. If its semantic `catalogSha256` matches the locally applied central database, no database or repository manifests are downloaded. Operational timestamp-only runner changes do not alter this semantic hash. If marketplace data changed, Omega downloads `omega-catalog-db.zip`, verifies size and exact `bundleSha256`, stages/validates every record, preserves user-added repository records, and atomically replaces the curated database snapshot.
2. **Local source fallback.** If the descriptor, bundle, checksum, schema, or database validation fails, Omega conditionally rebuilds the same database from the enabled bundled/local repository list. Existing ETag/Last-Modified repository validation remains the fallback transport.

When the central database is valid and there are no user-added repositories, the update is complete after the descriptor/hash check. Curated repositories are not contacted individually. User-added repositories remain an overlay and may still be checked independently.

`catalog/catalog-endpoint.json` is the packaged endpoint seed. It deliberately starts blank in this source ZIP because no repository URL has been supplied in-chat. The GitHub catalog workflow writes the repository-specific `catalog-latest/catalog.json` URL into this file and commits it, so subsequent builds automatically know their own central catalog endpoint without hard-coding a guessed repository. A config-directory `catalog-endpoint.json` overrides the packaged one.

### 0.7.0.0 GitHub catalog builder + prebuilt database

- Spotlight is fixed to Honse (`HonseFarm.Client`), AetherLove/AetherOS (`AetherLovePlugin`), Allagan Tools (`InventoryTools`), GatherBuddy Reborn (`GatherBuddyReborn`), and Chat 2 (`ChatTwo`). Missing fixed promotions are not replaced by unrelated plugins.
- Added the AetherLove/AetherOS repository to the curated source list.
- Added `.github/workflows/catalog-builder.yml`: a daily/manual GitHub Actions catalog runner.
- The runner maintains `catalog/candidates.json`, seeded from the three supplied discovery batches, and extends it using GitHub code search.
- Successfully fetched candidate content is SHA-256 hashed. `catalog/known-bad-hashes.json` skips deterministic bad content; GitHub blob hashes confirmed by the current discovery run can skip unchanged known-bad files before another download. New deterministic invalid hashes are added automatically. Network/HTTP failures are transient and never poison the bad list.
- Valid repositories are transformed into the same schema-1 per-source records Omega uses locally and published as `omega-catalog-db.zip` with a companion SHA-256 checksum.
- Before each scheduled build, the runner downloads the previous `catalog-latest` database when available. Its saved ETag/Last-Modified values drive conditional requests; unchanged repositories can return 304, and transient/bad upstream responses retain the previous last-known-good manifest in the new database.
- The stable `catalog-latest` GitHub release and Actions artifact expose the generated database, source list, report, generated-source list, and bad-hash list.
- Omega can import `omega-catalog-db.zip` locally from beside the plugin assembly or from its config directory. Importing performs no repository traffic, merges newly discovered source definitions, and never overwrites newer local records.

### 0.6.5.0 Spotlight page + stable API badge coverage

- Spotlight is now a dedicated first/default page with its own `★` sidebar icon instead of an area embedded in Discover.
- Spotlight displays exactly five promoted plugins: HonseFarm.Client, Ktisis, LMeter, AutoVisor, and Sphene; healthy catalog entries fill any temporarily missing promotion so the page remains five-wide.
- Discover no longer contains an inline Spotlight surface.
- Artwork API badges resolve stable `DalamudApiLevel` metadata across every repository variant. If the running API exists among those stable variants, that current API is shown in green; otherwise the highest known stable API is shown in red. A presentation variant without API metadata can no longer hide a stable API known from another source.
- Stable API badges remain green when that stable API matches the running Dalamud API and red otherwise.

### 0.6.4.1 compile repair
Preserve the API15 source-table overload with explicit `ImGuiTableFlags.None`, and do not reintroduce legacy `selectedSourceIndex` state. Build stamp: `omega-spotlight-page-stable-api-badges-20260813`.
