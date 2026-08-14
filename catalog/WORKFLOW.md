# Omega online catalog workflow

This document is the operator guide for Omega's online catalog generator. It explains what GitHub Actions reads, what it writes, where to add a repository manually, and how the game client consumes the published database.

## Short answer: how to pre-seed a repository

Use `sources/curated-sources.json`.

That file is the **manual/authoritative pre-seed list** for the online catalog builder. A source in this file is evaluated on every catalog build whether GitHub discovery finds it or not. Curated sources are processed before discovered candidates, and URL de-duplication gives the curated definition precedence.

Example:

```json
{
  "id": "aetherlove-aetheros",
  "name": "AetherLove - AetherOS",
  "url": "https://puni.sh/api/repository/aetherlove",
  "description": "AetherLove / AetherOS plugin repository.",
  "isOfficial": false,
  "enabledByDefault": true,
  "integrateWithDalamudByDefault": false
}
```

After editing the file, **commit and push the change to the GitHub repository that runs the workflow**. Then run the `Omega catalog builder` workflow manually or wait for its scheduled run.

## The three different kinds of "seed"

Omega uses three concepts that can look similar but serve different purposes.

### 1. Manual source pre-seed — `sources/curated-sources.json`

Use this when a repository **must** be considered by the builder.

- Hand-maintained source definitions.
- Evaluated before discovered candidates.
- Does not depend on GitHub code search.
- Best place for known repositories, Spotlight dependencies, and sources that live behind non-GitHub repository endpoints such as Puni.sh.
- A source may be temporarily unreachable; if a prior validated record exists, the builder can retain that last-known-good record.

This is the file to edit when you say: "Omega must know about this repository."

### 2. Discovery queue — `catalog/candidates.json`

This is a durable queue of possible repository-index files found by GitHub code search.

- `tools/catalog/discover_sources.py` reads `catalog/search-queries.json`.
- New results are merged into the existing candidate queue.
- Existing candidates are retained when a discovery query fails.
- A candidate is **not trusted** merely because discovery found it. `build_catalog.py` validates it later.

Normally do not hand-edit this file. Change `catalog/search-queries.json` when you want broader or narrower automatic discovery.


### 3. Previous database seed — release asset `catalog-latest/omega-catalog-db.zip`

This seed is about efficiency and resilience, not discovery.

The workflow downloads the previous stable catalog bundle and passes it to `build_catalog.py` as `--seed-bundle`.

It supplies:

- previous ETag and Last-Modified validators for conditional HTTP requests;
- previous validated manifests for last-known-good retention;
- a stable baseline when an upstream source has a transient DNS/timeout/rate-limit/HTTP failure.

It does not add new repository URLs by itself.

## Workflow trigger

File: `.github/workflows/catalog-builder.yml`

The workflow runs:

- on the daily cron schedule (`17 4 * * *`, 04:17 UTC);
- manually through GitHub Actions via `workflow_dispatch`.

The workflow has `contents: write` permission because it commits discovery/validation state and replaces assets on the stable `catalog-latest` release.

Only one catalog-builder run is allowed at a time by the `omega-catalog-builder` concurrency group.

## Step-by-step data flow

### Step 1 — Check out Omega

The workflow checks out the repository with full history (`fetch-depth: 0`).

**Operator input:** none.

### Step 2 — Set up Python

Python 3.13 is installed for the catalog tooling.

**Operator input:** change the Python version here only if the tooling requires it.

### Step 3 — Test the catalog pipeline

Command:

```text
python tools/catalog/test_catalog_pipeline.py
```

The build stops before touching discovery/release state if these regression tests fail.

**Operator input:** update this test suite whenever the catalog data contract changes.

### Step 4 — Discover GitHub repository candidates

Command shape:

```text
python tools/catalog/discover_sources.py \
  --queries catalog/search-queries.json \
  --output catalog/candidates.json \
  --token-env GITHUB_TOKEN \
  --max-pages 10
```

What it does:

1. Reads search strings from `catalog/search-queries.json`.
2. Uses GitHub code search.
3. Keeps JSON-looking results with repository/path information.
4. Builds raw URLs that follow the repository's `HEAD` branch.
5. Merges new results into the existing durable `catalog/candidates.json` queue.
6. Records discovery errors without deleting the old queue.

**Change here when:** automatic discovery misses a class of repositories. Usually edit `catalog/search-queries.json` rather than the Python code.

**Do not rely on this for:** non-GitHub endpoints or a repository that must definitely be included. Put those in `sources/curated-sources.json`.

### Step 5 — Download the previous stable bundle

The workflow tries to download:

```text
catalog-latest / omega-catalog-db.zip
```

into `catalog/seed/`.

Failure is allowed (`|| true`), which means a first-ever build can proceed without a seed.

**Change here when:** the stable release tag or bundle asset name changes.

### Step 6 — Build and validate the catalog database

Command shape:

```text
python tools/catalog/build_catalog.py \
  --curated sources/curated-sources.json \
  --candidates catalog/candidates.json \
  --known-bad catalog/known-bad-hashes.json \
  --out catalog/dist \
  --generated-sources-output catalog/generated-sources.json \
  --report-output catalog/latest-report.json \
  --seed-bundle catalog/seed/omega-catalog-db.zip \
  --download-url <stable release bundle URL> \
  --descriptor-url <stable release descriptor URL> \
  --update-known-bad
```

Important behavior:

1. Loads curated/manual sources first.
2. Loads discovered candidates second.
3. Normalizes URLs and removes duplicates. Because curated entries are first, a curated definition wins for the same URL.
4. Validates sources in a bounded worker pool (default 12, hard-bounded in code).
5. Uses conditional requests when the previous seed has ETag/Last-Modified values.
6. Accepts normal plugin arrays and supported plugin-array wrappers.
7. Requires usable plugin entries with at least `Name` and `InternalName`.
8. Hashes fetched content with SHA-256.
9. Deterministically invalid content can be added to `catalog/known-bad-hashes.json` so identical bad content is skipped next time.
10. DNS failures, timeouts, rate limits and other transient fetch errors are **not** classified as deterministic bad content.
11. When a transient failure happens and the previous bundle contains a valid record for that URL, the old record is retained.
12. Valid discovered sources that are not already curated are written to `catalog/generated-sources.json`.
13. Builds `catalog/dist/omega-catalog-db.zip` and the central descriptor files.

**Change here when:** validation rules, supported repository JSON shapes, retention behavior, bundle format, or concurrency need to change.

### Step 7 — Commit durable discovery/validation state

The workflow commits these generated state files when they changed:

- `catalog/candidates.json`
- `catalog/known-bad-hashes.json`
- `catalog/generated-sources.json`
- `catalog/latest-report.json`
- `catalog/catalog-endpoint.json`

The commit message uses `[skip ci]` to avoid causing a redundant workflow chain.

**Operator note:** `catalog/latest-report.json` is the first file to inspect when a repository is missing from the online database.

### Step 8 — Upload a GitHub Actions artifact

The workflow uploads the built database and reports as a normal Actions artifact for inspection/debugging. This is separate from the release used by Omega clients.

### Step 9 — Publish the stable `catalog-latest` release

The release tag is stable. The workflow creates it once if necessary and then uploads assets using `--clobber`, replacing the previous files in place.

Important published files include:

- `catalog.json` — small runtime descriptor;
- `omega-catalog-db.zip` — prebuilt catalog database;
- `omega-catalog-db.zip.sha256` — bundle checksum;
- `catalog-report.json` — full validation report;
- `sources.json` — source definitions represented by the bundle;
- `generated-sources.json` — automatically discovered valid sources;
- `known-bad-hashes.json` — deterministic invalid-content state;
- `catalog-endpoint.json` — descriptor endpoint metadata.

The package version of the workflow also includes a final `test_live_catalog.py` smoke test after publishing. Keep that step when syncing the packaged workflow back to GitHub; it verifies the same public descriptor/bundle route used by Omega clients.

## What the game client does with the result

At runtime Omega should **not** crawl all repository sources when the online catalog is healthy.

1. Omega loads `catalog/catalog-endpoint.json` (or a config override).
2. It requests the small `catalog.json` descriptor.
3. It compares the descriptor's semantic `catalogSha256` with the catalog it already applied.
4. If the semantic hash is unchanged, no bundle download is needed.
5. If it changed, Omega downloads `omega-catalog-db.zip`.
6. It verifies the exact bundle SHA-256.
7. The validated central bundle replaces the curated catalog database atomically.
8. The live Dalamud official/default source and user-added repositories are then layered over the central catalog where appropriate.
9. If the descriptor/bundle cannot be downloaded or validated, Omega falls back to its local repository/cache path.

The header tells you which path is active:

- `Online catalog` = central database active.
- `Local cache` = central path was unavailable/rejected and Omega is using local fallback.

For a `Local cache` result, check the Dalamud log for one of these messages:

```text
Omega online catalog unavailable; using local repository fallback. Reason: ...
Omega rejected the downloaded central catalog; using local repository fallback.
Omega applied central catalog database; records=...; sources=...; sha256=...
```

## AetherLove specifically

AetherLove should be handled as a curated/manual pre-seed because its repository endpoint is a Puni.sh API URL rather than something that should depend on GitHub code search:

```text
https://puni.sh/api/repository/aetherlove
```

Expected plugin internal name:

```text
AetherLovePlugin
```

To verify it after a workflow run:

1. Open `catalog/latest-report.json`.
2. Search for `https://puni.sh/api/repository/aetherlove`.
3. Confirm the status is `valid` or `not-modified` and the plugin count is at least 1.
4. Confirm the `catalog-latest` release was updated after that run.
5. In Omega, confirm the header says `Online catalog` rather than `Local cache`.

If steps 1-4 pass but step 5 says `Local cache`, the generator is not the missing piece; diagnose the client descriptor/download/import path instead.

## Operator change map

| Goal | Edit | Normally do not edit |
|---|---|---|
| Force a known repository into every build | `sources/curated-sources.json` | `catalog/generated-sources.json` |
| Broaden/narrow automatic discovery | `catalog/search-queries.json` | `catalog/candidates.json` by hand |
| Inspect why a source was accepted/rejected | `catalog/latest-report.json` | — |
| Retry identical content previously marked deterministically bad | carefully remove its entry from `catalog/known-bad-hashes.json` | builder validation code unless rule is wrong |
| Change repository parsing/validation | `tools/catalog/build_catalog.py` + tests | workflow YAML alone |
| Change GitHub discovery mechanics | `tools/catalog/discover_sources.py` + tests | build/import code |
| Change schedule/manual job steps | `.github/workflows/catalog-builder.yml` | runtime plugin code |
| Change published descriptor location | workflow URLs + `catalog/catalog-endpoint.json` | random release assets manually |
| Change client fallback/download behavior | `Omega/Services/OnlineCatalogClient.cs`, `CatalogUpdateCoordinator.cs` | builder discovery code |

## Safe adjustment workflow

When changing the catalog generator:

1. Change the smallest appropriate input/code file.
2. Update `tools/catalog/test_catalog_pipeline.py` for contract changes.
3. Run the pipeline test locally when possible.
4. Commit and push to the GitHub repository that owns the workflow.
5. Trigger `Omega catalog builder` manually.
6. Inspect `catalog/latest-report.json` and the workflow logs.
7. Verify the `catalog-latest` release timestamp/assets changed.
8. Verify Omega reports `Online catalog`.
9. Only then troubleshoot Spotlight/storefront selection if a plugin is still absent.
