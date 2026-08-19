# Omega

Omega is an open-source in-game marketplace for Dalamud plugins, developed by the Dalagab Group. This branch contains the production application source, regression suite, catalog/Sigmascope tooling, source definitions, and release automation. The public website is maintained separately on the `website` branch.

## Security policy

Vulnerability reporting and the retained Sigmascope/security architecture are documented in [`SECURITY.md`](SECURITY.md).

## Build Omega

Omega uses the Dalamud .NET SDK. On a Windows development system with Dalamud installed:

```powershell
dotnet build .\Omega.sln -c Debug
```

Building the solution also builds and runs `Omega.RegressionTests`. ZipRunner is the authoritative project build gate used during Omega development.

The main application project is `Omega/DalagabOmega.csproj`. Required runtime assets such as the application icons, Sigmascope banner, EULA, source definitions, and catalog endpoint are copied by that project or obtained by the release workflow where appropriate.

## Regression testing

The C# regression runner is part of `Omega.sln` and validates application behavior and repository contracts. Repository-side Python regressions can be run with:

```bash
python -m unittest discover -s tools/tests -p 'test_*.py' -v
```

The regression workflow also exercises the catalog and Sigmascope self-tests used by production automation.

## Catalog and Sigmascope

`tools/catalog/` contains catalog discovery, normalization, projection, dependency analysis, source resolution, and Sigmascope collection helpers. `tools/security/` contains Security Evidence v2 validation, publication, migration, audit, and developer-inspection tooling.

The canonical Sigmascope entry points include:

- `tools/catalog/sigmascope.py`
- `tools/catalog/sigmascope_source_followups.py`
- `tools/security/production_sigmascope_v2_pipeline.py`
- `tools/security/local_sigmascope_v2_test.py`

Sigmascope is deterministic/static evidence gathering. It does not use an LLM to scan, score, or decide whether a plugin is trustworthy.

Source feeds and source-resolution overrides live under `sources/`. The client-facing catalog endpoint is defined in `catalog/catalog-endpoint.json`. Generated catalog state is not committed to `main`: the daily/manual catalog workflow publishes a canonical sharded JSON snapshot plus a frozen Definitions snapshot to the dedicated `catalog-data` branch, then compiles the exact `omega-marketplace.sqlite` consumed by Omega. SQLite is therefore a bounded client projection, not the authoritative catalog store.

Sigmascope runs independently every 15 minutes against the active `catalog-data` snapshot. The daily snapshot includes an immutable deterministic queue seed with explicit reasons such as new variant, artifact change, source review, scanner-rule change, periodic revalidation, or manual review. Workers persist bounded lease/retry progress in Security Evidence v2, pin the scanner code to the snapshot's Definitions source commit, use its frozen OSV query/result set, process at most one queue item, and record catalog/Definitions/rule-set/source-commit provenance on the resulting evidence. Continuous scanner runs never publish a new Omega client database; client-visible catalog/Definitions publication is daily unless an operator deliberately runs the catalog workflow manually.

The daily client compiler reapplies the day's frozen Definitions-derived advisory/catalog conclusions to the latest validated evidence without rescanning artifacts. The compiled database therefore carries its own truthful security revision plus the source Security Evidence revision it was built from.

## Omega repository metadata

`.omega/index.json` is intentional production metadata. Omega's enrichment/scraping pipeline can read it when indexing this repository, including the project banner referenced by `OmegaBannerUrl`. It must not be removed as website-only material.

## Release and repository feed

`repository/pluginmaster.template.json` is the release template. The tagged release workflow builds `Omega.zip`, verifies the packaged manifest/version, generates the published PluginMaster from the actual artifact, and publishes immutable versioned release assets before updating the stable feed.

The source-tree `repository/pluginmaster.json` is a release-managed compatibility mirror and should not be manually advanced for ordinary work builds.

## Source layout

- `Omega/` — Dalamud plugin source.
- `Omega.RegressionTests/` — C# regression runner.
- `tools/catalog/` — catalog and source-processing pipeline.
- `tools/security/` — Sigmascope/Security Evidence v2 pipeline.
- `tools/release/` — release metadata generation.
- `tools/tests/` — deterministic Python regression tests.
- `sources/` — known repository feeds and source overrides.
- `repository/` — Dalamud repository publication metadata.
- `.omega/` — scrapeable Omega repository metadata.
- `.github/workflows/` — retained production catalog, Sigmascope, regression, source-intake, and release workflows.

Website HTML, Tailwind/Node tooling, website tests, and the retired external installation scripts intentionally do not live in this production source package.
