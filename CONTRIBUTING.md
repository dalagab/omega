# Contributing to Omega

Thanks for helping improve Omega. This repository is the public source tree for the Dalamud plugin and its catalog tooling.

## Build

Omega targets Dalamud API 15 and uses `Dalamud.NET.Sdk/15.0.0`. With a working Dalamud development environment:

```powershell
dotnet build .\Omega.sln -c Debug
```

The solution runs `Omega.RegressionTests` automatically after the build. A change is not considered complete when those tests fail.

## Architecture boundaries

- Dalamud remains responsible for plugin installation, updates, loading, unloading, profiles, and runtime hosting.
- Omega is a discovery/catalog/user-interface layer and must not become a second plugin runtime.
- Repository choice is explicit when multiple sources provide the same plugin.
- Existing user-managed Dalamud repositories must not be silently removed or taken over.
- Network work must not run from the ImGui draw path.
- Catalog discovery belongs in the GitHub Actions catalog pipeline, not inside the game process.
- Internal Dalamud reflection is isolated in bridge classes and must fail closed when an expected internal API is unavailable.

## Source organization

- `Omega/Models/` — marketplace/repository data models.
- `Omega/Services/` — catalog, repository, Dalamud integration, installation coordination, caching, and persistence.
- `Omega/UI/` — marketplace window partials grouped by responsibility.
- `Omega.RegressionTests/` — deterministic regression and architectural guards.
- `tools/catalog/` — offline catalog discovery/build/test tooling used by GitHub Actions.
- `installer/` — transparent one-time repository registration scripts.

## Engineering defaults

- Keep source files focused; the current project target is 400 lines or fewer per C# source file.
- Prefer small functions with one clear responsibility; extract complex ImGui and orchestration logic into named helpers/services.
- Non-trivial services and integration bridges should have concise XML summaries describing what they own.
- Every repaired defect should receive a regression guard when the behavior is deterministic.
- Preserve user-visible installation and repository ownership boundaries when refactoring.

## Catalog changes

The catalog workflow is documented in [`catalog/WORKFLOW.md`](catalog/WORKFLOW.md). Hand-maintained repository pre-seeds belong in [`sources/curated-sources.json`](sources/curated-sources.json). GitHub Actions discovers additional sources, conditionally refreshes manifests using ETag/Last-Modified state from the previous SQLite release, incrementally enriches project pages, and publishes one canonical `omega-catalog.sqlite` database. Generated stage JSON is for inspection/import and is not a runtime catalog format.

## Pull requests

Keep changes scoped, describe user-visible behavior, and include the regression coverage used to protect the change. Do not commit build output, local Dalamud state, credentials, daily generated catalog release databases, or user configuration. The small `catalog/bootstrap/omega-catalog.sqlite.zip` checked into this source tree is intentional: it seeds a first install before the online catalog has been downloaded.
