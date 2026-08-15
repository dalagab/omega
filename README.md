# Omega

**Omega** is an open-source visual marketplace for Dalamud plugins, developed by the **Dalagab Group**.

Omega is designed to make plugin discovery easier without replacing Dalamud as the plugin manager. Omega can index official and third-party PluginMaster-compatible repositories, present them through a searchable storefront, show repository provenance and compatibility information, and ask Dalamud to perform plugin installation from the repository selected by the user.

Project site: https://github.com/dalagab/omega

## What Omega provides

- **Spotlight** with five editorial plugin picks, latest additions, and latest updates.
- **Discover** with screenshot-rich Microsoft Store-style cards first, a compact fallback list for metadata-only plugins, full plugin product pages, global search, authors, repositories, categories, and searchable tags.
- **Library** for installed plugins plus Dalamud-owned Collections/profile folders.
- **Updates** for installed plugins where a newer compatible package is available, with a compact numeric notification badge when updates are waiting.
- **Settings** for source visibility, user-added repositories, catalog refresh, and access to the EULA/risk disclosure.
- Official/default Dalamud plugins alongside community repositories.
- Repository-choice installation when the same plugin is available from multiple sources, plus a known-sources popup for provenance/copying.
- One hash-checked SQLite catalog built and enriched online, with the last-known-good local database retained when offline.
- Stale-repository suppression and API compatibility handling.

Omega does **not** replace Dalamud's plugin lifecycle. Installation, updates, and uninstall/removal are delegated to Dalamud; Omega provides the discovery and user-facing control surface.

### Plugin artwork and screenshots

Omega consumes the standard Dalamud manifest fields `IconUrl` and `ImageUrls`. `ImageUrls` is shown as the Screenshots section on the Discover product page, so repository authors do not need an Omega-specific screenshot field. See [`examples/pluginmaster.json`](examples/pluginmaster.json).

The scheduled SQLite catalog workflow may also shallow-index the public project page already declared by a plugin. Standard page descriptions and preview images are cached and added as presentation-only Omega metadata. Listings enriched from a public project page receive a **star**; the star means richer indexed presentation data, not endorsement or security review. When repository variants disagree, Omega uses the single variant with the richest screenshot/description set for presentation while keeping normal Dalamud repository precedence for installation.

## Important third-party plugin warning

Plugins are executable software. Third-party plugins can have extensive access to data available to the game process and to resources available to the Windows user running the game. Plugin use may also place a FINAL FANTASY XIV / Square Enix account at risk, particularly where gameplay is automated.

Omega therefore shows a first-use **End User License Agreement and Third-Party Plugin Risk Disclosure** before the marketplace can be used. The full agreement is stored in [`EULA.md`](EULA.md) and remains available later from **Omega → Settings → View EULA / Risk Disclosure**.

A plugin being discoverable in Omega is **not an endorsement or security certification**.

## Installation

Normal users should install Omega through **Dalamud**, not by copying Omega DLLs or by running an external Omega updater.

The supplied open-source Windows script performs only the one-time repository-registration step. It adds the Omega PluginMaster URL to Dalamud's `ThirdRepoList`. It does **not** install Omega itself.

### 1. Review the installer

The installer source and a function-by-function description are in [`installer/`](installer/README.md).

Default repository URL:

```text
https://raw.githubusercontent.com/dalagab/omega/main/repository/pluginmaster.json
```

Default Dalamud configuration path on Windows:

```text
%APPDATA%\XIVLauncher\dalamudConfig.json
```

The script creates a timestamped backup before changing that file and preserves unrelated settings and repository entries.

### 2. Preview the change

Close FINAL FANTASY XIV and XIVLauncher, then run from the repository/release directory:

```powershell
powershell -ExecutionPolicy Bypass -File .\installer\Install-OmegaRepository.ps1 -WhatIfOnly
```

This prints the config path, repository URL, and planned action without writing anything.

### 3. Register the Omega source

```powershell
powershell -ExecutionPolicy Bypass -File .\installer\Install-OmegaRepository.ps1
```

The script either adds the exact Omega repository entry, enables an existing disabled Omega entry, or reports that the entry is already enabled.

### 4. Install Omega normally through Dalamud

Start XIVLauncher/FINAL FANTASY XIV, open:

```text
/xlplugins
```

Search for **Omega** and choose **Install**. From this point forward, Omega is installed, updated, disabled, and removed through Dalamud like other third-party repository plugins.

The OS-side script is not an Omega updater and is not needed for routine Omega updates.

### Publication note

The repository manifest in [`repository/pluginmaster.json`](repository/pluginmaster.json) expects the stable Dalamud distribution package at the GitHub release tag `omega-latest` as `Omega.zip`. Public installation becomes functional when that release asset and the `main` repository manifest are published together.

### Publishing a new Omega version

[`release.yml`](.github/workflows/release.yml) publishes tagged releases. Push a four-part version tag matching the project metadata, for example `v0.8.3.14`, or manually dispatch the workflow against an existing matching tag. The workflow downloads the current Dalamud development runtime, builds `Omega.sln` in Release mode (including the regression suite), locates the `Dalamud.NET.Sdk` `latest.zip`, verifies required plugin files, publishes it as `Omega.zip`, writes a SHA-256 sidecar, creates/updates the versioned release, refreshes the stable `omega-latest` assets, and creates a GitHub build-provenance attestation.

## Exactly what the installer changes

The installer changes one logical Dalamud setting: the Omega entry in `ThirdRepoList`.

Conceptually:

```json
{
  "ThirdRepoList": [
    {
      "Url": "https://raw.githubusercontent.com/dalagab/omega/main/repository/pluginmaster.json",
      "IsEnabled": true
    }
  ]
}
```

Existing entries are retained. The script parses the complete JSON document, changes only the Omega repository entry, writes a validated temporary JSON file beside the original, and atomically replaces the original after creating a backup.

It does **not**:

- copy Omega DLLs into Dalamud or FINAL FANTASY XIV;
- patch or replace game/launcher executables;
- inject code into a running process;
- create Windows services or scheduled tasks;
- modify registry keys or PATH;
- add firewall rules;
- install a browser extension; or
- install a separate Omega update service.

See [`installer/README.md`](installer/README.md) for every installer function and its read/write scope.

## Removing the repository entry

Uninstall Omega itself through Dalamud first if desired. The optional source-removal script only removes the exact Omega repository entry:

```powershell
powershell -ExecutionPolicy Bypass -File .\installer\Remove-OmegaRepository.ps1
```

It also creates a timestamped backup before writing.

## Building from source

Building Omega requires the Dalamud SDK and the .NET version configured by the repository workflows:

```powershell
dotnet build .\Omega.sln -c Debug
```

Expected debug assembly:

```text
Omega\bin\Debug\DalagabOmega.dll
```

The solution runs the Omega regression suite as part of the build.

## Catalog pipeline

Omega's central catalog workflow is documented in [`catalog/WORKFLOW.md`](catalog/WORKFLOW.md). GitHub Actions builds one `omega-catalog.sqlite` database from repository manifests and incremental website enrichment. The previous database supplies ETag/Last-Modified state and last-known-good website metadata, so unchanged sources can return HTTP 304 and fresh project pages are reused.

**The database is still downloaded and used by Omega.** At runtime Omega first loads the packaged/bootstrap SQLite catalog and the persisted local `omega-catalog.sqlite`. The catalog updater checks the small online descriptor at the `catalog-latest` release, compares the catalog SHA-256, downloads `omega-catalog.sqlite.zip` only when the database changed, verifies the bundle/database hashes and SQLite integrity, atomically replaces the local database, then immediately uses that database for marketplace projection, search, source metadata, filters, Spotlight, Library, and Updates. If the network or validation step fails, the previous local SQLite database stays active. Intermediate JSON files remain catalog-build inputs, not runtime catalog formats.

## Repository security

Omega ships repository security automation alongside the catalog builder:

- **CodeQL** scans C# on `main`, pull requests, and a weekly schedule.
- **Dependency Review** checks new dependency changes in pull requests.
- **OpenSSF Scorecard** publishes supply-chain posture and SARIF results.
- **Dependabot** tracks NuGet and GitHub Actions updates.
- **Release provenance** uses GitHub artifact attestations for the published `Omega.zip`.

Project security automation is maintained in the GitHub repository rather than exposed as developer-oriented in-game settings. Per-plugin static-analysis results are shown on plugin product pages when a scan is available. A configured workflow or a scan with no findings is not a guarantee that Omega or a third-party plugin is vulnerability-free. See [`SECURITY.md`](SECURITY.md) for reporting guidance.

## EULA and risk disclosure

The authoritative agreement shipped with the plugin is [`EULA.md`](EULA.md). On first use Omega requires acceptance after a 15-second reading delay. Acceptance is stored independently of the Omega software version, so normal Omega updates, catalog refreshes, and newly discovered plugins do not force repeated acceptance.

Declining closes Omega without recording acceptance.

## License

Omega source code is licensed under **AGPL-3.0-or-later** as declared by the project. Third-party plugins discovered through Omega remain subject to their own licenses, terms, privacy practices, and developer policies.

FINAL FANTASY XIV, Square Enix, Dalamud, and XIVLauncher are not products of the Dalagab Group. Omega is not an official Square Enix, Dalamud, or XIVLauncher product.

## Release metadata

- Omega version: `0.8.3.14`
- Dalamud API: `15`
- Assembly/internal identity: `DalagabOmega`
- Namespace: `Dalagab.Omega`
- Command: `/omega`

## Plugin security intelligence

The Omega repository includes a separate server-side static-analysis pipeline for third-party plugin artifacts. The scanner is not executed inside the Dalamud plugin. The scheduled [`security-scanner.yml`](.github/workflows/security-scanner.yml) workflow consumes the current SQLite catalog, selects only plugin variants that are new, changed, failed, produced by an older scanner version, or due for periodic revalidation, and scans those artifacts without executing or loading plugin code.

Scanner 1.8.1 records the exact artifact SHA-256, scanner version, scan timestamp, observed capabilities, severity-classified findings, bounded evidence, dependency declarations, managed assembly metadata, IL call-site evidence, hard/soft/optional dependency semantics, catalog dependency resolution, version compatibility, dependency drift history, and optional public GitHub source provenance. Source inspection is reported separately and is not treated as proof that published source corresponds to the downloaded binary. Results are stored in `plugin_security_scans`, `plugin_security_findings`, and `plugin_security_current` inside the same `omega-catalog.sqlite` database consumed by Omega.

Security findings describe capabilities and risk indicators. They are not a malware verdict, and a scan with no findings is not proof that a plugin is safe. Plugin archives are treated as hostile input: the scanner enforces download, archive-entry, uncompressed-size, compression-ratio, and path-traversal limits and never extracts plugin packages into an executable workspace.
