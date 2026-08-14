# Omega

**Omega** is an open-source visual marketplace for Dalamud plugins, developed by the **Dalagab Group**.

Omega is designed to make plugin discovery easier without replacing Dalamud as the plugin manager. Omega can index official and third-party PluginMaster-compatible repositories, present them through a searchable storefront, show repository provenance and compatibility information, and ask Dalamud to perform plugin installation from the repository selected by the user.

Project site: https://github.com/dalagab/omega

## What Omega provides

- **Spotlight** with five editorial plugin picks, latest additions, and latest updates.
- **Discover** with a stable five-column marketplace grid, global search, authors, repositories, categories, and searchable tags.
- **Library** for installed plugins plus Dalamud-owned Collections/profile folders.
- **Updates** for installed plugins where a newer compatible package is available.
- **Settings** for source visibility, user-added repositories, catalog refresh, and access to the EULA/risk disclosure.
- Official/default Dalamud plugins alongside community repositories.
- Repository-choice installation when the same plugin is available from multiple sources.
- A hash-checked downloadable central catalog with local source/cache fallback.
- Stale-repository suppression and API compatibility handling.

Omega does **not** replace Dalamud's plugin lifecycle. Where installation is supported, Omega delegates the final plugin installation to Dalamud.

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

Development builds require the Dalamud SDK and .NET environment used by this project:

```powershell
dotnet build .\Omega.sln -c Debug
```

Expected development assembly:

```text
Omega\bin\Debug\DalagabOmega.dll
```

The solution runs the Omega regression suite as part of the build. Contributor guidance and engineering expectations are documented in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Catalog pipeline

Omega's central catalog workflow is documented in [`catalog/WORKFLOW.md`](catalog/WORKFLOW.md). The client prefers the published hash-checked catalog database and falls back to local/cached repository data when the online database cannot be used.

## EULA and risk disclosure

The authoritative agreement shipped with the plugin is [`EULA.md`](EULA.md). On first use Omega requires acceptance after a 15-second reading delay. Acceptance is stored independently of the Omega software version, so normal Omega updates, catalog refreshes, and newly discovered plugins do not force repeated acceptance.

Declining closes Omega without recording acceptance.

## License

Omega source code is licensed under **AGPL-3.0-or-later**. See [`LICENSE`](LICENSE). Third-party plugins discovered through Omega remain subject to their own licenses, terms, privacy practices, and developer policies.

FINAL FANTASY XIV, Square Enix, Dalamud, and XIVLauncher are not products of the Dalagab Group. Omega is not an official Square Enix, Dalamud, or XIVLauncher product.

## Current source version

- Omega version: `0.7.8.11`
- Dalamud API: `15`
- Assembly/internal identity: `DalagabOmega`
- Namespace: `Dalagab.Omega`
- Command: `/omega`
