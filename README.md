# Omega

**Omega** is an open-source visual marketplace for Dalamud plugins, developed by the **Dalagab Group**.

Omega is designed to make plugin discovery easier without replacing Dalamud as the plugin manager. Omega can index official and third-party PluginMaster-compatible repositories, present them through a searchable storefront, show repository provenance and compatibility information, and ask Dalamud to perform plugin installation from the repository selected by the user.

Project site: https://github.com/dalagab/omega

## What Omega provides

- **Spotlight** with five editorial plugin picks, each using a subdued card tint derived from that plugin's own logo palette, plus neutral latest-additions and latest-updates shelves.
- **Discover** with screenshot-rich Microsoft Store-style cards first, a compact fallback list for metadata-only plugins, full plugin product pages, global search, authors, repositories, categories, and searchable tags.
- **Library** has three explicit views: **All** is a clean filtered list of installed plugins with local install timing, one-click plugin settings when exposed by Dalamud, and user-requested portable configuration ZIP backups written to the operating-system temporary directory; the Library header can import those backups again for an already-installed plugin after validation and confirmation. **Security scan** summarizes the current installed environment from repository/package-specific Omega security results and identifies the exact artifact SHA-256 behind shared mirror results. **Collections** is the Dalamud-owned folder/profile manager, with additive multi-collection membership managed inside each opened folder.
- **Updates** performs selected plugin updates through Dalamud, combines them with periodic Omega application-version checks and durable Definitions-update state, and can assist when a newer release has migrated to another repository by showing the source move before updating. Omega probes the lightweight Definitions descriptor hourly while loaded and emits one native Dalamud notification per newly seen Definitions revision; plugin/app update counts remain separate from the blue Definitions attention marker on the Downloads rail icon.
- **Settings** for source visibility, user-added repositories, catalog refresh, and access to the EULA/risk disclosure.
- Official/default Dalamud plugins alongside community repositories.
- Repository-choice installation when the same plugin is available from multiple sources; when scanned source packages disagree, Omega highlights a worse report in red and explains the difference before installation.
- One hash-checked SQLite catalog built and enriched online, with the last-known-good local database retained when offline.
- Stale-repository suppression and API compatibility handling.

Omega does **not** replace Dalamud's plugin lifecycle. Installation, updates, and uninstall/removal are delegated to Dalamud; Omega provides the discovery and user-facing control surface.

### Plugin artwork and screenshots

Omega consumes the standard Dalamud manifest fields `IconUrl` and `ImageUrls`. `ImageUrls` is shown as the Screenshots section on the Discover product page, and screenshots can be clicked to open a larger in-game viewer, so repository authors do not need an Omega-specific screenshot field. See [`examples/pluginmaster.json`](examples/pluginmaster.json).

The scheduled SQLite catalog workflow may also shallow-index the public project page already declared by a plugin. Standard page descriptions, a bounded README excerpt, and useful project images are cached and added as presentation-only Omega metadata. Discord join/widget banners are classified separately instead of being presented as product artwork, and explicit 18+ markers from declared tags or public project text feed the marketplace content-rating badge/filter. Listings enriched from a public project page receive a **star**; the star means richer indexed presentation data, not endorsement or security review. When repository variants disagree, Omega anchors product metadata and the user-facing security summary to the same preferred package shown in green. Dalamud, Puni.sh, NightmareXIV, and Combat Reborn are stable baseline providers (in that order when more than one publishes the same compatible version); this is a provenance rule, not a security waiver. Mirrors with the same artifact SHA-256 share one canonical security result, while same-version packages with different hashes are called out as artifact deviations. Installation still remains delegated to Dalamud.

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

[`release.yml`](.github/workflows/release.yml) publishes tagged releases. Push a three-part version tag matching the project metadata, for example `v0.8.49`, or manually dispatch the workflow against an existing matching tag. The workflow downloads the current Dalamud runtime, builds `Omega.sln` in Release mode (including the regression suite), locates the `Dalamud.NET.Sdk` `latest.zip`, verifies required plugin files, publishes it as `Omega.zip`, writes a SHA-256 sidecar, creates/updates the versioned release, refreshes the stable `omega-latest` assets, and creates a GitHub build-provenance attestation.

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

### Repository regression gates

Repository automation has its own regression layer. [`regression-tests.yml`](.github/workflows/regression-tests.yml) runs deterministic Python unit tests, static workflow-contract tests, offline catalog/security/v2 handoff fixtures, scanner/v2/legacy-compactor self-tests, and the normal Windows/.NET Omega regression suite on relevant pushes and pull requests.

The catalog, security-v2, legacy compatibility, and release workflows also run the Python regression suite before performing network or publication work. Larger SQLite/hash/v2 validation blocks live in importable tested modules rather than embedded workflow snippets, so the same production validation logic is exercised directly by unit tests.

Run the repository-side suite locally with:

```bash
python -m unittest discover -s tools/tests -p 'test_*.py' -v
```

## Catalog pipeline

Omega's central catalog workflow is documented in [`catalog/WORKFLOW.md`](catalog/WORKFLOW.md). GitHub Actions builds the authoritative catalog/evidence state from repository manifests and incremental website enrichment, then projects the small marketplace SQLite database consumed by Omega. The previous database supplies ETag/Last-Modified state and last-known-good website metadata, so unchanged sources can return HTTP 304 and fresh project pages are reused. PluginMaster ingestion accepts the common community trailing-comma extension while still rejecting other malformed JSON.

Any push to `main` that changes `tools/catalog/**`, source definitions, the bootstrap catalog, or one of the database-pipeline workflow files automatically restarts the chain from the catalog builder. The production security workflow then starts from the last-known-good `security-evidence-v2` snapshot, stages a bounded scanner update, validates/audits it, and only then replaces the v2 snapshot and small client marketplace projection. The old SQLite compactor workflow is manual compatibility-only. This deliberately favors correctness over a shorter partial run: changed processing code is exercised against current state without allowing a failed candidate to replace production.

Community source intake is repository automation rather than a client-side crawler. The **Add a plugin source** issue form accepts public HTTPS PluginMaster feeds; `source-submissions.yml` validates them with the production manifest parser, a bounded response size, a bounded plugin count, and public-network redirect checks. Community submissions may be automatically validated, but only a workflow dispatch or an OWNER/MEMBER/COLLABORATOR-associated event can enter the privileged persistence job. That job revalidates from a fresh checkout before changing `sources/community-sources.json` or `sources/source-overrides.json`. Community-submitted feeds enter Definitions **disabled by default**. When a scanner artifact has no usable `RepoUrl`, Scanner 2.1 can also derive a GitHub repository from the package URL. Remaining public-source gaps are projected into bounded, deduplicated follow-up issues; an approved public GitHub source reply is stored under a stable plugin/source key in `sources/source-overrides.json` and queues a targeted rescan. Numeric SQLite variant IDs are never used as durable override identities.

**Only the small marketplace database is downloaded and used by Omega.** At runtime Omega first loads the packaged/bootstrap SQLite catalog and the persisted local `omega-catalog.sqlite`. The catalog updater checks the small online descriptor at the `catalog-latest` release, compares the catalog SHA-256, downloads `omega-marketplace.sqlite.zip` only when the marketplace database changed, verifies the bundle/database hashes and SQLite integrity, atomically replaces the local database, then immediately uses that database for marketplace projection, search, source metadata, filters, Spotlight, Library, Updates, and current security summaries and bounded dependency summaries. Detailed forensic evidence lives on the repository-side `security-evidence-v2` snapshot branch and is never downloaded by Omega. The archived `security-evidence-latest` SQLite release remains only as the v1 historical/rollback reference. If the network or validation step fails, the previous local SQLite database stays active.

Marketplace artwork uses a separate bounded local SQLite cache, `omega-image-cache.sqlite`, under Omega's plugin configuration directory. Omega stores the encoded PNG/JPEG/WebP/etc. bytes exactly as downloaded, so already-compressed image formats are not inflated into raw pixels on disk. Icons and screenshots therefore survive plugin/game restarts and are decoded locally on subsequent views. Stale entries are served immediately and conditionally revalidated in the background after seven days. The cache is least-recently-used and capped at 256 MiB / 4096 entries, so image caching does not enlarge the published marketplace database or force every user to download every screenshot.

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

- Omega version: `0.8.80`
- Dalamud API: `15`
- Assembly/internal identity: `DalagabOmega`
- Namespace: `Dalagab.Omega`
- Commands: `/omega` and `/omg`
- UI: Spotlight/Discover sit near the top of the left rail; the Omega wordmark has a small red core; security states use Dalamud Font Awesome glyphs plus the geometric automation trefoil.

## Plugin security intelligence

Omega's third-party plugin analysis runs entirely in GitHub Actions. The scanner never executes or loads the plugin code it inspects. [`security-scanner.yml`](.github/workflows/security-scanner.yml) starts from the last-known-good `security-evidence-v2` snapshot, scans only new, changed, stale-scanner, or periodically due variants within a bounded batch, and stages all changes away from the published branch. Failed revalidations retain their previous validated current pointer; a broken candidate cannot replace production.

Scanner 2.5.0 records exact artifact SHA-256 values, source provenance when available, dependencies, managed metadata, IL call sites, reachability, permission candidates, static capability evidence, and resolved NuGet identities recovered from packaged `*.deps.json` files when project lock/assets files are absent. It also derives bounded automation classifications for game UI/menu control, synthetic clicks, targeting, character action execution, world/NPC interaction, teleport/travel, movement/navigation, camera control, inventory/vendor/retainer control, native input injection, and known automation-oriented IPC integrations. These are capability findings, not claims that a runtime branch necessarily executes.

Security enrichment inventories literal HTTP(S) endpoints without contacting them, strips credentials/query strings/fragments before storage, flags hard-coded filesystem paths outside known FFXIV/Dalamud locations when filesystem API evidence is present, compares artifact hashes for the same plugin version across independent sources, and imports exact-version NuGet vulnerability records from OSV. The production pipeline explicitly reports observed/queryable NuGet versions and fails publication if OSV coverage does not query the expected bounded package set.

### Separate marketplace and evidence stores

The production pipeline deliberately separates the client database from detailed evidence:

- **Marketplace database** (`catalog-latest/omega-marketplace.sqlite.zip`) is the only database downloaded by Omega. It contains plugin/source presentation data, current security and automation summaries, bounded plugin-dependency summaries, and semantic revision IDs. It contains no detailed forensic tables.
- **Security Evidence v2** (`security-evidence-v2` branch) is the authoritative detailed scanner state. Per-variant JSON points to content-addressed artifact analyses; ordinary findings/dependencies/permissions/automation remain bounded JSON, while large managed symbols/calls/reachability use compressed JSONL shards. Small NuGet, IPC, dependency-component, advisory, plugin, and artifact indexes support incremental processing without rebuilding one giant evidence database.
- **Archived v1 evidence** (`security-evidence-latest/omega-security-evidence.sqlite.zip`) is retained as the pre-v2 historical/rollback reference. Production scanning no longer downloads, compacts, or republishes it.

Every production run builds a disposable SQLite working projection from current catalog identities plus the small current v2 evidence needed by the existing scanner/projector. Successful new analyses are merged into a staged v2 tree; unchanged content-addressed analyses are reused. The staged tree must pass intrinsic hash/size/record-digest/pointer validation, OSV coverage gates, marketplace validation, and the independent developer audit before `publish_security_evidence_v2.py` can atomically replace the snapshot branch. The marketplace release is updated only after those gates pass.


### Dependency summaries in Definitions

Omega keeps detailed component evidence in the server-side security evidence database, but the in-game **Dependencies** panel deliberately shows only relationships to other plugins. Definitions projects bounded required/optional plugin relationships and IPC integrations; framework assemblies (including Dalamud itself), NuGet packages, bundled assemblies, native libraries and other implementation components are not presented as plugin dependencies. IPC is directional: channels obtained through `GetIpcProvider` are registered as provider observations, while `GetIpcSubscriber` creates a consumer edge. When exactly one current plugin exposes the same exact channel string, Omega connects the consumer to that provider and makes the provider clickable; ambiguous or unresolved channels remain explicit instead of being guessed from naming conventions. Source-assisted analysis additionally classifies each consumed IPC edge as **required**, **feature**, **optional**, or **unknown**, together with a conservative confidence level. A subscriber call alone never proves a mandatory dependency: high-confidence `required` needs startup/fatal/direct-use evidence, while availability guards and feature/configuration gates support feature or optional classifications. The in-game install chooser warns when a high-confidence required provider is missing and can route the user to the provider, but Omega does not silently install inferred dependencies. Detailed component paths, raw relationship evidence, dependency history, full resolution tables, IPC endpoint/registry evidence and advisory records remain server-side and continue to inform security analysis.

The Discover product page also groups every known repository variant into distinct downloadable **Packages & repositories**. Package identity prefers the scanner's artifact SHA-256 when available and otherwise falls back to the package URL; each group lists the repository manifests that reference it, with official Dalamud sources shown first. This makes mirrors and genuinely different package artifacts visible without duplicating binaries in Definitions. Required plugin dependencies also participate in the marketplace risk indicator: if a required dependency (recursively, within a bounded traversal) has UI/character/gameplay automation capability, the dependent plugin receives the automation/radiation status with a tooltip explaining the dependency path. Optional integrations do not automatically escalate the parent plugin.

### Definitions identity and changelog

Every production marketplace database carries three troubleshooting identifiers:

- **Definitions Revision** (`cat-v1-…`) identifies the logical marketplace plus current security state.
- **Security Revision** (`sec-<scanner-version>-…`) identifies the current user-facing normalized static-analysis state.
- **Evidence Revision** (`ev-v2-…`) identifies the detailed content-addressed evidence/index state that produced the security summaries.

These are different from `catalogSha256` and `bundleSha256`, which verify exact transport bytes. Transport scan IDs, scan timestamps, branch commit IDs, and compression representation do not by themselves change semantic revisions. A forensic-evidence/index change can advance Evidence Revision without changing the user-facing Security Revision; a meaningful current finding/capability/dependency change advances Security Revision and therefore Catalog Revision.

The marketplace database keeps the bounded revision/changelog information needed by the client. Scanner freshness lives in the v2 current variant records; no separate giant evidence release or scan-ledger publication is required.

Security findings describe observed static capabilities and risk indicators. They are not a malware verdict, and no findings is not proof that a plugin is safe. Plugin archives are treated as hostile input: downloads, entry counts, total expansion, compression ratio, paths, metadata parsing, graph sizes, and scan time are bounded.

## Release notes

Project release notes are maintained in [`CHANGELOG.md`](CHANGELOG.md). The release workflow extracts the matching version section and publishes it with the immutable GitHub release and `omega-latest`.

Omega product pages can also surface collected usage/command information and plugin changelogs from Definitions, so installation, operation, update context, and security provenance stay in one place.

## Security developer view

Repository developers can inspect the detailed published scanner evidence independently of the in-game client:

```bash
python tools/security/developer_view.py
```

For the production v2 snapshot, check out/download the `security-evidence-v2` branch and run `python tools/security/developer_view.py serve --evidence-v2 /path/to/security-evidence-v2` for the read-only click-through browser. The same tool retains v1 SQLite compatibility for historical comparison, while production automation uses `developer_view.py audit` against its disposable working projection and small marketplace candidate before publication. See [`tools/security/README.md`](tools/security/README.md) for details.
