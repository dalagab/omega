# Changelog

Omega follows semantic product versions. Development work stays under **Unreleased** until a GitHub tag is cut; the release workflow then assigns that pending work to the tagged version. Small work-build markers preserve which internal package introduced each change without turning every development package into a release entry.

## [Unreleased]

## [0.9.21] - 2026-08-18

<sub>work build: 0.9.21</sub>
- Repair the GitHub Actions Windows/.NET regression gate by staging and validating `omega-catalog.sqlite.zip` from the authoritative `omega-sqlite-catalog` catalog-builder artifact before `dotnet build`.
- Use the same artifact handoff in the tagged release workflow instead of expecting the full base catalog on `catalog-latest`, which intentionally publishes the small client marketplace projection.
- Add a shared fail-closed bootstrap handoff with fallback across retained successful catalog-builder runs, explicit Actions read permission for repository regressions, and regression coverage for both workflows.
- Keep clean local/ZipRunner source builds independent of generated GitHub artifact bytes while still running the full SQLite bootstrap round-trip whenever CI/release stages the authoritative artifact.

<sub>work build: 0.9.20</sub>
- Keep `site/`, `tools/site/`, Node/Tailwind files, the Pages workflow, and retired installer material out of the production package.
- Make the C# lean-source regression compatible with ZipRunner's overlay deployment: stale files left behind by an older checkout no longer make a correct direct-ZIP production snapshot fail.
- Keep clean-checkout/package absence enforcement in the Python production-release hygiene tests, where filesystem absence is authoritative.

<sub>work build: 0.9.19</sub>
- Restore a lean root `SECURITY.md` as a required production-source document for vulnerability reporting and Sigmascope/security architecture.
- Harden the lean-source regression contract so `README.md`, `SECURITY.md`, `EULA.md`, `CHANGELOG.md`, and `.omega/index.json` are all explicitly retained while website- and installer-only material remains excluded.

<sub>work build: 0.9.18</sub>

- Restore a lean root `README.md` as part of the production source contract; the source branch should remain understandable and buildable without carrying the GitHub Pages site.
- Change lean-source regressions from requiring `README.md` to be absent to requiring a developer-facing README while continuing to reject website/installer-only material.

<sub>work build: 0.9.17</sub>

- Restore `.omega/index.json` and its referenced `images/omega-banner.png`; this metadata is part of Omega's repository-enrichment/scraping contract, not website-only presentation material.
- Restore `.omega/**` and `images/omega-banner.png` as catalog/regression workflow triggers so changes to Omega's own scrapeable metadata rebuild and validate the catalog.
- Strengthen lean-production regressions so `.omega` metadata can never again be classified as removable website material.

<sub>work build: 0.9.16</sub>

- Reduce the production source package to the Omega application, regression suite, catalog/Sigmascope pipeline, source definitions, release automation, runtime assets, and required EULA/release metadata.
- Move website-only sources/tests/tooling out of the main production source package and remove the retired external installer plus unrelated repository-analysis workflows from this build tree.
- Include `catalog/catalog-endpoint.json` directly so a clean source extraction can compile Omega without relying on a pre-existing ZipRunner overlay checkout.


<sub>work build: 0.9.15</sub>

- Treat a 404 from the not-yet-initialized `omega-latest/pluginmaster.json` asset as a normal pre-release bootstrap state instead of an Omega update-check failure.
- Defer the silent legacy-repository migration without warning while that canonical stable feed has not yet been published.

<sub>work build: 0.9.14</sub>

- Isolate GitHub Pages publication to the dedicated `website` branch; pushes or manual dispatches from `main` no longer deploy the public site.

### Windows regression contract synchronization

- Synchronize the hourly Definitions probe regression guard with the renamed unmanaged-Dalamud source refresh gate introduced by the unified local repository model.
- Update the Settings source-table regression guard for the current unmanaged-source footer argument without changing the tested fixed-tab/self-scrolling layout.
- Replace the obsolete My-Sources-era Settings wording assertion with explicit guards for the separate online Omega Definitions and local Dalamud repository explanations.
- Keep the release-managed legacy `repository/pluginmaster.json` pinned to the published last-known-good release; ordinary work-build metadata advances independently.

<sub>work build: 0.9.12</sub>

### Single Dalamud installation path

- Remove the PowerShell helper from the public website installation flow and present one supported installation method: add Omega's canonical PluginMaster URL in Dalamud's Custom Plugin Repositories, then install through `/xlplugins`.
- Remove installer-script FAQs and public README installation instructions so the website and repository landing documentation no longer advertise competing installation paths.
- Keep the existing installer utilities in the source tree only as legacy/recovery tooling; they are no longer presented as the normal user installation path.

<sub>work build: 0.9.11</sub>

### Silent Omega repository servicing migration

- Validate the generated `omega-latest/pluginmaster.json` feed before changing any local repository state, including plugin identity, non-regressing version, and immutable versioned `Omega.zip` linkage.
- Stage only Omega's exact historical raw-`main` PluginMaster migration through Dalamud's live `ThirdRepoList`: add the canonical stable feed alongside the legacy row with the same enabled state, rather than orphaning an installed plugin by replacing its servicing URL too early.
- Retarget the running Omega `LocalPlugin.Manifest.InstalledFromUrl` in memory because Dalamud filters third-party updates by that exact source URL; retain the legacy row across restarts until a normal Dalamud update has persisted canonical provenance, then remove it automatically on a later launch.
- Never edit installed plugin files or `dalamudConfig.json` directly, recover a missing legacy row when a prior in-place migration left canonical configuration but legacy installed provenance, and roll back repository/provenance state if Dalamud's own repository refresh fails.

<sub>work build: 0.9.10</sub>

### Atomic generated Dalamud release feed

- Generate the public PluginMaster from the packaged `DalagabOmega.json` during the tagged release instead of requiring development `main` to carry the next release version in advance.
- Point generated install/update URLs at the immutable tagged `vX.Y.Z/Omega.zip`, publish that package first without permitting tagged asset replacement, re-download and verify it, then publish the stable `omega-latest/pluginmaster.json` feed.
- Keep `repository/pluginmaster.json` as a release-workflow-managed legacy compatibility mirror and stop advancing it in ordinary work builds, preventing `main` edits from advertising an unpublished package version.
- Move new installations and Omega's self-update probe to the stable release-manifest URL while retaining the legacy raw-`main` feed for existing Dalamud registrations.
- Serialize stable release publication across tags so two releases cannot race while updating the shared `omega-latest` endpoint.
- Include Omega's own generated stable feed in the curated online source inventory and queue a Definitions rebuild after publication so Omega can index its newly released version like any other plugin.

<sub>work build: 0.9.9</sub>

### Dalamud-owned local repository model

- Remove the duplicate My Sources settings list: online Omega sources remain in the Omega list, while local repositories remain in the separate Dalamud list.
- Add Source now registers the PluginMaster feed directly with Dalamud; Omega observes unknown feeds as blue unmanaged local overlays instead of owning a second repository entry.
- Hide repository rows that have neither discovered plugins nor API metadata, and offer a GitHub source-submission link for unmanaged Dalamud feeds missing from online Definitions.

### Original-source provenance and automated source intake

- Upgrade Sigmascope to 2.6.0 and derive original public source repositories from `RepoUrl`, resolved/download package URLs, GitHub raw/release/tree/blob forms, and persisted source overrides instead of treating each distribution feed as the source-code identity.
- Inspect the downloaded plugin manifest first and prefer exact `AssemblyVersion` / `vAssemblyVersion` Git refs before mutable branch refs; record source identity, version, repository-origin and selected-ref provenance without claiming reproducible source-to-binary verification.
- Share a successfully resolved source association across mirrors only when the plugin identity and exact artifact SHA-256 match, while keeping historical scan rows immutable and leaving `sourceToBinaryVerified` false.
- Do not open missing-source issues when current metadata can already resolve a source candidate; automatically close existing Omega source-followup issues after Sigmascope has successfully inspected the source.
- Automatically validate, scrape and persist public PluginMaster feeds submitted through the source-submission issue workflow, disabled by default, then queue the catalog builder. Validate source-repository replies on Omega-managed follow-up issues against the plugin identity before persisting an override and queueing a targeted Sigmascope rescan.
- Preserve dependency/advisory/risk projections per repository variant when identical artifact bytes are canonicalized, preventing a stale mirror with zero OSV matches from erasing a known advisory in another variant.

<sub>work build: 0.9.7</sub>

### Dalamud repository usage and safe removal

- Show how many currently installed plugins came from each repository in Settings > Repositories > Dalamud, using Dalamud's persisted `InstalledFromUrl` provenance rather than Omega catalog guesses.
- Add a repository Remove action for configured Dalamud repositories. Removal is available only when no installed plugin currently points at that repository; installed plugins block removal even when disabled so their update/service source cannot be orphaned.
- Re-check repository usage inside the Dalamud bridge immediately before removal, so a stale UI count cannot race a plugin install.
- Explain blocked removal with the installed plugin count and plugin names, while preserving the repository as an Omega source definition when only its Dalamud registration is removed.

<sub>work build: 0.9.6</sub>

### Installability, repository risk review, and Settings structure

- Stop treating a disabled Omega source as inherently uninstallable: explicit repository selection may use disabled or not-yet-local HTTPS sources and the install coordinator prepares them through Dalamud.
- Explain every unavailable install action with the concrete reason: missing package URL, testing-only package, newer Dalamud requirement, invalid source URL, or unsupported API generation.
- Replace the incomplete untrusted-source jump to Settings with an install-specific repository-risk review that preserves the selected plugin/source, shows repository URL/package/API/divergence evidence, and requires an explicit acknowledgement checkbox before the source can be used.
- Correct Library collection hover text to point to Library > Collections instead of referring to an unrelated location below the current row.
- Split Settings into General, Repositories, and Legal tabs; keep the modal chrome/tabs fixed and give the repository table its own vertical scrolling with a frozen header so the close cross never scrolls away.

<sub>work build: 0.9.5</sub>

### Card ribbon compile and overlap correction

- Repair the Discover rich-card card-bound refactor so the Windows/Dalamud build no longer has missing card-bound arguments or shadowed `cardMin`/`cardMax` locals.
- Keep ownership + collection side-by-side at the card top-left and Sigmascope + automation side-by-side at the card top-right, with the artwork child used only for front-most compositing.
- Remove the 0.9.4 blank top strip: artwork returns to its normal position and may be overlapped slightly by card ribbons, preserving icon space on horizontal rows.
- Add a restrained vertical velvet-like shade to ribbon colours without changing their semantic status hues.
- Add a source regression guard for the Discover card-bound ownership mistake that caused the 0.9.4 compile failure.

<sub>work build: 0.9.4</sub>

### Card-top ribbon anchoring correction

- Anchor ownership and collection ribbons to the card's top-left corner, side-by-side horizontally.
- Anchor Sigmascope and automation ribbons to the card's top-right corner, side-by-side horizontally.
- Keep ribbon coordinates completely independent from the plugin icon/logo; the artwork child is used only as the draw layer so ribbons composite above nested artwork rather than behind it.
- Expand the artwork-child clip rectangle to the card bounds while drawing ribbons, then restore it immediately, preventing the card-top flags from being clipped to the icon.
- Reserve a small card-top strip before drawing plugin artwork so horizontal and Spotlight icons remain readable instead of sitting underneath the ribbons.
- Add regression guards that reject artwork-relative X coordinates and vertical ribbon stacking.

<sub>work build: 0.9.3</sub>

### Ribbon layering and panel hierarchy correction

- Restore the intended ribbon semantics: installed/collection state stays on the left side of plugin artwork, while Sigmascope/automation stays on the right side.
- Composite listing ribbons inside the artwork child after the plugin image so every ribbon is genuinely above the icon instead of being hidden behind the child-window draw layer.
- Keep the robot/question glyphs centered against the complete flag shape and stack multiple ribbons vertically on their own side so left/right states never collide on compact artwork.
- Draw panel-local Filters before page headings, Library tabs/actions, and Updates content whenever Filters are available.
- Reduce the Omega application-update notice corner radius so it reads as a compact notification panel instead of a rounded card.

<sub>work build: 0.9.2</sub>

### Compact artwork status flags

- Replace the oversized Sigmascope/automation artwork ribbons with compact flags inset inside the plugin icon's upper-left corner.
- Keep paired Sigmascope + automation flags within compact-list artwork width, with a small fixed gap and no card-edge anchoring.
- Center the status glyph against the complete compact flag shape rather than the rectangular ribbon body.
- Keep installed/collection ownership ribbons and the bare update glyph as separate card-level states.

<sub>work build: 0.9.1</sub>

### About database size and artwork-anchored status ribbons

- Show the loaded Omega Definitions SQLite size immediately after the Definitions revision in About, using human-readable KiB/MiB/GiB units with the exact byte count available on hover.
- Anchor Sigmascope and automation ribbons to the actual plugin artwork rectangle instead of the card's top-right edge, so the status flags sit on the plugin icon consistently in Discover, Spotlight, and recency shelves.
- Center ribbon glyphs against the rectangular flag body and add small scale-aware optical corrections for the Font Awesome Robot and Question glyphs.

<sub>work build: 0.9.0</sub>

### Online Sigmascope Developer View

- Make the published `security-evidence-v2` branch the default Developer View source. `python tools/security/developer_view.py` now reads the atomic root over raw GitHub instead of cloning the branch or downloading the complete evidence database.
- Add a bounded revision-scoped HTTP cache (128 MiB by default), hash verification for indexed/sharded files, and a 60-second Evidence Revision check with an explicit **New evidence · Refresh** control.
- Load plugin variant descriptors, manifests, findings, dependencies, IPC, permissions, automation, and managed-call shards only when the operator opens them. Keep local `--evidence-v2` and explicit SQLite modes for unpublished/debug and historical workflows.
- Enrich the published `indexes/plugins.json` with a small identity/current-conclusion summary plus each variant descriptor SHA-256. This lets the online browser render and filter the full plugin list from the root/plugin indexes without fetching every variant descriptor.
- Extend intrinsic Evidence v2 validation to verify the optional descriptor hash and summary projection when present, while remaining backward-compatible with older published v2 indexes.

<sub>work build: 0.8.99</sub>

### Windows regression contract synchronization

- Update the C# Sigmascope regression to follow the 0.8.98 authoritative handoff architecture: the workflow delegates catalog selection to `tools/security/sigmascope_handoff.py`, and that helper owns the exact `omega-sqlite-catalog` artifact download.
- Add a Python preflight guard so the stale inline `--name omega-sqlite-catalog` workflow assertion cannot return.
- No production Sigmascope handoff or scanning behavior changed in this work build.

<sub>work build: 0.8.98</sub>

### Sigmascope workflow handoff resilience

- Resolve Sigmascope input from authoritative `omega-sqlite-catalog` artifacts produced by successful `Omega SQLite catalog builder` runs for **all** invocation modes. Scheduled/manual runs no longer depend on an already-published `catalog-latest` marketplace bundle.
- For `workflow_run` triggers, prefer the exact triggering builder artifact, then fall back to the newest successful builder artifact if that run's artifact is unavailable.
- Always write bounded `sigmascope-handoff-diagnostics.json` during the handoff step, recording event/run selection, attempted GitHub CLI commands, bounded stdout/stderr and observed files. The always-run diagnostics upload now has a real artifact even when catalog handoff fails before Sigmascope staging begins.
- Print a bounded summary of independent developer-audit failures directly into the GitHub Actions log before failing, while retaining the complete JSON audit in the diagnostics artifact.
- Retain the 0.8.97 client compatibility fix for `ev-v1-…` and `ev-v2-…` Definitions Evidence Revisions.

<sub>work build: 0.8.97</sub>

### Definitions Evidence v2 compatibility

- Accept both legacy `ev-v1-…` and Sigmascope `ev-v2-…` semantic Evidence Revision identifiers in the in-game Definitions client. The 0.8.96 client rejected valid Sigmascope descriptors because it still recognized only the older revision generation.
- Keep malformed and unknown Evidence Revision generations fail-closed; `ev-v3-…` remains rejected.
- Align catalog publication/validation helpers with the same v1/v2 compatibility contract so maintenance tooling does not reject a valid Sigmascope Evidence v2 descriptor.

<sub>work build: 0.8.96</sub>

### Sigmascope independent audit repair

- The live 0.8.95 Sigmascope run proves the 32 MiB transport repair works: Evidence v2 candidate validation and the small marketplace validation both pass.
- Repair historical Evidence v2 rows whose stored severity/count summary drifted from their normalized findings when the published snapshot is materialized into the disposable working database.
- Let bounded transport summaries fall back to the non-empty legacy report conclusion when an older row contains the known zero/`none` stale-summary shape.
- Audit immutable scan evidence separately from the intentionally derived current marketplace projection, so canonicalized or provenance-derived current findings do not falsely mutate the original scan record.
- Match the independent canonical-artifact audit to production identity semantics by grouping plugin identity, assembly version, artifact hash and scanner generation together.
- Keep the 32 MiB per-file publication ceiling unchanged and fail-closed.

<sub>work build: 0.8.95</sub>

### Sigmascope Evidence v2 publication repair

- Keep the 32 MiB per-file publication ceiling fail-closed; do not solve the live GitHub Action failure by raising the safety limit.
- Stop duplicating Sigmascope's full legacy `report_json` inside both the current and scan objects of every Evidence v2 variant descriptor. Detailed findings, dependencies, managed symbols, calls, reachability and other forensic records remain in their normalized content-addressed Evidence v2 datasets.
- Replace the legacy report copy with a deterministic bounded transport summary containing only compatibility state still needed by incremental rescans, source follow-ups and legacy marketplace projection.
- During every candidate synchronization, compact legacy oversized descriptors for **all active variants**, not only variants examined in the current batch. This lets the next successful Sigmascope run repair the already-published oversized Evidence v2 population in one pass.
- Add regression fixtures that reproduce the live failure with a descriptor exceeding 32 MiB and prove both fresh migration and legacy candidate synchronization reduce it below 1 MiB without losing source fingerprints needed for incremental scanning.

### GitHub Actions identity

- Keep `.github/workflows/sigmascope.yml` as the only canonical scanner workflow and `Omega Sigmascope` as the visible Actions name. The retired `security-scanner.yml` is intentionally absent from production source, so the next source publication removes the old workflow file while preserving its historical runs in GitHub.

<sub>work build: 0.8.94</sub>

### About information hierarchy

- Simplify the Omega identity hero: keep the publisher and product tagline, remove the duplicated inline version and the redundant marketplace-description sentence.
- Move the Definitions explanation beneath the Sigmascope banner, where the relationship between the online scanner, its collected results, and Omega Definitions is explained in short player-facing language.
- Remove implementation-oriented Sigmascope copy from About and shorten the lower feature bullets so the modal focuses on what an average player needs to know.

<sub>work build: 0.8.93</sub>

### Release-note staging

- Keep development changelog entries versionless under `Unreleased` instead of creating a release heading for every ZipRunner/source package.
- When a GitHub version tag is cut, release-note extraction uses the exact version section when one already exists and otherwise consumes the complete `Unreleased` block.
- Add a safe changelog finalizer for tag workflows: when the tagged commit is still the default-branch tip, the pending block is rolled into the tagged version and a fresh `Unreleased` section is opened.

### Repository presentation metadata

- Add the extensible `.omega/index.json` repository metadata file. `OmegaBannerUrl` is the first supported presentation key; unknown future keys remain preserved in server-side enrichment metadata so the format can grow without replacing the file.
- Resolve `.omega/index.json` from public GitHub source repositories during Definitions enrichment, cache it with website metadata, project `OmegaBannerUrl` into the client SQLite database, and retain backward compatibility with older Definitions that do not yet expose the column.
- Product detail pages use `OmegaBannerUrl` as a subtle, wide background behind the existing translucent hero panel. Banners are lazily downloaded through Omega's bounded persistent artwork cache.
- Add Omega's own `.omega/index.json` plus the supplied wide Omega marketplace banner as the reference implementation.

### Sigmascope identity

- Add the supplied Sigmascope V2.0 banner to About. The existing Omega identity and Definitions block remain fixed; Sigmascope appears at the start of the scrollable explanatory area with its evidence-oriented description.

### Availability

- This work adds presentation metadata and release-process behavior only. Plugin lifecycle operations remain delegated to Dalamud, and Sigmascope analysis semantics/evidence schemas are unchanged.

## [0.8.92] - 2026-08-17

### Card overlay alignment

- Move the automation ribbon to the top-right status stack beside the Sigmascope ribbon, keeping installed and collection ownership ribbons together on the left.
- Inset the left ownership ribbon stack by 8 logical pixels so the first ribbon is not clipped by rounded card boundaries at high UI scale.
- Simplify the card-level update indicator to the yellow sync glyph only: remove the circular background/border and align the bare icon to a consistent bottom-right inset.

### Availability

- 0.8.92 changes listing-card overlay placement/presentation only. Sigmascope semantics, evidence schemas, catalog behavior, website source, install/update authority, and ZipRunner overlay tombstones remain unchanged.

## [0.8.91] - 2026-08-17

### Release gate repair

- Synchronize the two remaining hidden source-text assertions in the marketplace chrome regression. The 0.8.90 Windows run compiled both projects and reached 71/72; the failing test stopped at its first stale assertion, masking a second stale assertion later in the same method.
- Preserve the scale-aware implementation unchanged: legacy collapsed geometry is detected with `expandedWindowSize.Y > Ui(96f)`, and repaired geometry restores the responsive `preferredPhysical` size derived from `ResponsiveDefaultWindowLogicalSize() * OmegaUiScale`.
- Extend the Python Windows-regression preflight to require both responsive geometry contracts and explicitly reject the two retired fixed-scale literals.

### Availability

- 0.8.91 contains no runtime behavior change beyond 0.8.90. Sigmascope behavior, evidence schemas, marketplace behavior, website source, and ZipRunner overlay tombstones remain unchanged.

## [0.8.90] - 2026-08-17

### Release gate repair

- Synchronize the final stale Windows C# source-text regression contract exposed by the 0.8.89 ZipRunner run, which compiled both projects and reached 71/72 regressions.
- The inline Filters child panel already used the correct scale-aware `ImGuiStyleVar.ChildRounding, Ui(4f)` implementation; only the regression assertion still expected the pre-scale `4f` literal.
- Extend the Python Windows-regression preflight with this final contract so the non-Windows package gate covers every stale literal surfaced by the 0.8.87–0.8.89 Windows runs.

### Availability

- 0.8.90 contains no runtime behavior change beyond 0.8.89. Sigmascope behavior, evidence schemas, marketplace behavior, website source, and ZipRunner overlay tombstones remain unchanged.

## [0.8.89] - 2026-08-17

### Release gate repair

- Synchronize the final four stale C# source-text regression contracts exposed by the 0.8.88 ZipRunner run. The runtime and regression projects both compiled successfully and 68/72 regressions passed; the four failures still expected pre-scale literals for sidebar spacing, inline-filter sizing, About positioning, and the fallback Discover hover outline.
- Keep the stronger responsive implementations unchanged: `ImGui.Dummy(Ui(0f, 6f))`, row-derived `CalculateInlineFilterPanelHeight()`, `var leftInset = Ui(12f)`, and `rowMax - Ui(0.5f, 0.5f)`.
- Extend the Python Windows-regression preflight to cover these four contracts so the non-Windows package gate now mirrors all source literals exposed by the 0.8.88 Windows run.

### Availability

- 0.8.89 contains no runtime behavior change beyond 0.8.88. Sigmascope behavior, evidence schemas, marketplace behavior, website source, and the ZipRunner overlay tombstones remain unchanged.

## [0.8.88] - 2026-08-17

### Release gate repair

- Synchronize nine stale C# source-text regression contracts with the responsive `Ui(...)` geometry and canonical Sigmascope production-report name already present in the runtime/workflow implementation. These assertions were the remaining 10/72 ZipRunner regression failures after both C# projects compiled successfully in 0.8.87.
- Restore the constructor-size regression to its actual two-stage contract: `MarketplaceWindow` starts from the baseline default minimum, while `PreDraw` applies `ResponsiveMinimumWindowLogicalSize()` for the current viewport and Dalamud scale.
- Finish one real Sigmascope wording cutover left in Library: identical package hashes now say `Sigmascope evidence shared by ...` instead of the legacy `scan shared by ...`.
- Add a Python preflight contract covering the ten Windows regression literals so future responsive/branding source changes cannot leave the C# regression suite stale without being detected before packaging.

### Availability

- 0.8.88 changes no marketplace behavior, security-analysis semantics, evidence schema, or website content beyond the Library wording correction above. The 0.8.86 ZipRunner overlay tombstones remain intact.

## [0.8.87] - 2026-08-17

### Fixed

- Correct the Spotlight high-scale C# regression assertion to use the declared `shelves` source variable. The 0.8.86 runtime project compiled successfully in ZipRunner, but `Omega.RegressionTests` failed with CS0103 because the assertion referenced the nonexistent identifier `spotlightShelves`.
- Add a Python source-contract guard so the Spotlight shelf regression binding cannot silently drift to an undeclared variable again before the Windows/Dalamud compile gate.

### Availability

- 0.8.87 contains no runtime behavior change beyond 0.8.86. Sigmascope behavior, evidence schemas, marketplace functionality, website source, and overlay tombstones remain unchanged.

## [0.8.86] - 2026-08-17

### ZipRunner overlay repair

- Add compatibility tombstones at the retired `MarketplaceWindow.PluginSecurity.cs` and `MarketplaceWindow.LibrarySecurity.cs` paths. ZipRunner 1.2.304.4 overlays package files onto the existing Omega workspace; 0.8.85 omitted those renamed files, so the pre-Sigmascope partial-class implementations remained beside the new Sigmascope files and produced eleven `CS0111` duplicate-member errors.
- Keep `MarketplaceWindow.Sigmascope.cs` and `MarketplaceWindow.LibrarySigmascope.cs` as the canonical implementations. The tombstones contain no runtime behavior and exist only to make cumulative/overlay installation converge on the same compilable source state as a clean extraction.
- No Sigmascope analysis semantics, evidence schema, marketplace behavior, or website content changes in this repair.

## [0.8.85] - 2026-08-17

### Sigmascope

- Canonicalize Omega's evidence-gathering analysis engine as **Sigmascope**, a small twist on *Sigmascape*: Omega's data-driven test world for studying unexpected results and gathering evidence. A scope examines closely, matching the engine's purpose without implying a final trust judgement.
- Rename the production workflow, canonical Python entry points, in-game Library/product presentation, ribbon/status language, and Security Developer View identity to Sigmascope. Historical Python command paths remain compatibility shims, while persisted `scanner_version` fields remain stable evidence/database contracts.
- Add first-class Sigmascope engine name/version metadata to Security Evidence v2 analysis manifests and root indexes while retaining legacy scanner-version metadata for readers of older evidence.
- Keep findings explicitly evidence-oriented: Sigmascope reports what Omega observed in package/public-source analysis and does not present a final trust verdict.
- Website source is intentionally unchanged in this release; public-site Sigmascope rebranding is deferred.

### Release gate repair

- Repair the 0.8.84 C# high-scale regression contracts so ZipRunner checks the responsive `Ui(...)` geometry introduced by the 175–200% layout repair instead of stale fixed-pixel literals.
- Correct the Spotlight wrap regression to inspect the responsive shelf implementation where the column layout is actually calculated.

### Availability

- Sigmascope is the canonical engine name from 0.8.85 onward. Compatibility aliases and historical evidence field names are retained only to avoid breaking existing tools, databases, and published evidence.

## [0.8.84] - 2026-08-17

### Fixed

- Make Omega's marketplace geometry follow Dalamud's global UI scale instead of mixing scaled fonts with fixed-pixel cards, rows, controls, ribbons, artwork, and modal dimensions. The supported layout range is explicitly bounded through 225%, covering 175% and 200% configurations.
- Keep the expanded window usable at high scale by deriving logical default/minimum sizes from the current viewport. Existing persisted oversized geometry is automatically reduced only when it no longer fits comfortably on the current display.
- Make Discover responsive: rich-card columns reduce automatically as usable width shrinks, compact rows and artwork spacing scale consistently, and the ribbon/status overlay remains layout-neutral.
- Make Spotlight shelves responsive so promoted and recency cards wrap into fewer columns rather than forcing a five-card row beyond the available content width.
- Make the inline filter panel responsive: filter controls and filter actions reflow into fewer columns at high UI scale instead of overlapping or extending outside the panel.
- Scale the sidebar, application bar, collection/library rows, product page, repository chooser, security panels, artwork overlays, source management, and shared modal chrome from a single Omega UI-scale helper.
- Cap secondary modal sizes to the current viewport so Settings, EULA, install/update dialogs, repository review, source panels, screenshot viewing, and other secondary windows remain reachable at high scale.
- Repair the C# ribbon regression strings so the Windows/ZipRunner compile gate can execute those presentation assertions instead of encountering malformed nested quote literals.

### Availability

- 0.8.84 is a UI/layout-only release on top of the 0.8.83 ribbon presentation and 0.8.82 Security Evidence v2 repairs. No marketplace database, scanner schema, evidence format, or publication-gate semantics change.

## [0.8.83] - 2026-08-17

### Changed

- Replace Discover and Spotlight's floating top-right star/down-arrow/security icon cluster with a shared ribbon language. The top-right ribbon color now communicates security posture: blue for informational, gold for no findings, yellow for low, orange for medium, and red for high/critical.
- Make the top-right ribbon glyph communicate source/index status independently from security color: a lock means public source was unavailable/closed, a white star means public source was indexed by Omega, and an indexed plugin that is behind the current Dalamud API receives a red star. Unscanned/incomplete packages use a neutral question ribbon instead of pretending a source/security conclusion exists.
- Add left-edge state ribbons in a stable order: installed is green with a white check, named Dalamud collection membership uses a folder ribbon, and detected direct/required-dependency automation uses an Omega cyan/blue robot ribbon.
- Show a Sync/update indicator at the bottom-right of a plugin panel whenever Omega resolves a compatible update for the installed version.
- Keep ribbon overlays layout-neutral: artwork/text geometry does not shift when installed, collected, automated, outdated, or update state changes. Discover no longer renders the old circular installed check over the plugin artwork.
- Apply the same ribbon semantics to Discover rich cards, Discover compact rows, Spotlight promoted cards, and Spotlight recency shelves.

### Availability

- 0.8.83 is a UI-only marketplace presentation release on top of the 0.8.82 Security Evidence v2 publication and Windows release-gate repairs. No scanner/evidence schema or publication-gate behavior is changed by this release.

## [0.8.82] - 2026-08-17

### Fixed

- Keep Security Evidence v2 variant records lightweight by moving current dependency resolutions, dependency issues, and advisory-match projections into bounded `derived/variants/...` record datasets. Small projections remain readable JSON; large projections are deterministically chunked as compressed JSONL with the existing 32 MiB hard publication ceiling.
- Extend intrinsic v2 validation to verify every derived dataset file hash, size, record count, and semantic record digest, and reject orphan derived files. The failed 0.8.81 production candidate can therefore be rebuilt without weakening the publication limit.
- Update the one-time/local v1-to-v2 migration and parity validator to use the same bounded derived-evidence representation while remaining backward-compatible with the already-published inline-derived baseline.
- Close SQLite test connections explicitly with `contextlib.closing()` in the Security Evidence v2 regression fixtures. Python's SQLite context manager does not close the connection, which caused Windows release runners to retain temporary `.sqlite` handles and fail cleanup with `WinError 32`.
- Add regressions for Windows-safe v2 SQLite lifecycle and compressed derived-evidence sharding.
- Ignore root `.staging/` and `artifacts/` working directories so local/security publication scratch output cannot be committed accidentally.

### Availability

- 0.8.82 supersedes the failed 0.8.81 GitHub release attempt. The current validated `security-evidence-v2` snapshot remains the last-known-good production state until a fully staged 0.8.82 scanner candidate passes every publication gate.

## [0.8.81] - 2026-08-17

### Fixed

- Make `catalog/security-v2-work/production-security-v2-report.json` an explicit named path in the security workflow diagnostics artifact. The report was already included by the broader `*.json` upload, but the release regression contract intentionally requires an explicit path so future diagnostics cleanup cannot silently stop retaining the per-batch production summary.
- Restore the C# production security release gate that verifies every bounded Security Evidence v2 run keeps an auditable production summary. No scanner semantics, evidence schema, marketplace projection, or publication behavior changed from 0.8.80.

### Availability

- 0.8.81 supersedes the failed 0.8.80 ZipRunner candidate. The production Security Evidence v2 cutover remains otherwise unchanged.

## [0.8.80] - 2026-08-17

### Added

- Promote **Security Evidence v2** to the production scanner state. The security workflow now checks out the last-known-good `security-evidence-v2` snapshot, materializes only the bounded mutable evidence needed by the scanner/projector into a disposable SQLite working database, and stages every candidate update away from the published branch.
- Add the production v2 orchestrator `tools/security/production_security_v2_pipeline.py`. Bounded scans reuse unchanged content-addressed analyses, retain the previous current pointer when a revalidation fails, refresh dependency/IPC/advisory projections, merge only successful new analyses, garbage-collect unreferenced analysis objects, rebuild all v2 indexes, validate the staged snapshot, and build the small client marketplace SQLite.
- Add artifact-side resolved NuGet recovery from packaged `*.deps.json` files. Exact package/version observations are emitted as `nuget-resolved` evidence even when a distributed plugin does not contain `project.assets.json` or `packages.lock.json`.
- Add explicit scanner diagnostics for dependency rows by kind, exact and missing-version NuGet observations, IPC provider/consumer/unresolved channels, and OSV observed/queried/matched coverage.
- Add intrinsic v2 snapshot validation for index hashes, variant/analysis pointers, dataset hashes/sizes/record digests, root counts, orphan analyses, and the publication file-size ceiling. Incremental v2 publication requires this validation report plus the independent developer audit.
- Include the latest operator/security/source-analysis tools supplied for this cutover, including the local v2 scanner, evidence inspector, public Git source handling, permission/dependency analysis, package validator, and marketplace UI validation helpers.

### Changed

- Advance the security scanner generation to **2.5.0** so existing 2.4.0 evidence is revalidated gradually under the new artifact dependency semantics. A revalidation that fails cannot replace previously validated evidence.
- Route OSV coverage through exact current NuGet package/version observations and fail publication when observed queryable versions are not actually queried. Advisory matches are then re-projected without starting a second artifact scan.
- Rebuild `indexes/nuget.json`, `indexes/ipc.json`, dependency components, advisories, plugin mappings, and artifact mappings from the staged current state before publication. Security/evidence revisions ignore transient SQLite scan IDs so an identical revalidation does not manufacture a semantic change.
- Publish the `security-evidence-v2` branch as a validated snapshot only after the independent audit succeeds. The client `catalog-latest` release is updated only after those v2 gates pass.
- Stop the catalog builder from downloading the archived detailed SQLite evidence database. It now uses only the small marketplace SQLite as an identity/presentation seed.
- Retire the giant SQLite compactor from the production chain. `catalog-compaction.yml` is now a manual compatibility/self-test workflow and the existing `security-evidence-latest` release remains untouched as the archival v1 rollback/reference dataset.
- Add a public-source availability badge to the product security summary so package scan severity, automation, and source coverage remain distinct signals.

### Safety / publication guarantees

- Scanner crashes, failed plugin revalidations, malformed or oversized shards, hash/record-digest mismatches, missing variant/analysis pointers, incomplete OSV coverage, marketplace projection disagreement, developer-audit failures, or an evidence push failure cannot replace the last-known-good v2 snapshot. The root `index.json` is generated last in staging and the evidence branch is replaced only after every gate passes.
- Detailed evidence remains server/developer-side. The Dalamud client continues to consume the compact `omega-marketplace.sqlite` projection rather than the forensic v2 corpus.

### Availability

- This is the production cutover release. Once 0.8.80 is pushed to GitHub `main`, the next successful catalog/security chain begins bounded 2.5.0 revalidation against the already-published `security-evidence-v2` baseline. The archived v1 SQLite evidence is not deleted or overwritten.

## [0.8.79] - 2026-08-17

### Added

- Add `--download-current` to the security-evidence v2 migration CLI. The tool now resolves the live `security-evidence-latest` GitHub release, resumes interrupted downloads, validates the published size and SHA-256, invalidates stale cache entries, safely extracts the SQLite database, and immediately uses that verified database as the v1 migration source.
- Add `--validate` to run the **full** v1 ↔ v2 parity validator automatically after migration. The default report is written to `<output>/validation-report.json`, and a parity mismatch makes the migration command fail instead of leaving the snapshot looking publication-ready.
- Record the operator-local v1 database path only in the excluded migration state so `validate_security_evidence_v2.py` can infer the exact source database when `--database` is omitted, without leaking a local filesystem path into the publishable `index.json`.

### Changed

- The recommended local migration command is now one operation: `--download-current --output ... --resume --validate`. Manual `--database` migration remains available for offline or archived v1 evidence.
- Keep downloading/migration separate from publication: the v2 branch publisher still requires an explicit successful full validation report and `--push`.

### Availability

- These are local/operator CLI changes and require no Definitions refresh. After this source is built through ZipRunner, the current published v1 evidence can be downloaded and migrated directly from the Omega repository checkout.

## [0.8.78] - 2026-08-17

### Added

- Add the first **security evidence v2** migration toolchain for moving the large server-side forensic database away from one monolithic SQLite transport. `migrate_security_evidence_v2.py` opens a downloaded v1 evidence database read-only and exports current security state into per-variant JSON plus content-addressed artifact analyses. Ordinary evidence remains readable JSON where bounded, while managed symbols, calls, reachability, and other large collections are emitted as deterministic gzip JSONL shards.
- Add resumable local migration state. Interrupted conversions can continue with `--resume` as long as the source database revision has not changed; the v2 root `index.json` is written last so an incomplete conversion cannot masquerade as a finished evidence snapshot.
- Add `indexes/plugins.json`, `indexes/artifacts.json`, `indexes/nuget.json`, and `indexes/ipc.json` so future scanners, OSV processing, and the Developer View can use small purpose-built indexes instead of traversing multi-gigabyte forensic storage. Identical mirror evidence deduplicates to one semantic analysis ID beneath the shared artifact SHA-256.
- Add a full **v1 ↔ v2 parity validator**. It verifies every referenced file hash/size, current scan and identity state, derived dependency state, NuGet/IPC/advisory/component indexes, and semantic row digests for current findings, dependencies, IPC, permissions, automation, assemblies, imports, managed symbols, calls, and reachability.
- Add a local evidence publisher for the dedicated `security-evidence-v2` branch. It performs preflight by default, enforces the bounded per-file ceiling, publishes from a temporary Git repository rather than touching the Omega source checkout, and uses a single snapshot commit with force-with-lease only when `--push` is explicitly supplied.

### Changed

- Document the migration boundary explicitly: **the client marketplace/Definitions database remains SQLite**. Security evidence v2 is only for the large server-side static-analysis/evidence transport. Phase 1 migrates current security state while the downloaded v1 SQLite database remains the historical reference.

### Availability

- The v2 tools are local/operator tooling and do **not** change the production GitHub Actions publication format yet. Download the current v1 evidence database, migrate it locally, run full parity validation, then publish the validated snapshot branch. Production runners will be switched only after the real migrated dataset proves equivalent.

## [0.8.77] - 2026-08-17

### Added

- Add a **click-through evidence browser** to the Security Developer View. Developer investigation can now start from readable table groups, browse rows with pagination, inspect every field, follow database relationships, and jump from rows carrying a variant ID directly into the plugin conclusion view. The raw SQL console remains available only as an optional Advanced tool.
- Make summary cards such as Findings, OSV matches, IPC providers, dependencies, and scan state open the corresponding evidence table directly.

### Fixed

- Fix the Developer View plugin list returning zero rows in browsers where the element id `status` collided with the browser's built-in `window.status` property. UI code now resolves controls explicitly instead of depending on implicit element globals.

### Changed

- Reposition the GitHub Pages homepage around Omega's actual product: an **in-game Dalamud plugin marketplace with integrated security scanning**. Search/share metadata and the hero copy now lead with plugin discovery, source comparison, dependency/security intelligence, and install-through-Dalamud instead of framing Omega primarily as evidence gathering in a risky ecosystem.

### Availability

- The Developer View changes are available immediately after updating the repository tooling and work with an already-downloaded evidence database. A newly published database is not required for click-through browsing.
- The homepage copy becomes public after the next successful GitHub Pages deployment from this source revision. Search engines and link-preview caches may keep the previous title/description temporarily after deployment.

## [0.8.76] - 2026-08-17

### Fixed

- Repair **OSV collection against real scanner output**. Public-advisory collection now includes resolved NuGet observations recorded as `nuget-lock` and `nuget-resolved` as well as direct `nuget` dependencies. The previous collector could report `queriedPackages: 0` even while the evidence database contained tens of thousands of resolved dependency rows.
- Fix the Security Developer View SQL example so it contains real line breaks instead of literal `\n` escape text, which SQLite rejected as `unrecognized token: "\"`.
- Make the developer-view evidence cache invalidate a same-named release asset when its published size or SHA-256 changes instead of accidentally reusing the previous large database.
- Add resumable `.part` downloads using HTTP Range requests for the detailed security evidence bundle, so an interrupted hundreds-of-megabytes download does not normally have to restart from zero.
- Carry the corrected SQLite catalog integration expectation that failed current website scrapes invalidate marketplace presentation while retaining server-side history; this is the repair required for the currently failing scheduled catalog-builder preflight once this source reaches `main`.

### Changed

- The Security Developer View now shows **current scans at the latest scanner generation**, **legacy current scans**, and the number of observed resolved NuGet package/version pairs. IPC is labelled **IPC providers observed** so a zero is not misread as proof that no plugin exposes IPC while incremental rescanning is still catching up.
- OSV collection de-duplicates package/version observations across current variants and only queries dependencies belonging to completed current scans.
- Persist OSV collector coverage (`queriedPackages` / `matchedPackages`) into security evidence metadata. The developer consistency audit now fails when resolved NuGet versions exist but the collector queried fewer packages than expected, making a silent zero-query regression publish-blocking.

### Availability

- Developer-view download/SQL/coverage fixes are available immediately after updating the repository tooling.
- OSV matches begin populating after the next successful security scan using this collector and a subsequent evidence/Definitions publication. Existing published evidence can continue to show zero until that run completes.
- The online catalog workflow repair takes effect only after this source revision is pushed to GitHub `main`; rerunning the old workflow revision will continue to execute its stale self-test.

## [0.8.75] - 2026-08-17

### Added

- Add the **Omega Security Developer View**, a read-only Python/localhost browser tool that can download the published detailed security-evidence database and small marketplace database, verify their SHA-256 sidecars, and traverse current plugin/source-variant security conclusions.
- Expose static findings and evidence, exact-version OSV matches, dependency resolutions/issues, IPC providers/consumers and required/feature/optional semantics, permission candidates, automation evidence, plugin source build scope, source/package comparison, scan lineage, dependency drift, and lazy managed-call inspection.
- Add a bounded read-only SQL console for developer investigation. The SQLite connection runs with `query_only` and the console accepts only a single SELECT/PRAGMA/WITH/EXPLAIN statement.
- Add an independent **conclusion audit** that reproduces finding counters, highest static severity, exact-version advisory summary, hidden internal risk score, and the client marketplace security projection from detailed evidence.
- Run that conclusion audit inside the catalog compaction/publication workflow before databases can be published, and publish `security-developer-audit.json` with the detailed evidence release for diagnostics.

### Fixed

- Update the SQLite catalog integration self-test to match the current-presentation policy introduced in 0.8.72: a failed due website re-scrape keeps server-side history but marks that website presentation non-current instead of expecting stale rich-card data to remain active. This repairs the current push-driven catalog/regression workflow failure.

### Availability

- The developer view is repository tooling and can be used immediately after updating the source. Running it without arguments downloads the latest published security evidence locally; the Omega plugin itself still never downloads the detailed evidence database.
- The new online conclusion-audit artifact appears after the next successful security -> compaction publication using this workflow revision.

## [0.8.74] - 2026-08-17

### Changed

- Hide the **Collections** subsection on an installed plugin product page when the plugin is not a member of any named Dalamud collection. The plugin-state row remains visible, but Omega no longer reserves empty space or shows the redundant “Not in a named collection” placeholder.

### Availability

- This is a client UI change and is visible immediately after installing 0.8.74. No Definitions refresh or plugin re-scrape is required.

## [0.8.73] - 2026-08-17

### Fixed

- Repair the Windows/ZipRunner build gate after the 0.8.71 project-link redesign. The regression suite now validates the classified **Discord / Website / Source / Documentation / Issues / Releases** action model instead of requiring the obsolete single globe-icon project button.
- Remove the nullable-return warning in legacy plugin-config backup identity inference by explicitly discarding null filename candidates before validation.

### Availability

- This is a compile/regression repair only. It does not change Definitions data or require plugins to be re-scraped.

## [0.8.72] - 2026-08-17

### Changed

- Treat marketplace website/README metadata as a **current presentation projection**, not an accumulating history. A successful re-scrape replaces the previous description, README, images, and classified project links instead of merging old presentation text into the new entry.
- Keep prior successful scrape content only in the server-side evidence/cache for diagnostics and retry lineage. If a due re-scrape fails, that stale content is no longer projected into the client marketplace until a current scrape succeeds.
- Add a presentation-parser generation to website enrichment. Parser changes can invalidate older cached presentation snapshots so improved scraping/rendering does not have to wait for the normal seven-day website cache horizon.
- Release changelog entries now call out **Availability** whenever a feature is shipped in plugin code before existing catalog entries have been re-scraped/re-published.

### Availability

- This release changes how future Definitions are built. Existing installed Definitions remain unchanged until the next catalog/security/compaction publication is applied in Omega.

## [0.8.71] - 2026-08-17

### Added

- Added classified project actions for **Join Discord**, **Website**, **Source**, **Documentation**, **Issues**, and **Releases**. Only recognized HTTPS roles are promoted to storefront buttons; arbitrary discovered URLs stay in server-side evidence.
- Added safe README presentation for Markdown headings, paragraphs, lists, quotes, code fences, and common embedded HTML while stripping executable/interactive HTML such as scripts, forms, iframes, objects, and embeds.
- Added removable active-filter pills that remain visible outside the expanded filter editor, plus multi-select author filters with AND semantics.

### Changed

- Expanded marketplace text search to include enriched project descriptions and README content.
- Reworked the filter editor so its lower controls are not clipped at scaled UI sizes.

### Availability

- Filter pills and README rendering are client features available immediately after installing 0.8.71.
- Discord/website/source/docs/issues/releases actions and newly searchable enriched text depend on each project having been scraped with the newer metadata parser and then included in a published Definitions revision. Older catalog entries may therefore gain these features progressively as they are re-scraped.

## [0.8.70] - 2026-08-17

### Changed

- Check the lightweight online Definitions descriptor every hour while Omega is loaded instead of at most once per 24 hours. The scheduler wakes every 15 minutes so an overdue check is picked up promptly without downloading the Definitions database or refreshing every custom repository.
- Preserve the previous daily-check timestamp as a configuration fallback so upgrades do not create unnecessary duplicate requests.

### Added

- Show a native Dalamud notification when a new Definitions revision is discovered, even when the Omega window is closed. Each revision is announced once and remains visible through the existing Updates attention state until applied.

## [0.8.69] - 2026-08-17

### Fixed

- Repository package-divergence warnings no longer show an unnecessary outer scrollbar.
- **Review Sources** now opens a dedicated Dalamud repository view backed by Dalamud's live configured repository list, rather than only Omega's curated/My Sources inventory.
- Divergent repositories can be acknowledged directly from the Dalamud source-review view; acknowledgement is source-specific and tied to the current evidence fingerprint, so changed package evidence requires review again.
- The install chooser no longer inherits the currently displayed product variant as its implicit source. It starts from Omega's ranked clean candidate instead.
- Packages already identified as cross-source artifact outliers, and repositories with known package divergence, are demoted behind clean alternatives before ordinary provider preference is applied.
- Selecting an unacknowledged divergent repository changes the install action to **Review risk** instead of allowing that source to be installed accidentally.
- Repository security comparison now compares package hashes only for the same plugin version/API, avoiding false divergence when two repositories legitimately advertise different versions.

## [0.8.68] - 2026-08-17

### Added

- Classify consumed Dalamud IPC relationships as **required**, **feature**, **optional**, or **unknown**, with a bounded confidence level and static evidence explaining the classification.
- Show IPC relationship semantics in the in-game Dependencies panel and preserve the bounded relationship reason in Definitions while keeping detailed source evidence server-side.
- Warn in the repository/install chooser when a **High** or **VeryHigh** confidence required IPC provider is not installed, with a direct route to the resolved provider when Omega knows it.

### Changed

- Required-provider inference is deliberately conservative: merely obtaining an IPC subscriber is not enough. Strong required status needs startup/fatal/direct-use evidence; guarded integrations are classified as feature/optional and insufficient evidence remains unknown.
- High-confidence required IPC channels that cannot be resolved, or resolve ambiguously, now produce dependency-graph issues instead of being treated like ordinary optional IPC.
- Required IPC providers participate in the same bounded required-dependency automation propagation as declared required plugin dependencies. Omega still does not silently install inferred dependencies.
- Security scanner schema advances to **2.4.0** / dependency intelligence v2 so existing source-assisted IPC relationships are re-evaluated under the new semantics.

## [0.8.67] - 2026-08-17

### Changed

- Split Dalamud IPC observations into explicit provider and consumer roles instead of treating every `GetIpcProvider`/`GetIpcSubscriber` reference as the same external integration.
- Added a current IPC provider registry keyed by the exact Dalamud channel string, allowing subscriber edges to resolve to the plugin that exposes the channel without guessing by plugin name.
- Resolved IPC integrations now carry the provider plugin target into Definitions, making the provider clickable from the in-game Dependencies panel; unresolved and ambiguous provider channels remain explicit.
- Provider declarations no longer count as indirect automation consumption merely because the exposed channel name resembles a known automation IPC.
- IPC provider/consumer endpoint evidence and the provider registry are retained in the server-side security evidence database and semantic Evidence Revision.

## [0.8.66] - 2026-08-17

### Changed
- Increase scheduled catalog/source discovery from once daily to every six hours. Accepted source submissions remain event-driven and continue to queue the catalog builder immediately.
- Run the independent security/OSV safety-net scan twice daily, in addition to the security scan automatically triggered after every successful catalog build. With the four catalog passes, normal security/follow-up reconciliation can now run up to six times per day.
- Reconcile actionable public-source follow-up issues after every security pass, while retaining the existing per-run creation bound so increased cadence clears backlogs without creating an unbounded issue burst.
- Keep successful website enrichment cached for seven days; the higher catalog cadence therefore prioritizes newly discovered or stale sources instead of repeatedly scraping unchanged project sites.

## [0.8.65] - 2026-08-17

### Added
- Plugins whose exact resolved dependency versions match one or more public OSV advisories now carry a visible **Known risk** security marker in Discover, product security summaries, and the installed-environment security view.
- Marketplace Definitions now retain the bounded advisory count, highest advisory severity, and an internal 0–100 security risk score for each exact plugin package. The numeric score remains intentionally hidden from normal UI.

### Changed
- Known OSV advisories now add explicit weight to Omega's internal plugin risk score and can elevate the effective security posture used for Library ordering and warning color, while remaining distinct from static-analysis findings.
- Advisory matching is now exact-version scoped when projecting risk, preventing an advisory for one version of a shared NuGet component from incorrectly flagging plugins that use a different version.
- The security workflow refreshes OSV data after artifact scanning and re-projects advisory matches with `--max-scans 0`, so dependencies discovered in the current run can receive known-risk status immediately instead of waiting for the next scheduled scan.

## [0.8.64] - 2026-08-17

### Fixed
- Scope source-assisted security analysis to the actual Dalamud plugin build graph instead of treating an entire monorepo as plugin-integrated code.
- Follow transitive `ProjectReference` dependencies, linked source/build inputs, and applicable MSBuild configuration for the selected plugin project.
- Keep sibling server, website, deployment, test, and tooling projects as non-critical repository context so their capabilities do not affect plugin security, dependency, endpoint, or automation conclusions.
- Distinguish a repository-only commit change from a change to the relevant plugin source fingerprint in security lineage.

### Security
- Bump the static security scanner to 2.2.0 so existing source-assisted scans are refreshed under the corrected source-scope semantics.

## [0.8.63] - 2026-08-16

### Changed
- Integrated the revised public **Features** page from the supplied Pages handoff without replacing the rest of the already-integrated 0.8.62 site.
- Reframed the Features page around Omega's shared product story: broader in-game discovery, visible provenance, security context, and the boundary that **Omega finds it; Dalamud installs it**.
- Updated the public-site regression contract to lock the revised Features narrative and provenance screenshot into future builds.

## [0.8.62] - 2026-08-16

### Changed
- Integrated the supplied GitHub Pages refresh across Overview, Features, Install, Security, FAQ, and 404 pages, plus the new About page.
- Added the supplied in-game screenshots for the home view, repository setup, provenance/source comparison, and installed-plugin security context.
- Updated the public-site navigation, responsive presentation, and site validation contracts while preserving the rule that plugin discovery remains in game rather than exposing a browsable web catalog.

## [0.8.61] - 2026-08-16

### Fixed
- Restored the newer source-discovery and security-review workflow that was accidentally overwritten by the 0.8.57 source-recovery overlay.
- Human-reviewed public-source overrides again use stable plugin/source identities rather than build-local SQLite variant row IDs, so catalog rebuilds do not detach reviewed source mappings.
- Source follow-up generation is again deduplicated per stable plugin/feed identity, distinguishes retryable/transient source failures from actionable missing-source cases, and carries the stable override identity through GitHub issue replies.
- Source-submission validation again uses the hardened bounded/public-URL checks and structured override document from the known-good 0.8.56 pipeline.
- Preserves all 0.8.59 direct-update/repository-migration behavior and the 0.8.60 Discover installed-marker overlay fix.

## [0.8.60] - 2026-08-16

### Fixed
- Discover now composites the green installed check inside the plugin artwork child after the image is drawn, preventing the plugin icon from covering the installed-state marker.
- Installed markers retain identical card/list geometry and gain a dark contrast rim so they remain readable on bright or similarly colored plugin artwork.

## [0.8.59] - 2026-08-16

### Added
- Omega now detects a newer compatible release that has moved to another known repository and offers an explicit **Migrate & update** confirmation showing the installed source, destination source, version change, and any package/security difference.
- Repository migration prepares the destination source automatically when needed while deliberately leaving the old repository in place for any other plugins that may still use it.

### Fixed
- **Update** now executes the selected plugin update through Dalamud's real plugin-update lifecycle instead of only opening Dalamud's Updateable Plugins page.
- Same-repository updates remain preferred, while a cross-repository package is considered a migration only when both its version and release chronology prove it is newer.
- Dalamud's `OFFICIAL` installed-source marker is recognized as the same publishing lineage as the live official repository, preventing official updates from being misclassified as migrations.

## [0.8.58] - 2026-08-16

### Changed
- About now keeps the Omega identity and Version/Definitions summary fixed while the lower product/help section scrolls independently.
- The large Omega artwork is aligned toward the content edge instead of centering the entire hero block, fixing the visual mismatch with the sections below it.
- Version remains visible as a concise value without redundant explanatory prose; Definitions retains a wrapped explanation of what the independently updated data package contains.
- Long About bullets now wrap inside the modal instead of clipping past the right edge.

## [0.8.57] - 2026-08-16

### Changed
- A package that differs from Omega's preferred package baseline now raises a prominent red **Plugin differs from the preferred package baseline** warning at the top of the plugin page instead of leaving that signal buried inside an expanded package row.
- Library Security now opens with a prominent red warning explaining that static analysis reports observed capabilities and that no findings do not prove a plugin is safe.
- User-facing package/security identity text now says **Plugin** or **Plugin package** instead of **Artifact** while retaining the exact SHA-256 context.
- About once again explains the installed Omega **Version** and the independently updated **Definitions** data package, including the loaded Definitions revision when available.

## [0.8.56] - 2026-08-16

### Added
- Library now exposes **Import config backup** at the top and can safely restore Omega-created plugin configuration ZIPs, including a confirmation step and legacy-backup inference.
- Library security results now explain the artifact SHA-256 identity and when one scan is shared by identical repository packages.

### Changed
- Security projection backfills completed scan history and propagates one canonical result across variants with the same proven artifact identity instead of requiring every repository row to own a duplicate current-scan record.
- Plugin/project images are centered against the actual content rectangle rather than the child-window origin.
- Product plugin state keeps the state text and toggle on one line; the toggle remains visible but disabled while a named collection controls the plugin.
- Product collection membership uses a full-width panel and a normal-contrast **Collections** heading.
- Marketplace Filters moved to the right edge while the expanded filter panel still consumes the full content width.

### Fixed
- A plugin artifact already scanned server-side no longer appears unscanned merely because the selected repository variant lacked its own duplicate `plugin_security_current` row.
- Image padding no longer shifts artwork left/up inside cards, screenshots, product pages, and the large image viewer.

## [0.8.55] - 2026-08-16

### Added
- Omega now imports third-party repositories already configured in Dalamud into **My Sources** without taking ownership of them, and shows whether they are enabled in Dalamud.
- Repository-risk warnings now alert users when an enabled/installed source publishes artifact bytes that differ from Omega's stable-provider baseline for the same plugin version.
- Manifest authors are normalized into individual identities; product-page author names can be clicked to discover all plugins by that author.
- **Latest additions** and **Latest updates** now explain their chronology directly in Spotlight.

### Changed
- Library rows now show the repository the installed plugin actually came from, using Dalamud's persisted `InstalledFromUrl`, instead of always showing Omega's preferred marketplace source.
- Spotlight no longer shows a fixed plugin count in its navigation tooltip.
- Tooltips use their own full-contrast style and remain readable when an unavailable/older-API plugin row is dimmed.

### Security
- Sources with cross-source artifact SHA-256 divergence are marked for review in Settings; acknowledgements persist until the set of affected repositories changes.

## [0.8.54] - 2026-08-16

### Added
- Product pages now expose a dedicated **How to use** section derived from the plugin's own description and enriched public README data.
- Product pages now expose plugin changelogs, including bounded historical entries retained in the Definitions database.
- Library Updates now shows a changelog icon beside the installed → offered version line.
- GitHub releases now use this `CHANGELOG.md` as their release-note source.

### Fixed
- The Dalamud **Default plugins** profile is no longer presented as a named collection on product pages. Plugins with no named membership now say so explicitly.
- Product state/collection panel sizing was increased so membership information is not clipped.

## [0.8.53] - 2026-08-16

### Fixed
- Cross-repository version numbers are no longer treated as one global chronology. The preferred green package is the update authority, with `LastUpdate` used to validate cross-source updates.
- Historical/API-shaped versions such as `v15.x` no longer automatically outrank unrelated `v0.x` package versions.

## [0.8.52] - 2026-08-16

### Fixed
- Omega now ships its own `e_sqlite3` runtime instead of depending on Windows `winsqlite3`, allowing the plugin to start under Wine/Proton environments used by Linux FFXIV installations.
- Release packaging verifies the native SQLite runtime is actually present in `Omega.zip`.

## [0.8.51] - 2026-08-16

### Fixed
- Updated product-navigation regression contracts to follow the preferred stable package baseline rather than an official-source-only rule.

## [0.8.48] - 2026-08-16

### Added
- Dalamud, Puni.sh, NightmareXIV and Combat Reborn are recognized as stable provenance providers for preferred package selection.
- Same-hash artifacts share one canonical security result; differing hashes are surfaced as different packages.

## [0.8.45] - 2026-08-16

### Added
- Library environment security overview for installed plugins.
- Durable Definitions-update notification and periodic Omega update checks.
- Source security comparisons in package and install views.
