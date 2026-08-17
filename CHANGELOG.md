# Changelog

Omega follows semantic product versions. Release entries here are consumed by the GitHub release workflow so the same human-readable notes are published with each immutable release.

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
