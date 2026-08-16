# Changelog

Omega follows semantic product versions. Release entries here are consumed by the GitHub release workflow so the same human-readable notes are published with each immutable release.

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
