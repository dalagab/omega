# Changelog

Omega follows semantic product versions. Release entries here are consumed by the GitHub release workflow so the same human-readable notes are published with each immutable release.

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
