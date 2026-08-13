$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$required = @(
  'Omega.sln',
  'Omega/DalagabOmega.csproj',
  'Omega/Plugin.cs',
  'Omega/BuildInfo.cs',
  'Omega/GlobalUsings.cs',
  'Omega/DalagabOmega.json',
  'images/icon.png',
  'images/title-icon.png',
  'images/company-fallback.png',
  'sources/curated-sources.json',
  'Omega/Models/CuratedSourceDefinition.cs',
  'Omega/Services/CuratedSourceCatalog.cs',
  'Omega/Services/CatalogBundleImporter.cs',
  'Omega/Services/CatalogDatabase.cs',
  'Omega/Services/DailyCatalogUpdateService.cs',
  'Omega/Services/CatalogUpdateCoordinator.cs',
  'Omega/Services/OnlineCatalogClient.cs',
  'Omega/Services/DalamudInstallerBridge.cs',
  'Omega/Services/DalamudRepositoryBridge.cs',
  'Omega/Services/DalamudSystemMenuBridge.cs',
  'Omega/Services/MarketplaceCatalogService.cs',
  'Omega/Services/MarketplaceCatalogRules.cs',
  'Omega/Services/RepositoryCatalogStatus.cs',
  'Omega/Services/RepositoryHealthRules.cs',
  'Omega/Services/RepositoryManifestParser.cs',
  'Omega/Services/PluginIconCache.cs',
  'Omega/UI/MarketplaceWindow.cs',
  'Omega.RegressionTests/Omega.RegressionTests.csproj',
  'Omega.RegressionTests/Program.cs',
  'DESIGN.adoc',
  'UI_DESIGN.adoc',
  'INSTRUCTIONS.md',
  'AGENTS.md',
  'omega.zr',
  'BUILD_STAMP.txt',
  '.github/workflows/catalog-builder.yml',
  'catalog/search-queries.json',
  'catalog/candidates.json',
  'catalog/known-bad-hashes.json',
  'catalog/generated-sources.json',
  'catalog/latest-report.json',
  'catalog/README.md',
  'catalog/catalog-endpoint.json',
  'tools/catalog/discover_sources.py',
  'tools/catalog/build_catalog.py',
  'tools/catalog/test_catalog_pipeline.py'
)
foreach ($relative in $required) {
  $path = Join-Path $root $relative
  if (-not (Test-Path $path)) { throw "Missing required file: $relative" }
}

$buildInfo = Get-Content (Join-Path $root 'Omega/BuildInfo.cs') -Raw
$project = Get-Content (Join-Path $root 'Omega/DalagabOmega.csproj') -Raw
$zr = Get-Content (Join-Path $root 'omega.zr') -Raw | ConvertFrom-Json
$manifest = Get-Content (Join-Path $root 'Omega/DalagabOmega.json') -Raw | ConvertFrom-Json
$curated = Get-Content (Join-Path $root 'sources/curated-sources.json') -Raw | ConvertFrom-Json
$stamp = (Get-Content (Join-Path $root 'BUILD_STAMP.txt') -Raw).Trim()

if ($zr.version -ne '0.7.1.0') { throw 'Unexpected Omega version for this pass' }
if ($zr.expected_build_stamp -ne 'omega-online-catalog-with-local-fallback-20260813') { throw 'Unexpected build stamp for this pass' }
if ($stamp -ne $zr.expected_build_stamp) { throw 'BUILD_STAMP does not match omega.zr' }
if ($buildInfo -notmatch [regex]::Escape($zr.version)) { throw 'BuildInfo version does not match omega.zr' }
if ($project -notmatch "<Version>$([regex]::Escape($zr.version))</Version>") { throw 'csproj version does not match omega.zr' }
if ($buildInfo -notmatch [regex]::Escape($zr.expected_build_stamp)) { throw 'BuildInfo stamp does not match omega.zr' }
if ($project -notmatch '<AssemblyName>DalagabOmega</AssemblyName>') { throw 'AssemblyName must be DalagabOmega' }
if ($project -notmatch '<AllowUnsafeBlocks>true</AllowUnsafeBlocks>') { throw 'System-menu bridge requires explicit unsafe build setting' }
if ($manifest.Author -ne 'Dalagab Group' -or $manifest.Name -ne 'Omega') { throw 'Manifest product identity mismatch' }
if ($manifest.LoadRequiredState -ne 2) { throw 'Omega must explicitly permit pre-login loading with LoadRequiredState 2' }
if (-not $curated -or -not ($curated | Where-Object { $_.id -eq 'dalamud-official' })) { throw 'Curated source catalog must include Dalamud official' }

$plugin = Get-Content (Join-Path $root 'Omega/Plugin.cs') -Raw
$ui = Get-Content (Join-Path $root 'Omega/UI/MarketplaceWindow.cs') -Raw
$config = Get-Content (Join-Path $root 'Omega/Configuration.cs') -Raw
$installer = Get-Content (Join-Path $root 'Omega/Services/DalamudInstallerBridge.cs') -Raw
$catalog = Get-Content (Join-Path $root 'Omega/Services/MarketplaceCatalogService.cs') -Raw
$systemMenu = Get-Content (Join-Path $root 'Omega/Services/DalamudSystemMenuBridge.cs') -Raw
$curatedService = Get-Content (Join-Path $root 'Omega/Services/CuratedSourceCatalog.cs') -Raw
$repoClient = Get-Content (Join-Path $root 'Omega/Services/RepositoryClient.cs') -Raw
$catalogDatabase = Get-Content (Join-Path $root 'Omega/Services/CatalogDatabase.cs') -Raw
$dailyUpdate = Get-Content (Join-Path $root 'Omega/Services/DailyCatalogUpdateService.cs') -Raw
$catalogUpdates = Get-Content (Join-Path $root 'Omega/Services/CatalogUpdateCoordinator.cs') -Raw
$onlineCatalog = Get-Content (Join-Path $root 'Omega/Services/OnlineCatalogClient.cs') -Raw
$manifestParser = Get-Content (Join-Path $root 'Omega/Services/RepositoryManifestParser.cs') -Raw
$catalogRules = Get-Content (Join-Path $root 'Omega/Services/MarketplaceCatalogRules.cs') -Raw
$regressionProject = Get-Content (Join-Path $root 'Omega.RegressionTests/Omega.RegressionTests.csproj') -Raw
$regressionProgram = Get-Content (Join-Path $root 'Omega.RegressionTests/Program.cs') -Raw
$solution = Get-Content (Join-Path $root 'Omega.sln') -Raw
$marketplacePlugin = Get-Content (Join-Path $root 'Omega/Models/MarketplacePlugin.cs') -Raw
$iconCache = Get-Content (Join-Path $root 'Omega/Services/PluginIconCache.cs') -Raw

# Manual source policy / package assets.
if ($ui -notmatch 'Reload Sources') { throw 'Reload Sources action is missing' }
if ($plugin -notmatch 'catalog-db' -or $plugin -notmatch 'catalog.LoadCached') { throw 'Persistent local catalog startup load is missing' }
if ($plugin -match 'catalog\.RefreshAsync') { throw 'Plugin startup must not synchronously refresh repositories' }
if ($plugin -notmatch 'DailyCatalogUpdateService') { throw 'Daily update service is not wired into plugin lifetime' }
if ($dailyUpdate -notmatch 'TimeSpan\.FromDays\(1\)' -or $dailyUpdate -notmatch 'updates\.RefreshAsync' -or $dailyUpdate -notmatch 'LastDailyUpdateCheckUtc') { throw 'Daily online/fallback update contract is incomplete' }
if ($catalog -notmatch 'RefreshPluginSourcesAsync') { throw 'Scoped per-plugin source refresh is missing' }
if ($ui -notmatch 'updates\.RefreshPluginSourcesAsync') { throw 'Plugin details must trigger coordinator freshness checks' }
if ($repoClient -notmatch 'IfNoneMatch' -or $repoClient -notmatch 'IfModifiedSince' -or $repoClient -notmatch 'HttpStatusCode.NotModified') { throw 'Conditional repository refresh support is incomplete' }
if ($catalogDatabase -notmatch 'ContentSha256' -or $catalogDatabase -notmatch 'ManifestJson') { throw 'Catalog database record contract is incomplete' }
if ($catalogDatabase -notmatch 'ImportRecord') { throw 'Catalog database prebuilt-record import is missing' }
if ($plugin -notmatch 'omega-catalog-db.zip' -or $plugin -notmatch 'catalog.ImportBundle') { throw 'Prebuilt catalog bundle startup import is missing' }
if ($ui -match 'override void OnOpen') { throw 'Catalog must not refresh on window open' }
if ($config -match 'RefreshOnOpen') { throw 'RefreshOnOpen must not be reintroduced' }
if ($ui -notmatch 'Paste URL list from clipboard') { throw 'Bulk source-list import is missing' }
if ($project -notmatch [regex]::Escape('..\images\icon.png')) { throw 'Omega product icon is not copied into build output' }
if ($project -notmatch [regex]::Escape('..\images\title-icon.png')) { throw '64x64 title icon is not copied into build output' }
if ($project -notmatch [regex]::Escape('..\images\company-fallback.png')) { throw 'Company fallback artwork is not copied into build output' }
if ($project -notmatch [regex]::Escape('..\sources\curated-sources.json')) { throw 'Curated source catalog is not copied into build output' }
if ($project -notmatch 'omega-catalog-db.zip') { throw 'Conditional prebuilt catalog bundle packaging support is missing' }
if ($project -notmatch 'catalog-endpoint.json') { throw 'Online catalog endpoint seed is not packaged' }
if ($curatedService -notmatch 'MergeInto') { throw 'Curated source merge is missing' }
if ($catalogUpdates -notmatch 'TryApplyOnlineCatalogAsync' -or $catalogUpdates -notmatch 'await catalog.RefreshAsync\(configuration.Repositories\)') { throw 'Central catalog preferred/local fallback coordinator is incomplete' }
if ($catalogUpdates -notmatch 'userRepositories.Length == 0' -or $catalogUpdates -notmatch '!x.IsCurated') { throw 'Central catalog must avoid curated fan-out and only overlay user repositories' }
if ($onlineCatalog -notmatch 'omega.catalog.v1' -or $onlineCatalog -notmatch 'Sha256' -or $onlineCatalog -notmatch 'DownloadFileAsync') { throw 'Online catalog descriptor/hash downloader is incomplete' }
if ($catalogDatabase -notmatch 'ReplaceAll' -or $catalogDatabase -notmatch '\.staging-') { throw 'Authoritative central database staging/swap is missing' }

# Entry points.
if ($plugin -notmatch 'ITitleScreenMenu') { throw 'Public title-screen menu service is missing' }
if ($plugin -notmatch 'AddEntry\(1000,\s*"Omega"') { throw 'Omega title-screen entry registration is missing' }
if ($plugin -notmatch 'DalamudSystemMenuBridge') { throw 'System-menu bridge is not constructed' }
if ($systemMenu -notmatch 'AgentHUD\.Addresses\.OpenSystemMenu') { throw 'API-15 OpenSystemMenu hook is missing' }
if ($systemMenu -notmatch 'ExecuteMainCommand') { throw 'System-menu command dispatch hook is missing' }
if ($systemMenu -notmatch 'PushColorType\(539\)') { throw 'Green/colored Omega System-menu label is missing' }
if ($systemMenu -notmatch 'Append\("Omega"\)') { throw 'System-menu Omega label is missing' }

# Omega-native storefront shell.
if ($ui -notmatch 'omega-app-sidebar') { throw 'Omega app sidebar shell is missing' }
if ($ui -notmatch 'omega-app-content') { throw 'Omega content canvas is missing' }
if ($ui -notmatch 'DrawPillButton') { throw 'Custom Omega controls are missing' }
if ($ui -notmatch 'DrawStorefrontLayout') { throw 'Responsive storefront layout is missing' }
if ($ui -notmatch 'targetTileWidth = 166f') { throw 'Responsive icon-grid sizing is missing' }
if ($ui -notmatch 'ImGui\.IsRectVisible') { throw 'Visible-entry icon gating is missing' }
if ($ui -notmatch 'DrawArtworkOverlayActions') { throw 'Artwork-overlay plugin actions are missing' }
if ($ui -match 'DrawCompactTileActions') { throw 'Below-artwork compact action row must not return' }
if ($ui -notmatch 'DrawPluginDetailsPanel') { throw 'Inline plugin details panel is missing' }
if ($ui -match 'storefrontPage') { throw 'Paged storefront state must not return' }
if ($ui -match 'plugin-tile-') { throw 'Visible plugin-card child surface must not return' }
if ($ui -match 'ImGui\.BeginTable\("market"') { throw 'Legacy giant plugin table must not be the default marketplace UI' }
if ($installer -match 'OpenPluginInstallerTo') { throw 'Omega must not automatically fall back to the stock Dalamud plugin installer' }

# API badges, fallback artwork, and duplicate-source choice.
if ($marketplacePlugin -notmatch 'SupportsApiLevel') { throw 'API support helper missing' }
if ($marketplacePlugin -notmatch 'DisplayApiLevel') { throw 'API display helper missing' }
if ($marketplacePlugin -notmatch 'IsUnmaintained') { throw 'Unmaintained API-age helper missing' }
if ($ui -notmatch 'DrawApiBadge') { throw 'Artwork API badge missing' }
if ($catalog -notmatch 'GetStableApiLevel') { throw 'Catalog aggregate stable API helper missing' }
if ($catalogRules -notmatch 'GetStableApiLevel') { throw 'Testable stable API aggregation rule missing' }
if ($ui -notmatch 'catalog\.GetStableApiLevel\(plugin\.InternalName, currentApi\)') { throw 'Artwork badge must resolve stable API across repository variants and prefer current API support' }
if ($ui -notmatch 'Selected') { throw 'Visible selected-plugin marker missing' }
if ($ui -notmatch 'Unmaintained') { throw 'Unmaintained artwork label missing' }
if ($ui -notmatch 'omega-author-filter') { throw 'Direct author filter missing' }
if ($ui -notmatch '0\.08f, 0\.62f, 0\.32f') { throw 'Supported API green badge color missing' }
if ($ui -notmatch '0\.72f, 0\.12f, 0\.16f') { throw 'Unsupported API red badge color missing' }
if ($ui -notmatch 'fallbackIconPath') { throw 'Dalagab fallback artwork path missing' }
if ($catalog -notmatch 'GetVariants') { throw 'Duplicate repository variants are not retained' }
if ($catalog -notmatch 'MarketplaceCatalogRules\.Project') { throw 'Catalog must use tested projection rules' }
if ($catalogRules -notmatch 'visibleVariants') { throw 'Catalog variant retention is missing' }
if ($ui -notmatch 'selectedVariantSource') { throw 'Per-plugin source choice state missing' }
if ($ui -notmatch 'Available from .* sources') { throw 'Duplicate-source details selector missing' }
if ($ui -notmatch 'Install from') { throw 'Selected-source install action missing' }

# Curated/community compatibility retained.
if (($curated | Measure-Object).Count -lt 136) { throw 'Curated source catalog must contain the reviewed + discovered 136-source set' }
if (($curated | Where-Object { -not $_.enabledByDefault } | Measure-Object).Count -ne 0) { throw 'All curated sources must default enabled in Omega' }
if (-not ($curated | Where-Object { $_.id -eq 'nightmarexiv' -and $_.url -eq 'https://raw.githubusercontent.com/NightmareXIV/MyDalamudPlugins/main/pluginmaster.json' })) { throw 'NightmareXIV curated URL is not normalized' }
if (-not ($curated | Where-Object { $_.id -eq 'shoegaze' -and $_.url -eq 'https://raw.githubusercontent.com/SHOEGAZEssb/DalamudPluginRepo/main/pluginmaster.json' })) { throw 'SHOEGAZEssb curated URL must use main branch' }
if (-not ($curated | Where-Object { $_.id -eq 'eisenhuth-trustworthy' -and $_.url -eq 'https://raw.githubusercontent.com/Eisenhuth/TrustworthyDalamudPlugins/master/pluginmaster.json' })) { throw 'Eisenhuth curated source missing' }
if (-not ($curated | Where-Object { $_.id -eq 'sphene-dev' -and $_.url -eq 'https://raw.githubusercontent.com/SpheneDev/repo/main/plogonmaster.json' })) { throw 'SpheneDev curated source missing' }
if (-not ($curated | Where-Object { $_.id -eq 'ktisis-direct' -and $_.url -eq 'https://raw.githubusercontent.com/ktisis-tools/Ktisis/main/repo.json' })) { throw 'Ktisis direct curated source missing' }
if (-not ($curated | Where-Object { $_.id -eq 'lmeter-direct' -and $_.url -eq 'https://raw.githubusercontent.com/lichie567/LMeter/main/repo.json' })) { throw 'LMeter curated source missing' }
if (-not ($curated | Where-Object { $_.id -eq 'karlin-main' -and $_.url -eq 'https://raw.githubusercontent.com/Karlin-Z/DalamudPlugins/main/pluginmaster.json' })) { throw 'Karlin main curated source missing or not normalized' }
if (-not ($curated | Where-Object { $_.id -eq 'autovisor-direct' -and $_.url -eq 'https://raw.githubusercontent.com/Ottermandias/AutoVisor/master/repo.json' })) { throw 'AutoVisor curated source missing' }
if (-not ($curated | Where-Object { $_.id -eq 'ookura-risona' -and $_.url -eq 'https://raw.githubusercontent.com/Ookura-Risona/DalamudPlugins/main/pluginmaster.json' })) { throw 'Ookura-Risona curated source missing or not normalized' }
if (-not ($curated | Where-Object { $_.id -eq 'williamw1979-ffxiv' -and $_.url -eq 'https://raw.githubusercontent.com/WilliamW1979/FFXIV/main/repository.json' -and $_.enabledByDefault })) { throw 'WilliamW1979 source missing or unexpectedly disabled' }
if (-not ($curated | Where-Object { $_.id -eq 'movemexiv' -and $_.url -eq 'https://raw.githubusercontent.com/hocng015/MoveMeXiv-Release/master/MoveMeXiv.json' -and $_.enabledByDefault })) { throw 'MoveMeXiv source missing, not normalized, or unexpectedly disabled' }
if (-not ($curated | Where-Object { $_.id -eq 'automarket-pro' -and $_.url -eq 'https://raw.githubusercontent.com/bimilbimil/AutomarketPro/main/repo.json' -and $_.enabledByDefault })) { throw 'AutoMarket Pro curated source missing or unexpectedly disabled' }
if (-not ($curated | Where-Object { $_.id -eq 'aethergel-plugins' -and $_.url -eq 'https://raw.githubusercontent.com/aethergel/plugins/main/repo.json' -and $_.enabledByDefault })) { throw 'aethergel source missing, not normalized, or unexpectedly disabled' }

if (-not ($curated | Where-Object { $_.id -eq 'lightless-sync' -and $_.url -eq 'https://repo.lightless-sync.org/' -and $_.enabledByDefault })) { throw 'Lightless Sync curated source missing or disabled' }
if (-not ($curated | Where-Object { $_.id -eq 'playersync' -and $_.url -eq 'https://playersync.io/download/plugin/repo.json' -and $_.enabledByDefault })) { throw 'PlayerSync curated source missing or disabled' }
if (-not ($curated | Where-Object { $_.id -eq 'xivsync' -and $_.url -eq 'https://raw.githubusercontent.com/xivsync/repo/main/plogonmaster.json' -and $_.enabledByDefault })) { throw 'XIV Sync curated source missing, disabled, or not normalized' }
if (-not ($curated | Where-Object { $_.id -eq 'aetherlove-aetheros' -and $_.url -eq 'https://puni.sh/api/repository/aetherlove' -and $_.enabledByDefault })) { throw 'AetherLove/AetherOS curated source missing or disabled' }
if ($config -notmatch 'Version \{ get; set; \} = 7') { throw 'Configuration schema 7 is missing' }
if ($curatedService -notmatch 'enableAllCuratedMigration' -or $curatedService -notmatch 'source.Enabled = true') { throw 'One-time all-curated-enabled migration is missing' }
if ($curated | Where-Object { $_.url -match 'gp\.xuolu\.com/love\.json' }) { throw 'Unverified gp.xuolu source must not be bundled yet' }
if ($manifestParser -notmatch 'AllowTrailingCommas\s*=\s*true') { throw 'Community JSON trailing-comma tolerance missing' }
if ($manifestParser -notmatch 'JsonCommentHandling\.Skip') { throw 'Community JSON comment tolerance missing' }
if ($repoClient -notmatch 'RepositoryManifestParser\.Parse') { throw 'RepositoryClient must use the tested manifest parser' }
if ($marketplacePlugin -notmatch '"LastUpdate",\s*"LastUpdated"') { throw 'LastUpdated manifest alias missing' }
if ($iconCache -notmatch 'MaximumIconBytes = 4 \* 1024 \* 1024') { throw 'Plugin icon response cap missing' }
if ($iconCache -notmatch 'GetOrQueue') { throw 'Lazy visible-entry icon loading is missing' }
if ($ui -notmatch 'ImGui\.GetClipboardText\(\)') { throw 'API-15 clipboard repair is missing' }


# Executable build-time regression suite.
if ($solution -notmatch 'Omega\.RegressionTests') { throw 'Regression test project is not included in Omega.sln' }
if ($regressionProject -notmatch 'RunOmegaRegressionTests') { throw 'Regression suite is not wired to run after build' }
if ($regressionProject -notmatch 'AfterTargets="Build"') { throw 'Regression suite must run as part of normal build' }
if ($regressionProject -match 'PackageReference') { throw 'Regression runner must remain dependency-free' }
if ($regressionProgram -notmatch 'Omega regression suite') { throw 'Regression runner entry point missing' }
if ($regressionProgram -notmatch 'TestDuplicateVariantRetention') { throw 'Duplicate-source behavioral regression test missing' }
if ($regressionProgram -notmatch 'TestStableApiVariantAggregation') { throw 'Stable API variant aggregation regression test missing' }
if ($regressionProgram -notmatch 'TestManifestParserCommunityTolerance') { throw 'Manifest parser behavioral regression test missing' }
if ($regressionProgram -notmatch 'TestManualReloadContract') { throw 'Reload contract regression test missing' }
if ($regressionProgram -notmatch 'TestCatalogDatabaseRoundTrip') { throw 'Catalog database regression test missing' }
if ($regressionProgram -notmatch 'TestPersistentCatalogContract') { throw 'Persistent catalog regression contract missing' }
if ($regressionProgram -notmatch 'TestDailyUpdateJobContract') { throw 'Daily update job regression contract missing' }
if ($regressionProgram -notmatch 'TestUnmaintainedThreshold') { throw 'Unmaintained threshold regression test missing' }
if ($regressionProject -notmatch 'CatalogDatabase.cs') { throw 'Regression runner must link the production CatalogDatabase implementation' }
if ($regressionProject -notmatch 'CatalogBundleImporter.cs') { throw 'Regression runner must link the production CatalogBundleImporter implementation' }
if ($regressionProgram -notmatch 'TestCatalogBundleImport') { throw 'Prebuilt catalog bundle regression test missing' }
if ($regressionProgram -notmatch 'TestCatalogBuilderContract') { throw 'GitHub catalog builder regression test missing' }
if ($regressionProgram -notmatch 'TestOnlineCatalogFallbackContract') { throw 'Online catalog/local fallback regression test missing' }
if ($regressionProgram -notmatch 'TestOnlineCatalogDescriptorHelpers') { throw 'Online catalog descriptor regression test missing' }

Write-Host "Omega package metadata validation passed: $($zr.version) / $($zr.expected_build_stamp)"

# API-15 system-menu hook typing regression guard.
$systemMenuBridge = Get-Content -Raw (Join-Path $Root 'Omega/Services/DalamudSystemMenuBridge.cs')
if ($systemMenuBridge -notmatch 'HookFromAddress<AgentHUD\.Delegates\.OpenSystemMenu>') { throw 'OpenSystemMenu hook must use the explicit FFXIVClientStructs delegate type' }
if ($systemMenuBridge -notmatch 'HookFromAddress<UIModule\.Delegates\.ExecuteMainCommand>') { throw 'ExecuteMainCommand hook must use the explicit FFXIVClientStructs delegate type' }

# Spotlight/repository-health/source-table regression guards.
if ($curated.Count -lt 136) { throw 'Curated/discovered source catalog unexpectedly shrank below 136 entries' }
if (($curated | Where-Object { -not $_.enabledByDefault }).Count -ne 0) { throw 'All bundled sources should default enabled' }
if ($ui -notmatch 'MarketplaceView\.Spotlight' -or $ui -notmatch '★  Spotlight' -or $ui -notmatch 'DrawSpotlightPage') { throw 'Dedicated Spotlight page/icon contract missing' }
foreach ($promoted in @('HonseFarm.Client','AetherLovePlugin','InventoryTools','GatherBuddyReborn','ChatTwo')) { if ($ui -notmatch [regex]::Escape($promoted)) { throw "Missing Spotlight promotion: $promoted" } }
if ($ui -notmatch 'Take\(5\)') { throw 'Spotlight must remain capped to five highlighted plugins' }
if ($ui -match 'DrawSpotlight\(mainProjection\.Plugins') { throw 'Legacy inline Discover Spotlight must not return' }
if ($ui -notmatch 'omega-repository-filter') { throw 'Direct repository filter missing' }
if ($ui -notmatch 'omega-source-table' -or $ui -notmatch 'source-enabled-') { throw 'Checkbox source table missing' }
if ($ui -notmatch [regex]::Escape('ImGui.BeginTable("omega-source-table", 5, ImGuiTableFlags.None, new Vector2(860f, 360f), 0f)')) { throw 'Source table must use the API-15 BeginTable flags/outer-size/inner-width overload' }
if ($ui -match 'selectedSourceIndex') { throw 'Legacy selectedSourceIndex must not return after source-table migration' }
if ($catalog -notmatch 'GetMainProjection' -or $catalog -notmatch 'RepositoryHealthRules\.BuildStatuses') { throw 'Stale-aware main projection missing' }
$healthRules = Get-Content (Join-Path $root 'Omega/Services/RepositoryHealthRules.cs') -Raw
if ($healthRules -notmatch 'entries\.All' -or $healthRules -notmatch 'IsUnmaintained\(currentApi\)') { throw 'Repository stale-all rule missing' }
if (-not (Test-Path (Join-Path $root 'sources/discovery/dalamud_batch1.json'))) { throw 'Source discovery batch 1 missing' }
if (-not (Test-Path (Join-Path $root 'sources/discovery/dalamud_batch2.json'))) { throw 'Source discovery batch 2 missing' }
if (-not (Test-Path (Join-Path $root 'sources/discovery/dalamud_batch3.json'))) { throw 'Source discovery batch 3 missing' }

# GitHub catalog-builder / downloadable database regression guards.
$catalogWorkflow = Get-Content (Join-Path $root '.github/workflows/catalog-builder.yml') -Raw
$catalogBuilder = Get-Content (Join-Path $root 'tools/catalog/build_catalog.py') -Raw
$catalogDiscovery = Get-Content (Join-Path $root 'tools/catalog/discover_sources.py') -Raw
$knownBad = Get-Content (Join-Path $root 'catalog/known-bad-hashes.json') -Raw | ConvertFrom-Json
$candidates = Get-Content (Join-Path $root 'catalog/candidates.json') -Raw | ConvertFrom-Json
if ($catalogWorkflow -notmatch 'schedule:' -or $catalogWorkflow -notmatch 'catalog-latest' -or $catalogWorkflow -notmatch 'upload-artifact' -or $catalogWorkflow -notmatch 'Download previous catalog database seed' -or $catalogWorkflow -notmatch '--seed-bundle' -or $catalogWorkflow -notmatch 'catalog/dist/catalog.json' -or $catalogWorkflow -notmatch 'catalog/dist/catalog-endpoint.json') { throw 'GitHub catalog-builder publication/seed/descriptor workflow incomplete' }
if ($catalogBuilder -notmatch 'known-bad-git-blob' -or $catalogBuilder -notmatch 'merge_bad_entry' -or $catalogBuilder -notmatch 'omega-catalog-db.zip' -or $catalogBuilder -notmatch 'omega-catalog-db.zip.sha256' -or $catalogBuilder -notmatch 'If-None-Match' -or $catalogBuilder -notmatch 'load_seed_bundle' -or $catalogBuilder -notmatch 'retainedLastKnownGood') { throw 'Catalog builder hash-gating/conditional-seed/bundle contract incomplete' }
if ($catalogDiscovery -notmatch 'search/code' -or $catalogDiscovery -notmatch 'raw.githubusercontent.com') { throw 'GitHub repository discovery contract incomplete' }
if ($knownBad.schemaVersion -ne 1) { throw 'Known-bad hash schema mismatch' }
if ($candidates.count -lt 470) { throw 'Discovery candidate queue lost the uploaded source-batch seed set' }

Write-Host 'Omega package validation passed.'
