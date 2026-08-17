$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$required = @(
  'Omega.sln',
  'Omega/DalagabOmega.csproj',
  'Omega/Plugin.cs',
  'Omega/BuildInfo.cs',
  'Omega/DalagabOmega.json',
  'Omega/Services/SqliteCatalogStore.cs',
  'Omega/Services/MarketplaceCatalogService.cs',
  'Omega/Services/MarketplaceCatalogService.Refresh.cs',
  'Omega/Services/CatalogUpdateCoordinator.cs',
  'Omega/Services/OnlineCatalogClient.cs',
  'Omega/UI/MarketplaceWindow.Discover.cs',
  'Omega/UI/MarketplaceWindow.ProductPage.cs',
  'Omega/UI/MarketplaceWindow.UninstallAndSources.cs',
  'Omega/UI/MarketplaceWindow.Spotlight.cs',
  'Omega/UI/MarketplaceWindow.Sources.cs',
  'Omega.RegressionTests/Omega.RegressionTests.csproj',
  'Omega.RegressionTests/RegressionCases.PluginNavigationLifecycle.cs',
  '.github/workflows/catalog-builder.yml',
  'tools/catalog/collect_sources.py',
  'tools/catalog/enrich_metadata.py',
  'tools/catalog/scrape_websites.py',
  'tools/catalog/scrape_websites_incremental.py',
  'tools/catalog/build_sqlite_catalog.py',
  'tools/catalog/test_sqlite_catalog.py',
  'catalog/catalog-endpoint.json',
  'catalog/bootstrap/omega-catalog.sqlite.zip',
  'sources/curated-sources.json',
  'README.md',
  'EULA.md',
  'installer/Install-OmegaRepository.ps1',
  'repository/pluginmaster.json',
  'omega.zr',
  'BUILD_STAMP.txt'
)
foreach ($relative in $required) {
  if (-not (Test-Path (Join-Path $root $relative))) { throw "Missing required file: $relative" }
}

$expectedVersion = '0.8.1.13'
$expectedStamp = 'omega-filter-height-regression-contract-repair-20260814'
$zr = Get-Content (Join-Path $root 'omega.zr') -Raw | ConvertFrom-Json
if ($zr.version -ne $expectedVersion) { throw 'omega.zr version mismatch' }
if ($zr.expected_build_stamp -ne $expectedStamp) { throw 'omega.zr build stamp mismatch' }
if ((Get-Content (Join-Path $root 'BUILD_STAMP.txt') -Raw).Trim() -ne $expectedStamp) { throw 'BUILD_STAMP mismatch' }

$project = Get-Content (Join-Path $root 'Omega/DalagabOmega.csproj') -Raw
if ($project -notmatch [regex]::Escape("<Version>$expectedVersion</Version>")) { throw 'Project version mismatch' }
if ($project -notmatch 'Microsoft.Data.Sqlite.Core' -or $project -notmatch 'SQLitePCLRaw.provider.winsqlite3') { throw 'SQLite package references missing' }
if ($project -notmatch 'omega-catalog\.sqlite\.zip') { throw 'SQLite bootstrap packaging missing' }

$buildInfo = Get-Content (Join-Path $root 'Omega/BuildInfo.cs') -Raw
if ($buildInfo -notmatch [regex]::Escape($expectedVersion) -or $buildInfo -notmatch [regex]::Escape($expectedStamp)) { throw 'BuildInfo mismatch' }

$store = Get-Content (Join-Path $root 'Omega/Services/SqliteCatalogStore.cs') -Raw
if ($store -notmatch 'PRAGMA integrity_check' -or $store -notmatch 'runtime_plugin_variants' -or $store -notmatch 'ReplaceFromBundle' -or $store -notmatch 'Pooling = false') { throw 'SQLite runtime store incomplete' }
if ($store -match 'CatalogDatabaseRecord') { throw 'Legacy per-source database type returned' }

$coordinator = Get-Content (Join-Path $root 'Omega/Services/CatalogUpdateCoordinator.cs') -Raw
if ($coordinator -match 'LocalFallback') { throw 'Legacy client-side public catalog fallback returned' }
if ($coordinator -notmatch 'retaining local database') { throw 'Last-known-good SQLite fallback missing' }

$online = Get-Content (Join-Path $root 'Omega/Services/OnlineCatalogClient.cs') -Raw
if ($online -notmatch 'omega\.catalog\.sqlite\.v1' -or $online -match 'omega\.catalog\.v1') { throw 'Online descriptor schema mismatch' }


$storefrontUi = Get-Content (Join-Path $root 'Omega/UI/MarketplaceWindow.Storefront.cs') -Raw
$filtersUi = Get-Content (Join-Path $root 'Omega/UI/MarketplaceWindow.Filters.cs') -Raw
$discoverUi = Get-Content (Join-Path $root 'Omega/UI/MarketplaceWindow.Discover.cs') -Raw
$chromeUi = Get-Content (Join-Path $root 'Omega/UI/MarketplaceWindow.Chrome.cs') -Raw
if ($storefrontUi -notmatch 'filtersOpen = !filtersOpen' -or $storefrontUi -notmatch 'DrawInlineMarketplaceFilters') { throw 'Collapsed inline filter contract missing' }
if ($storefrontUi -notmatch 'triangle = filtersOpen' -or $storefrontUi -notmatch 'FrameRounding, 4f') { throw 'Square Filters toggle with open-state triangle missing' }
if ($filtersUi -notmatch 'omega-inline-filters' -or $filtersUi -notmatch 'omega-inline-filter-grid') { throw 'Expanded filter panel contract missing' }
if ($filtersUi -notmatch 'MarketplaceView.Discover or MarketplaceView.Library' -or $filtersUi -notmatch 'ChildRounding, 4f') { throw 'Discover/Library expanded filter panel geometry contract missing' }
if ($discoverUi -notmatch 'TextUnformatted\("Featured"\)' -or $discoverUi -notmatch 'TextUnformatted\("The rest"\)' -or $discoverUi -notmatch 'const float gridStartX = 0f') { throw 'Discover section naming/alignment contract missing' }
if ($discoverUi -notmatch 'var cardMin = ImGui.GetWindowPos\(\)' -or $discoverUi -notmatch 'cardMax - new Vector2\(0\.5f, 0\.5f\)') { throw 'Discover hover alignment contract missing' }
if ($chromeUi -notmatch 'notificationCount: counts\.Updates' -or $chromeUi -notmatch 'badgeHeight = 15f' -or $chromeUi -notmatch '99\+') { throw 'Compact Updates counter badge contract missing' }
if ($discoverUi -notmatch 'queueIfVisible: true' -or $discoverUi -notmatch 'showOverlays: false') { throw 'Visible Discover plugin icon loading contract missing' }
if ($chromeUi -notmatch 'MinimumSize = DefaultExpandedWindowSize' -or $chromeUi -notmatch 'MaximumSize = new Vector2\(float.MaxValue\)' -or $chromeUi -notmatch 'SizeConstraints = null') { throw 'Minimum marketplace window-size contract missing' }
if ($chromeUi -match 'ImGui.SetNextWindowSize\(viewport.Size' -or $chromeUi -match 'ImGui.SetNextWindowPos\(viewport.Pos') { throw 'Forced full-screen viewport sizing returned' }
if ($chromeUi -notmatch 'migrateLegacyFullscreenGeometry' -or $chromeUi -notmatch 'SizeCondition = ImGuiCond.Always' -or $chromeUi -notmatch 'PositionCondition = ImGuiCond.Always') { throw 'Legacy full-screen geometry migration missing' }
if ($chromeUi -notmatch 'using Dalamud.Interface.Utility;' -or $chromeUi -notmatch 'ImGuiHelpers.GlobalScale') { throw 'Geometry migration ImGuiHelpers import missing' }
if ($chromeUi -notmatch 'Size = null' -or $chromeUi -notmatch 'Position = null') { throw 'Window geometry migration does not return ownership to the user' }
$windowUi = Get-Content (Join-Path $root 'Omega/UI/MarketplaceWindow.cs') -Raw
if ($windowUi -notmatch 'activeView is MarketplaceView.Library or MarketplaceView.Updates') { throw 'Redundant Discover content header returned' }
$configUi = Get-Content (Join-Path $root 'Omega/Configuration.cs') -Raw
if ($configUi -notmatch 'WindowGeometryRevision') { throw 'Window geometry migration revision marker missing' }


$spotlightUi = Get-Content (Join-Path $root 'Omega/UI/MarketplaceWindow.Spotlight.cs') -Raw
$shelvesUi = Get-Content (Join-Path $root 'Omega/UI/MarketplaceWindow.SpotlightShelves.cs') -Raw
if ($spotlightUi -notmatch 'contentStartY \+ 112f' -or $spotlightUi -notmatch 'contentStartY \+ 166f' -or $spotlightUi -notmatch 'contentStartY \+ 178f') { throw 'Spotlight fixed alignment anchors missing' }
if ($spotlightUi -match 'DrawSpotlightActionRow' -or $spotlightUi -match 'spotlight-install-' -or $spotlightUi -match 'DrawSpotlightInfoButton') { throw 'Spotlight duplicate action controls returned' }
if ($spotlightUi -notmatch 'OpenSpotlightPluginInDiscover\(plugin\)' -or $shelvesUi -notmatch 'OpenSpotlightPluginInDiscover\(plugin\)') { throw 'Spotlight whole-card Discover navigation missing' }

$libraryUi = Get-Content (Join-Path $root 'Omega/UI/MarketplaceWindow.Library.cs') -Raw
$productUi = Get-Content (Join-Path $root 'Omega/UI/MarketplaceWindow.ProductPage.cs') -Raw
$detailsUi = Get-Content (Join-Path $root 'Omega/UI/MarketplaceWindow.Details.cs') -Raw
if ($libraryUi -notmatch 'rowHeight = 88f' -or $libraryUi -notmatch 'BuildAuthorSourceLine' -or $libraryUi -notmatch '→ v\{offered\}' -or $libraryUi -notmatch 'FontAwesomeIcon.SyncAlt') { throw 'Library/Updates compact metadata/update-icon contract missing' }
if ($detailsUi -notmatch 'ApplyLibraryRuntimeFilter' -or $libraryUi -notmatch 'DrawInlineLibraryRuntimeField') { throw 'Library Discover-equivalent filter contract missing' }
if ($productUi -notmatch 'GetAvailableUpdateVersion' -or $productUi -notmatch 'DrawProductActionButton\("Update"' -or $productUi -notmatch 'PluginInstallerOpenKind.UpdateablePlugins') { throw 'Discover product-page Update action contract missing' }
if ($windowUi -notmatch 'new\(980f, 800f\)') { throw 'Marketplace minimum height contract missing' }

$repositoryClient = Get-Content (Join-Path $root 'Omega/Services/RepositoryClient.cs') -Raw
if ($repositoryClient -notmatch 'using var response = await httpClient\.SendAsync' -or $repositoryClient -notmatch 'HttpCompletionOption\.ResponseHeadersRead') { throw 'Repository HTTP response lifetime contract missing' }

$workflow = Get-Content (Join-Path $root '.github/workflows/catalog-builder.yml') -Raw
foreach ($needle in @('collect_sources.py','enrich_metadata.py','scrape_websites_incremental.py','build_sqlite_catalog.py','test_sqlite_catalog.py','--seed-database','omega-catalog.sqlite.zip','PRAGMA integrity_check','catalog-latest')) {
  if ($workflow -notmatch [regex]::Escape($needle)) { throw "SQLite workflow missing: $needle" }
}

$builder = Get-Content (Join-Path $root 'tools/catalog/build_sqlite_catalog.py') -Raw
foreach ($needle in @('plugin_variants','websites','presentation','plugin_search','raw_manifest_json','VACUUM','omega.catalog.sqlite.v1')) {
  if ($builder -notmatch [regex]::Escape($needle)) { throw "SQLite builder missing: $needle" }
}

$legacyFiles = @('Omega/Services/CatalogDatabase.cs','Omega/Services/CatalogBundleImporter.cs')
foreach ($relative in $legacyFiles) {
  $path = Join-Path $root $relative
  if (-not (Test-Path $path)) { continue }
  $legacyText = Get-Content $path -Raw
  if ($legacyText -match 'class\s+CatalogDatabase' -or $legacyText -match 'class\s+CatalogBundleImporter') {
    throw "Legacy runtime catalog implementation returned: $relative"
  }
}

$sourceFiles = Get-ChildItem (Join-Path $root 'Omega') -Filter '*.cs' -Recurse
$sourceFiles += Get-ChildItem (Join-Path $root 'Omega.RegressionTests') -Filter '*.cs' -Recurse
foreach ($file in $sourceFiles) {
  $lineCount = (Get-Content $file.FullName).Count
  if ($lineCount -gt 400) { throw "C# source exceeds 400 lines: $($file.FullName) ($lineCount)" }
}

Write-Host "Omega package validation passed: $expectedVersion / $expectedStamp / SQLite catalog v1 + Spotlight navigation/alignment + Discover-equivalent Library filters + compact Library/Updates rows + product Update state + 980x800 minimum window + Discover layout/filter alignment + visible icon loading + update counter UI"
