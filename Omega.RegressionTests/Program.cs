using System.Buffers.Binary;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Dalagab.Omega;
using static Dalagab.Omega.RegressionTests.RegressionCases;

var root = args.Length > 0
    ? Path.GetFullPath(args[0])
    : FindRepositoryRoot(AppContext.BaseDirectory);

var tests = new (string Name, Action Body)[]
{
    ("manifest parser accepts community JSON variants", TestManifestParserCommunityTolerance),
    ("manifest parser accepts wrapper objects", TestManifestParserWrappers),
    ("official presentation wins when available, rich community presentation fills gaps", TestPresentationRichnessSelection),
    ("manifest parser rejects unsupported root shapes", TestManifestParserRejectsInvalidShape),
    ("manifest parser skips entries without plugin identity", TestManifestParserSkipsInvalidEntries),
    ("stable API compatibility is preserved", TestStableApiCompatibility),
    ("testing API compatibility is opt-in", TestTestingApiCompatibility),
    ("Omega API range compatibility is preserved", TestOmegaApiRangeCompatibility),
    ("unmaintained threshold is three API levels", TestUnmaintainedThreshold),
    ("repository stale rule hides only fully unmaintained repositories", TestRepositoryStaleRule),
    ("duplicate repository variants remain available", TestDuplicateVariantRetention),
    ("stable API badge aggregates repository variants", TestStableApiVariantAggregation),
    ("official source wins storefront projection", TestOfficialVariantWinsProjection),
    ("highest community version wins without official source", TestHighestCommunityVersionWinsProjection),
    ("hidden variants stay out of the storefront", TestHiddenVariantFiltering),
    ("curated source catalog invariants", TestCuratedSources),
    ("SQLite bootstrap exposes catalog variants and source definitions", TestCatalogDatabaseRoundTrip),
    ("pre-security SQLite catalogs remain readable", TestLegacyCatalogWithoutSecurityProjection),
    ("SQLite bundle replacement contract stays strict", TestCatalogBundleImport),
    ("persistent catalog and conditional refresh contract", TestPersistentCatalogContract),
    ("daily update job remains conditional and cache-first", TestDailyUpdateJobContract),
    ("curated all-enabled migration remains one-time", TestCuratedEnableMigration),
    ("release version metadata stays synchronized", TestVersionMetadataSynchronization),
    ("pre-login manifest requirements stay enabled", TestPreLoginManifest),
    ("title icon remains 64x64 PNG", TestTitleIcon),
    ("API-15 native menu hook typing stays explicit", TestSystemMenuHookTyping),
    ("startup network access remains user-triggered", TestManualReloadContract),
    ("storefront regression guards stay intact", TestStorefrontContract),
    ("spotlight and repository filtering remain visible", TestSpotlightAndRepositoryFilter),
    ("Settings source manager remains a checkbox table with stale status", TestSourceTableContract),
    ("GitHub catalog builder remains reproducible and hash-gated", TestCatalogBuilderContract),
    ("online SQLite catalog retains last-known-good local database on failure", TestOnlineCatalogFallbackContract),
    ("Dalamud default plugins remain part of the Omega marketplace", TestDalamudDefaultCatalogContract),
    ("Dalamud collections remain folder-based and Dalamud-owned", TestDalamudCollectionsContract),
    ("marketplace list and collection geometry stays aligned", TestMarketplaceLayoutGeometryContract),
    ("store navigation keeps installed state under Library and grouping under filters", TestStoreLibraryNavigationContract),
    ("installed plugin snapshots tolerate transient null version state", TestInstalledSnapshotNullSafetyContract),
    ("Library and details artwork remain clean app/plugin images", TestCleanDetailsArtworkContract),
    ("Discover uses Store-style results and product pages", TestDiscoverStoreListContract),
    ("Discover exposes risk, installed, unavailable, and Dalamud-official status visually", TestDiscoverRiskOwnershipAndAvailabilityContract),
    ("plugin icons open details and screenshots open a larger viewer", TestPluginArtworkAndScreenshotInteractionContract),
    ("secondary Omega panels share the main application chrome", TestSecondaryPanelChromeContract),
    ("online catalog descriptor helpers remain strict", TestOnlineCatalogDescriptorHelpers),
    ("Definitions updates stay pending until applied and About owns identity", TestDefinitionsUpdateUiContract),
    ("live catalog endpoint and publication smoke test remain wired", TestLiveCatalogEndpointContract),
    ("storefront virtualization bounds open-window draw work", TestStorefrontVirtualization),
    ("open-window performance guards remain cached", TestOpenWindowPerformanceGuards),
    ("marketplace artwork persists in a bounded local SQLite cache", TestPersistentMarketplaceImageCache),
    ("marketplace tags normalize duplicates and use AND matching", TestMarketplaceTagRules),
    ("Steam-style searchable tag picker remains wired", TestSearchableTagPickerContract),
    ("artwork actions remain aligned Font Awesome icon overlays", TestArtworkIconOverlayContract),
    ("marketplace chrome keeps controls in their owning panels", TestMarketplaceChromeOwnershipContract),
    ("expanded marketplace enforces only a minimum usable size", TestMarketplaceMinimumWindowSizeContract),
    ("first-run catalog acquisition stays automatic and visually quiet", TestCatalogFirstRunLoadingContract),
    ("first-use EULA and Settings retrieval remain enforced", TestEulaFirstUseContract),
    ("GitHub distribution and repository-only installation remain documented", TestGitHubDistributionDocumentationContract),
    ("GitHub release and security workflows remain publishable and visible", TestGitHubReleaseAndSecurityWorkflowsContract),
    ("third-party plugin security scanning remains static, incremental, and catalog-backed", TestPluginSecurityIntelligenceContract),
    ("security-enriched catalog compaction preserves history and runtime projection", TestCatalogCompactionWorkflowContract),
    ("install always chooses a repository and delegates to Dalamud", TestInstallRepositoryChooserContract),
    ("plugin selections, project navigation, uninstall, and update badge stay canonical", TestCanonicalPluginNavigationAndLifecycleContract),
    ("repository HTTP response lifetime stays explicit and stream-bounded", TestRepositoryClientResponseLifetimeContract),
    ("regression runner remains wired into Omega.sln", TestRegressionBuildWiring),
};

Dalagab.Omega.RegressionTests.RegressionCases.Root = root;

var failures = new List<string>();
Console.WriteLine($"Omega regression suite: {tests.Length} tests");
Console.WriteLine($"Repository root: {root}");

foreach (var (name, body) in tests)
{
    try
    {
        body();
        Console.WriteLine($"PASS  {name}");
    }
    catch (Exception ex)
    {
        failures.Add($"{name}: {ex.Message}");
        Console.Error.WriteLine($"FAIL  {name}: {ex.Message}");
    }
}

if (failures.Count == 0)
{
    Console.WriteLine($"Omega regression suite passed: {tests.Length}/{tests.Length}");
    return 0;
}

Console.Error.WriteLine($"Omega regression suite FAILED: {failures.Count}/{tests.Length}");
foreach (var failure in failures)
    Console.Error.WriteLine($" - {failure}");
return 1;

