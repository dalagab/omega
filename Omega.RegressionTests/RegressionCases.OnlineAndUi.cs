using System.Buffers.Binary;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Dalagab.Omega;

namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestCatalogBuilderContract()
    {
        var workflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "catalog-builder.yml"));
        Contains(workflow, "name: Omega security services · daily catalog launcher", "main keeps only the thin daily catalog launcher");
        Contains(workflow, "cron: \"17 2 * * *\"", "catalog and Definitions launcher remains scheduled once per day");
        Contains(workflow, "workflow_dispatch:", "operators can deliberately request an out-of-cycle daily snapshot");
        False(Regex.IsMatch(workflow, @"(?m)^  push:\s*$"), "ordinary client source pushes do not create client-visible catalog churn");
        Contains(workflow, "uses: dalagab/omega/.github/workflows/catalog-builder.yml@sigmascope", "catalog implementation is delegated to the security-services branch");
        Contains(workflow, "concurrency: ${{ inputs.concurrency || '8' }}", "launcher forwards bounded catalog concurrency");
        Contains(workflow, "timeout: ${{ inputs.timeout || '20' }}", "launcher forwards request timeout");
        Contains(workflow, "website_max_age_hours: ${{ inputs.website_max_age_hours || '168' }}", "launcher forwards website-cache policy");
        Contains(workflow, "allow_source_removal: ${{ inputs.allow_source_removal || false }}", "launcher forwards explicit source-removal approval");
        Contains(workflow, "secrets: inherit", "reusable security-services workflow receives the caller's scoped secrets");
        False(workflow.Contains("production_sigmascope_v2_pipeline.py", StringComparison.Ordinal), "catalog launcher does not directly invoke Sigmascope");
        False(Directory.Exists(Path.Combine(Root, "tools", "catalog")), "client branch does not duplicate catalog-service implementation");
        False(Directory.Exists(Path.Combine(Root, "tools", "security")), "client branch does not duplicate security-service implementation");
    }

    internal static void TestOnlineCatalogFallbackContract()
    {
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "CatalogUpdateCoordinator.cs"));
        Contains(coordinator, "TryApplyOnlineCatalogAsync", "online SQLite catalog is checked first");
        Contains(coordinator, "retaining local Definitions", "network failure retains last-known-good SQLite Definitions");
        False(coordinator.Contains("LocalFallback", StringComparison.Ordinal), "public catalog is not rebuilt by crawling repositories in-game");
        False(coordinator.Contains("await catalog.RefreshAsync(configuration.Repositories)", StringComparison.Ordinal), "central failure does not fan out across public sources");
        Contains(coordinator, "!x.IsCurated", "unmanaged Dalamud sources can remain explicit temporary overlays");

        var store = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "SqliteCatalogStore.cs"));
        Contains(store, "ReplaceFromBundle", "SQLite update replaces one database");
        Contains(store, "omega-catalog.staged-", "replacement is staged before swap");
        Contains(store, "omega-catalog.backup-", "failed swap can restore previous database");
        Contains(store, "PRAGMA integrity_check", "candidate database is validated before activation");
    }

    internal static void TestDalamudDefaultCatalogContract()
    {
        var bridge = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudDefaultCatalogBridge.cs"));
        Contains(bridge, "AvailablePlugins", "default catalogue comes from Dalamud's already-loaded available plugins");
        Contains(bridge, "IsThirdParty", "bridge distinguishes the official repository from third-party repositories");
        Contains(bridge, "SourceIsOfficial = true", "default entries retain official provenance");
        False(bridge.Contains("HttpClient", StringComparison.Ordinal), "reading Dalamud defaults must not create startup network traffic");

        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        Contains(plugin, "RefreshDefaultCatalog()", "default catalogue is merged during construction and when Omega opens");
        Contains(plugin, "defaultCatalogBridge.ReadAvailable()", "Omega reads the current in-memory Dalamud defaults");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "SetDefaultPlugins", "marketplace accepts runtime default plugin metadata");
        Contains(catalog, "databaseVariants", "database variants remain separate from runtime defaults");
        Contains(catalog, "defaultPlugins", "runtime defaults participate in the storefront projection");
        Contains(catalog, "!x.SourceIsOfficial || !runtimeNames.Contains", "runtime official metadata replaces stale cached official duplicates only");

        Contains(catalog, "HasLoaded = databaseVariants.Count > 0", "runtime defaults do not suppress fresh central-catalog seeding");
        False(catalog.Contains("CachedRepositoryCount > 0 || defaultPlugins.Count > 0", StringComparison.Ordinal), "runtime defaults must not masquerade as a complete database");

        using var curated = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "sources", "curated-sources.json")));
        True(curated.RootElement.EnumerateArray().Any(x =>
            x.GetProperty("id").GetString() == "dalamud-official" &&
            x.GetProperty("isOfficial").GetBoolean()), "official source remains bundled and identifiable");
    }

    internal static void TestOnlineCatalogDescriptorHelpers()
    {
        True(OnlineCatalogClient.IsValidSha256(new string('a', 64)), "64 hex characters form a valid SHA-256");
        False(OnlineCatalogClient.IsValidSha256(new string('g', 64)), "non-hex SHA-256 is rejected");
        False(OnlineCatalogClient.IsValidSha256("abc"), "short SHA-256 is rejected");
        True(OnlineCatalogClient.IsValidCatalogRevision("cat-v1-0123456789abcdef"), "legacy Catalog Revision format remains accepted");
        True(OnlineCatalogClient.IsValidCatalogRevision("cat-v2-0123456789abcdef"), "marketplace v2 Catalog Revision format is accepted");
        False(OnlineCatalogClient.IsValidCatalogRevision("cat-v1-not-a-hash"), "malformed legacy Catalog Revision is rejected");
        False(OnlineCatalogClient.IsValidCatalogRevision("cat-v2-not-a-hash"), "malformed v2 Catalog Revision is rejected");
        True(OnlineCatalogClient.IsValidDefinitionsRevision("defs-v1-0123456789abcdef"), "semantic Definitions Revision format is accepted");
        False(OnlineCatalogClient.IsValidDefinitionsRevision("defs-v1-not-a-hash"), "malformed Definitions Revision is rejected");
        True(OnlineCatalogClient.IsValidSecurityRevision("sec-2.0.0-0123456789abcdef"), "semantic Security Revision format is accepted");
        False(OnlineCatalogClient.IsValidSecurityRevision("sec-2.0.0-short"), "malformed Security Revision is rejected");
        True(OnlineCatalogClient.IsValidEvidenceRevision("ev-v1-0123456789abcdef"), "legacy Evidence Revision format remains accepted");
        True(OnlineCatalogClient.IsValidEvidenceRevision("ev-v2-0123456789abcdef"), "Sigmascope Evidence v2 Revision format is accepted");
        False(OnlineCatalogClient.IsValidEvidenceRevision("ev-v1-short"), "malformed Evidence Revision is rejected");
        False(OnlineCatalogClient.IsValidEvidenceRevision("ev-v3-0123456789abcdef"), "unknown Evidence Revision generation is rejected");

        True(OnlineCatalogClient.IsSupportedDescriptorContract(new OnlineCatalogDescriptor
        {
            SchemaVersion = 1,
            Schema = "omega.catalog.sqlite.v1",
            CatalogRevision = "cat-v1-0123456789abcdef",
        }), "legacy descriptor contract remains readable");
        True(OnlineCatalogClient.IsSupportedDescriptorContract(new OnlineCatalogDescriptor
        {
            SchemaVersion = 2,
            Schema = "omega.catalog.marketplace.v2",
            CatalogRevision = "cat-v2-0123456789abcdef",
        }), "marketplace descriptor v2 is accepted");
        False(OnlineCatalogClient.IsSupportedDescriptorContract(new OnlineCatalogDescriptor
        {
            SchemaVersion = 2,
            Schema = "omega.catalog.marketplace.v2",
            CatalogRevision = "cat-v1-0123456789abcdef",
        }), "v2 descriptor cannot advertise a v1 catalog revision");

        var hashes = new OnlineCatalogDescriptor
        {
            CatalogSha256 = new string('a', 64),
            BundleSha256 = new string('b', 64),
        };
        Equal(new string('a', 64), OnlineCatalogClient.EffectiveCatalogSha256(hashes), "database hash drives change detection");
        Equal(new string('b', 64), OnlineCatalogClient.EffectiveBundleSha256(hashes), "ZIP hash authenticates transport bytes");

        var descriptor = new Uri("https://example.invalid/releases/catalog.json");
        Equal("https://example.invalid/releases/omega-marketplace.sqlite.zip",
            OnlineCatalogClient.ResolveDownloadUri(descriptor, "omega-marketplace.sqlite.zip").ToString(),
            "relative SQLite URL resolves against descriptor");
        Throws<InvalidDataException>(
            () => OnlineCatalogClient.ResolveDownloadUri(descriptor, "http://example.invalid/catalog.zip"),
            "non-HTTPS central catalog is rejected");

        var client = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "OnlineCatalogClient.cs"));
        Contains(client, "ProbeAsync", "descriptor-only checks can detect a pending Definitions update without downloading it");
        Contains(client, "OnlineCatalogCheckStatus.UpdateAvailable", "descriptor probe distinguishes pending Definitions from current state");
        Contains(client, "omega.catalog.sqlite.v1", "client retains legacy online descriptor compatibility");
        Contains(client, "omega.catalog.marketplace.v2", "client accepts the post-split marketplace v2 descriptor");
        Contains(client, "cat-v2-", "client recognizes v2 marketplace revisions");
        False(client.Contains("omega.catalog.v1", StringComparison.Ordinal), "legacy JSON bundle schema removed");
    }

    internal static void TestSearchDownloadsAndBehaviorSettingsContract()
    {
        var configuration = File.ReadAllText(Path.Combine(Root, "Omega", "Configuration.cs"));
        Contains(configuration, "MinimizeAsBar", "minimize presentation preference is persisted");
        Contains(configuration, "ShowInSystemMenu", "ESC/System menu visibility preference is persisted");
        Contains(configuration, "ShowInTitleScreenMenu", "pre-login menu visibility preference is persisted");
        Contains(configuration, "SearchEverywhere { get; set; } = true", "global search visibility defaults on");
        Contains(configuration, "DiscoverLayoutMode.Dynamic", "Discover presentation defaults to the existing dynamic screenshot-first view");
        Contains(configuration, "ShowAdvancedSecurityInformation { get; set; } = false", "advanced security details default off");
        Contains(configuration, "TrustUnrecognizedSources", "unrecognized-source trust preference is persisted and defaults off");
        Contains(configuration, "TutorialCompleted", "first-use tutorial completion is persisted");
        Contains(configuration, "WarnOnBotLikeAutomation { get; set; } = true", "bot-like automation warning starts enabled");
        Contains(configuration, "WarnOnCameraControl", "camera-control install preference is persisted");
        Contains(configuration, "WarnOnChatControl", "chat-control install preference is persisted");
        Contains(configuration, "WarnOnMenuControl", "menu-control install preference is persisted");

        var appBar = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.AppBar.cs"));
        Contains(appBar, "search-clear", "global search exposes a clear X control");
        Contains(appBar, "Clear search", "search clear control has an accessible tooltip");
        Contains(appBar, "ImGuiCol.FrameBg", "global search owns a dedicated lighter frame background");
        Contains(appBar, "configuration.SearchEverywhere || activeView == MarketplaceView.Discover", "search can be hidden outside Discover without losing Discover search");
        Contains(appBar, "EffectiveSearchQuery", "hidden global search cannot silently filter non-Discover pages");

        var discover = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Discover.cs"));
        DoesNotContain(discover, "reported downloads / installations", "Discover keeps catalog-wide usage totals out of the header");
        DoesNotContain(discover, "installed here", "Discover keeps local installed totals out of the removed aggregate header");

        var product = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductPage.cs"));
        Contains(product, "Downloads / installations", "product metadata exposes reported usage");

        var settings = ReadMarketplaceWindowSource();
        DoesNotContain(settings, "SettingsSection.Behavior", "Settings no longer has a dedicated Behavior area");
        DoesNotContain(settings, "settings-tab-behavior", "Behavior is removed from the Settings tab bar");
        Contains(settings, "DrawSettingsGeneralTab", "General owns the combined settings surface");
        Contains(settings, "settingsSection = SettingsSection.General", "Settings opens on the lightweight General list instead of repository inventory");
        Contains(settings, "ImGui.Checkbox($\"##settings-{id}\"", "General preferences render as a checkbox list");
        Contains(settings, "Repository reflection and catalog", "opening Settings defers repository work until the Repositories tab is requested");
        DoesNotContain(Capture(settings, @"private void OpenSettings\(\)\s*\{([\s\S]*?)\r?\n    \}"), "RefreshDalamudRepositoryAwareness()", "opening Settings must not synchronously refresh repository awareness");
        Contains(settings, "Minimize Omega as a bar", "General settings expose compact bar minimize mode");
        Contains(settings, "Show Omega in the ESC / System menu", "General settings expose ESC menu visibility");
        Contains(settings, "Show Omega before login", "General settings expose pre-login menu visibility");
        Contains(settings, "Search everywhere", "General settings expose the global-search visibility toggle");
        Contains(settings, "Discover layout", "General settings expose the Discover presentation selector");
        Contains(settings, "Compact cards", "Discover presentation selector includes icon-only compact cards");
        Contains(settings, "One row per plugin", "Discover presentation selector includes a dense list mode");
        Contains(settings, "omega-settings-general-scroll", "General settings scroll so install permissions cannot be clipped below the modal");
        Contains(settings, "ImGuiWindowFlags.AlwaysVerticalScrollbar", "General settings visibly expose their vertical scroll path");
        Contains(settings, "Advanced security information", "General settings expose the detailed security toggle");
        Contains(settings, "Leave this off for the simpler view", "General explains the simple security mode without developer jargon");
        Contains(settings, "Source trust", "General settings separates source identity trust from plugin capability preferences");
        Contains(settings, "Trust unrecognized sources", "General exposes the opt-in unrecognized-source trust preference");
        Contains(settings, "Skip only the extra source acknowledgement", "source trust explains that protection/reporting remains active");
        Contains(settings, "Install permissions", "General settings expose install permission preferences");
        Contains(settings, "Warn about gameplay automation", "General exposes the bot-like automation permission preference");
        Contains(settings, "Warn about camera control", "General exposes the camera permission preference");
        Contains(settings, "Warn about chat control", "General exposes the chat permission preference");
        Contains(settings, "Warn about menu control", "General exposes the menu permission preference");
        Contains(settings, "Show tutorial again", "General can replay the first-use tour");
        Contains(settings, "DrawMinimizedBar", "minimized bar presentation is implemented");

        var tutorial = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Tutorial.cs"));
        Contains(tutorial, "Welcome to Omega", "first-use tour introduces Omega");
        Contains(tutorial, "plus some of the latest additions", "Spotlight tour copy focuses on discovery and new additions rather than security");
        Contains(tutorial, "new(\"sidebar-view-Discover\", \"Discover\"", "Discover has its own highlighted tour step instead of borrowing the Filters control");
        Contains(tutorial, "browse the full Omega catalog", "Discover tour explains the full catalog in user-facing language");
        Contains(tutorial, "new(\"filters\", \"Filters\"", "Filters have their own highlighted tour step");
        Contains(tutorial, "project page, and help links", "Discover tour points users to community and help information");
        Contains(tutorial, "The changelog is there to give you more details without needing you to go to each individual plugin", "Updates tour explains the changelog as a convenience view");
        Contains(tutorial, "What do the little flags mean?", "first-use tour explains ribbon symbols");
        Contains(tutorial, "Question mark", "ribbon tutorial includes the unresolved/not-yet-known icon");
        Contains(tutorial, "What the finding colour means", "ribbon tutorial explains finding colours separately from status colours");
        Contains(tutorial, "Omega is built to help you make informed decisions", "permission tour frames Omega around informed user decisions");
        Contains(tutorial, "Omega will warn you before installing it", "permission tour explains the comfort-level install warning in plain language");
        Contains(tutorial, "omega-tutorial-scroll-body", "tutorial content scrolls instead of clipping long steps");
        Contains(tutorial, "ImGuiWindowFlags.AlwaysVerticalScrollbar", "tutorial exposes a visible vertical scrollbar for long explanations");
        Contains(tutorial, "filtersOpen = tutorialStep == 3", "the dedicated Filters step opens the filter panel after the Discover step");
        Contains(tutorial, "tutorialRibbonLegendReviewed", "the flag guide tracks whether the user reached the bottom");
        Contains(tutorial, "GetScrollMaxY", "the flag guide checks the actual scroll extent before allowing progression");
        Contains(tutorial, "Scroll to the bottom of the flag guide to continue", "the flag guide tells the user why Next is disabled");
        Contains(tutorial, "ImGui.BeginDisabled(!canAdvance)", "Next stays disabled until the required flag-guide scroll is completed");
        Contains(tutorial, "Thank you for trusting Omega", "the final tour page thanks the user for trusting Omega");
        Contains(tutorial, "safe searching", "the final tour page closes with a friendly safe-searching send-off");
        Contains(tutorial, "Should I worry?", "first-use tour gives a plain-language safety explanation");
        Contains(tutorial, "Choose your install permissions", "first-use tour includes permission choices");
        Contains(tutorial, "DrawTutorialHighlight", "tour highlights the relevant live Omega controls");
        Contains(tutorial, "RememberTutorialTarget", "tour follows actual UI control geometry rather than hard-coded screen coordinates");

        var sigmascope = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Sigmascope.cs"));
        Contains(sigmascope, "if (!configuration.ShowAdvancedSecurityInformation)", "product security has a compact mode");
        Contains(sigmascope, "DrawCompactProductSigmascope", "compact security is rendered as badges rather than detailed sections");
        Contains(sigmascope, "ResolveSimpleSigmascopeVisual", "compact security owns a plain-language visual model");
        Contains(sigmascope, "Not checked yet", "compact security avoids analysis jargon for missing results");
        Contains(sigmascope, "Checking now", "compact security uses simple progress language");
        Contains(sigmascope, "Very serious", "compact critical results use ELI5 severity wording");
        Contains(sigmascope, "Nothing found", "compact clean results use ELI5 wording");
        Contains(sigmascope, "Known problem", "compact dependency-risk wording avoids OSV jargon");
        Contains(sigmascope, "PlainLanguageFindingTitle", "compact hover details translate common finding types to plain language");
        Contains(sigmascope, "Can connect to the internet", "compact finding translation includes simple network wording");
        Contains(sigmascope, "BuildCompactFindingTooltip", "compact finding badges expose findings on hover");
        Contains(sigmascope, "if (configuration.ShowAdvancedSecurityInformation)", "hero review coverage is hidden with advanced security details");

        var ribbons = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Ribbons.cs"));
        Contains(ribbons, "ResolveSimpleSigmascopeVisual", "ribbon tooltips also use simple language when advanced security is off");
        Contains(ribbons, "This plugin does not support your current Dalamud version", "unsupported ribbon tooltip stays understandable without API jargon in simple mode");

        var librarySecurity = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.LibrarySigmascope.cs"));
        Contains(librarySecurity, "BuildSimpleEnvironmentSigmascopeIssueLine", "installed security view has simple-mode issue summaries");
        Contains(librarySecurity, "Omega matched this exact installed plugin file", "installed security identity is expressed plainly in simple mode");

        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        Contains(plugin, "ApplyBehaviorConfiguration", "title-screen visibility changes apply immediately");
        Contains(plugin, "Configuration.Version < 14", "configuration migration retains the schema 14 compact-security migration");
        Contains(plugin, "Configuration.ShowAdvancedSecurityInformation = false", "schema 14 applies the compact security default once to existing clients");
        Contains(plugin, "Configuration.Version < 15", "configuration migration advances clients to the tutorial/permission schema");
        Contains(plugin, "Configuration.Version < 16", "configuration migration advances clients to the Discover-layout schema");
        Contains(plugin, "Configuration.DiscoverLayout = DiscoverLayoutMode.Dynamic", "schema 16 preserves the existing dynamic Discover layout on upgrade");
        Contains(plugin, "Configuration.Version < 17", "configuration migration advances clients to the source-trust schema");
        Contains(plugin, "Configuration.TrustUnrecognizedSources = false", "schema 17 keeps unrecognized-source trust opt-in by default");
        Contains(plugin, "Configuration.WarnOnBotLikeAutomation = true", "schema 15 applies the bot-like automation warning default");
        Contains(plugin, "Configuration.TutorialCompleted = false", "schema 15 shows the first-use tour once after upgrade");
        Contains(plugin, "Configuration.ShowInSystemMenu", "system-menu bridge reads the live preference");

        var systemMenu = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudSystemMenuBridge.cs"));
        Contains(systemMenu, "Func<bool> isEnabled", "ESC menu injection is dynamically gated");
        Contains(systemMenu, "if (!isEnabled())", "disabled ESC integration falls through to the original menu");
    }

    internal static void TestPopularityAndUpdateFailureUiContract()
    {
        var popularity = MarketplacePopularityRules.Build(Enumerable.Range(0, 20).Select(index => new MarketplacePlugin
        {
            InternalName = $"Popularity{index}",
            Name = $"Popularity {index}",
            DownloadCount = index == 0 ? 400 : index == 1 ? 600 : 0,
        }));
        Equal(20, popularity.PluginCount, "popularity denominator counts logical plugins");
        Equal(1000L, popularity.TotalDownloads, "popularity numerator uses total reported downloads");
        Equal(50d, popularity.AverageDownloads, "catalog average is total downloads divided by logical plugin count");
        Equal(8d, popularity.MultipleFor(400), "400 downloads is eight times a 50-download catalog average");
        Equal(12d, popularity.HighestMultiple, "600 downloads is the catalog popularity leader at twelve times average");
        Equal(100d, popularity.RelativePercentFor(600), "the most popular plugin defines 100 percent");
        Equal(400d / 600d * 100d, popularity.RelativePercentFor(400), "other plugins are positioned relative to the popularity leader");
        var leaderScale = new MarketplacePopularitySnapshot(20, 2950, 147.5d, 59d);
        Equal(6d / 59d * 100d, leaderScale.RelativePercentFor(885), "a six-times-average plugin lands at roughly ten percent when the leader is fifty-nine times average");
        var originalCulture = System.Globalization.CultureInfo.CurrentCulture;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo("nl-NL");
            Equal("8.00×", MarketplacePopularityRules.FormatMultiple(8d), "popularity multiple remains directly readable under a comma-decimal locale");
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = originalCulture;
        }

        var discover = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Discover.cs"));
        DoesNotContain(discover, "average / plugin", "Discover no longer exposes catalog-wide popularity statistics");
        DoesNotContain(discover, "reported downloads / installations", "Discover keeps aggregate download totals out of the header");

        var cacheUi = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Cache.cs"));
        Contains(cacheUi, "MarketplaceSort.Downloads => \"Popularity\"", "download ordering is presented as normalized popularity");

        var product = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductPage.cs"));
        Contains(product, "DrawProductPopularityMetadataRow", "product pages expose normalized popularity beside raw downloads");
        Contains(product, "Retry update", "product action becomes an explicit retry after a failed update");
        Contains(product, "DrawProductUpdateFailure", "product pages surface the last structured update failure");

        var popularityUi = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Popularity.cs"));
        Contains(popularityUi, "DrawPopularityBar", "product popularity is rendered as a leader-relative bar");
        Contains(popularityUi, "RelativePercentFor", "product popularity is positioned against the most popular plugin");
        Contains(popularityUi, "MarketplacePopularityRules.FormatPercent", "product popularity exposes its leader-relative percentage");
        Contains(popularityUi, "MarketplacePopularityRules.Describe", "popularity tooltip explains the hidden calculation without cluttering Discover");
        Contains(popularityUi, "catalog.GetDailyPopularitySnapshot", "UI popularity uses the stable daily database snapshot");

        var catalogService = ReadMarketplaceCatalogServiceSource();
        Contains(catalogService, "GetDailyPopularitySnapshot", "catalog service exposes one stable daily popularity baseline");
        Contains(catalogService, "allDatabaseVariants", "popularity excludes runtime overlays and user source filters");

        var installer = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudInstallerBridge.cs"));
        Contains(installer, "UpdateFailureKind.Download", "Dalamud download failures retain a structured failure category");
        Contains(installer, "faileddownload", "Dalamud FailedDownload status is translated explicitly");
        Contains(installer, "Your installed v", "download failure copy makes it clear the installed version was kept");
        Contains(installer, "Task<string> UpdateThroughDalamudInternalsAsync", "Dalamud update status is preserved instead of thrown away");
        DoesNotContain(installer, "throw new InvalidOperationException($\"Dalamud update returned", "known Dalamud update statuses are no longer flattened into an exception");

        var updateUi = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Update.cs"));
        Contains(updateUi, "SetUpdateFailure(updatingInternalName", "failed updates are captured through the persistent per-plugin diagnostic path");
        Contains(updateUi, "RestorePersistedUpdateFailures", "failed update diagnostics survive Omega restarts");
        Contains(updateUi, "configuration.UpdateFailures", "failed update diagnostics are stored in plugin configuration");
        Contains(updateUi, "FailureTargetVersion", "saved update failures are bound to the version that actually failed");
        Contains(updateUi, "IsUpdateFailureApplicable", "stale failure diagnostics are discarded when a different target update replaces them");
        Contains(updateUi, "Dismiss##update-failure-dismiss", "users can explicitly dismiss a persisted update diagnostic");
        Contains(updateUi, "Open repository##update-failure-open", "failed-update diagnostics can open the repository for recovery context");
        Contains(updateUi, "Update needs attention", "product failure panel has clear user-facing status");
        Contains(updateUi, "Dalamud status:", "failure details preserve the underlying Dalamud status code");

        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));
        Contains(library, "previousFailure.Message", "Updates rows display the plugin-specific failure inline");
        Contains(library, "Retry this update through Dalamud", "Updates rows explain that the action is now a retry");
    }

    internal static void TestRuntimeOverlaySecurityProjectionContract()
    {
        const string official = "https://kamori.goats.dev/Plugin/PluginMaster";
        var database = new MarketplacePlugin
        {
            InternalName = "AbsoluteRoleplay",
            Name = "Absolute Roleplay",
            AssemblyVersionText = "0.0.4.4",
            SourceName = "Dalamud official",
            SourceUrl = official,
            SourceIsOfficial = true,
            SecurityStatus = "complete",
            SecurityScannedAtUtcText = "2026-08-20T08:19:31Z",
            SecurityArtifactSha256 = new string('a', 64),
            SigmascopeVersion = "2.9.0",
            SecurityHighestSeverity = "high",
            SecurityCautionCount = 27,
            SecurityHighCount = 1,
            SecurityFindings = [new MarketplaceSecurityFinding { RuleId = "rule.high", Severity = "high", Title = "Test finding", Description = "Evidence" }],
            SecurityAutomationLevel = "ui-automation",
            SecurityReviewCoverageLabel = "Artifact only",
        };
        var live = new MarketplacePlugin
        {
            InternalName = "AbsoluteRoleplay",
            Name = "Absolute Roleplay",
            AssemblyVersionText = "0.0.4.4",
            SourceName = "Dalamud official",
            SourceUrl = official,
            SourceIsOfficial = true,
            DownloadCount = 99999,
        };

        True(live.CanInheritSecurityProjectionFrom(database), "same official plugin/version may inherit the database security projection");
        live.ApplySecurityProjectionFrom(database);
        True(live.HasCompletedSecurityScan, "live official manifest retains completed Sigmascope status");
        Equal("high", live.SecurityHighestSeverity, "live official manifest retains the projected severity");
        Equal(27, live.SecurityCautionCount, "live official manifest retains finding counts");
        Equal(1, live.SecurityHighCount, "live official manifest retains high finding count");
        Equal(1, live.SecurityFindings.Count, "live official manifest retains detailed projected findings");
        Equal(99999L, live.DownloadCount, "runtime manifest continues to own fresh runtime metadata");

        var newer = new MarketplacePlugin
        {
            InternalName = "AbsoluteRoleplay",
            AssemblyVersionText = "0.0.4.5",
            SourceUrl = official,
            SourceIsOfficial = true,
        };
        False(newer.CanInheritSecurityProjectionFrom(database), "a newer package version must never inherit an older scan");

        var otherSource = new MarketplacePlugin
        {
            InternalName = "AbsoluteRoleplay",
            AssemblyVersionText = "0.0.4.4",
            SourceUrl = "https://example.invalid/PluginMaster.json",
            SourceIsOfficial = false,
        };
        False(otherSource.CanInheritSecurityProjectionFrom(database), "community/source identity cannot inherit official evidence by name/version alone");

        live.ApplySecurityProjectionFrom(null);
        False(live.HasCompletedSecurityScan, "rebuilds clear inherited security when no matching database evidence remains");
        Equal("none", live.SecurityHighestSeverity, "clearing inherited evidence restores a neutral security state");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "MergeDatabaseSecurityLocked", "catalog projection explicitly merges server security into live runtime manifests");
        Contains(catalog, "pair.Value.Select(MergeDatabaseSecurityLocked)", "unmanaged live overlays retain exact-version database security");
        Contains(catalog, "defaultPlugins.Select(MergeDatabaseSecurityLocked)", "Dalamud official runtime manifests retain exact-version database security");
        Contains(catalog, "runtimePlugin.ApplySecurityProjectionFrom(null)", "projection is cleared before each re-evaluation to prevent stale carry-over");
    }

    internal static void TestDefinitionsUpdateUiContract()
    {
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "CatalogUpdateCoordinator.cs"));
        Contains(coordinator, "DefinitionsUpdateAvailable", "coordinator exposes a pending Definitions update state");
        Contains(coordinator, "AvailableCatalogSha256", "pending Definitions identity is persisted separately from the applied hash");
        Contains(coordinator, "CheckForUpdatesAsync", "Definitions can be checked without applying them");
        Contains(coordinator, "ApplyDefinitionsUpdateAsync", "pending Definitions can be explicitly applied");
        Contains(coordinator, "onlineClient.ProbeAsync", "normal update checks only fetch the descriptor");

        var temp = Path.Combine(Path.GetTempPath(), "omega-definitions-state-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var store = new OnlineCatalogStateStore(temp);
            store.Save(new OnlineCatalogState
            {
                DescriptorUrl = "https://example.invalid/catalog.json",
                CatalogSha256 = new string('a', 64),
                AvailableCatalogSha256 = new string('b', 64),
                AvailableCatalogRevision = "cat-v1-0123456789abcdef",
                AvailableDefinitionsRevision = "defs-v1-fedcba9876543210",
            });
            var loaded = store.Load();
            Equal(new string('b', 64), loaded.AvailableCatalogSha256, "pending Definitions hash survives restart state round-trip");
            Equal("cat-v1-0123456789abcdef", loaded.AvailableCatalogRevision, "pending Catalog revision survives restart state round-trip");
            Equal("defs-v1-fedcba9876543210", loaded.AvailableDefinitionsRevision, "pending Definitions revision survives restart state round-trip");
        }
        finally
        {
            if (Directory.Exists(temp)) Directory.Delete(temp, true);
        }

        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "definitions-update-row", "Updates page advertises pending Definitions inside the update list");
        Contains(ui, "Update Omega Definitions", "Updates page exposes the explicit Definitions apply action");
        Contains(ui, "##omega-about-version", "version footer is the About entry point");
        Contains(ui, "(versionAvailable - versionButtonSize.X) * 0.5f", "version footer is centered in the application rail");
        Contains(ui, "About Omega", "version footer opens the product-focused About popup");
        Contains(ui, "Every plugin. One orbit.", "About uses the Omega product tagline");
        Contains(ui, "DrawAboutVersionAndDefinitions", "About shows a concise Version row and explanatory Definitions information");
        Contains(ui, "catalog.DefinitionsRevision", "About and Downloads prefer the actual frozen Definitions revision over the catalog revision");
        Contains(ui, "catalog.DatabaseSizeBytes", "About shows the loaded Definitions database size beside its revision");
        Contains(ui, "FormatDefinitionsDatabaseSize", "Definitions database size uses a bounded human-readable formatter");
        Contains(ui, "Check for updates", "Settings starts with an update check action");
        Contains(ui, "View EULA", "Settings labels the agreement simply as EULA");
        False(ui.Contains("View EULA / Risk Disclosure", StringComparison.Ordinal), "Settings does not relabel EULA as a risk disclosure");
        False(ui.Contains("Catalog identity", StringComparison.Ordinal), "catalog identity is removed from Settings");
        False(ui.Contains("[Curated (", StringComparison.Ordinal), "Curated source tab has no decorative brackets");
    }

    internal static void TestLiveCatalogEndpointContract()
    {
        using var endpoint = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "catalog", "catalog-endpoint.json")));
        Equal(1, endpoint.RootElement.GetProperty("schemaVersion").GetInt32(), "live endpoint schema");
        Equal("https://github.com/dalagab/omega/releases/download/catalog-latest/catalog.json",
            endpoint.RootElement.GetProperty("descriptorUrl").GetString(), "live production descriptor URL");

        var catalogLauncher = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "catalog-builder.yml"));
        Contains(catalogLauncher, "uses: dalagab/omega/.github/workflows/catalog-builder.yml@sigmascope", "daily catalog work is delegated to the security-services branch");
        False(catalogLauncher.Contains("production_sigmascope_v2_pipeline.py", StringComparison.Ordinal), "catalog launcher never directly starts a security scan");

        var sigmascopeLauncher = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "sigmascope.yml"));
        Contains(sigmascopeLauncher, "uses: dalagab/omega/.github/workflows/sigmascope.yml@sigmascope", "continuous evidence scanning is delegated independently to the security-services branch");
        False(sigmascopeLauncher.Contains("catalog-builder.yml@sigmascope", StringComparison.Ordinal), "Sigmascope launcher cannot masquerade as catalog publication");
        False(sigmascopeLauncher.Contains("gh release upload catalog-latest", StringComparison.Ordinal), "thin scanner launcher never publishes the client database itself");

        var online = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "OnlineCatalogClient.cs"));
        Contains(online, "CatalogSha256", "client verifies published marketplace database bytes");
        Contains(online, "BundleSha256", "client verifies published marketplace ZIP bytes");
        Contains(online, "CatalogRevision", "client validates the published Catalog Revision contract");
        Contains(online, "DefinitionsRevision", "client retains frozen Definitions identity from the descriptor");
        Contains(online, "SecurityRevision", "client retains compiled Security Revision identity");
        Contains(online, "EvidenceRevision", "client retains source Evidence Revision identity without downloading detailed evidence");
    }

    internal static void TestStorefrontVirtualization()
    {
        var first = StorefrontVirtualization.Calculate(
            itemCount: 727,
            columns: 5,
            rowHeight: 210f,
            scrollY: 0f,
            viewportHeight: 700f,
            contentStartY: 60f,
            bufferRows: 1);
        Equal(146, first.TotalRows, "727 plugins at five columns produce 146 rows");
        Equal(0, first.FirstRow, "top of storefront starts at first row");
        True(first.LastRowExclusive <= 5, "top viewport submits only a bounded row window");

        var middle = StorefrontVirtualization.Calculate(
            itemCount: 727,
            columns: 5,
            rowHeight: 210f,
            scrollY: 8400f,
            viewportHeight: 700f,
            contentStartY: 60f,
            bufferRows: 1);
        True(middle.FirstRow > 30, "deep scroll skips preceding rows");
        True(middle.LastRowExclusive - middle.FirstRow <= 7, "deep scroll still submits only visible rows plus buffer");
    }

    internal static void TestOpenWindowPerformanceGuards()
    {
        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "DrawDiscoverHybridResults", "Discover must keep the enhanced-card and fallback-list hybrid path");
        Contains(ui, "StorefrontVirtualization.Calculate", "virtualization helper must drive visible rows");
        Contains(ui, "stableIdCache", "ImGui IDs must not SHA-256 the same strings every frame");
        Contains(ui, "GetFilteredPlugins", "filter/sort results must be cached between UI frames");
        Contains(ui, "GetTopCategories", "category aggregation must be cached between UI frames");
        Contains(ui, "GetSidebarCounts", "sidebar catalog metrics must be cached between UI frames");
        Contains(ui, "configuredSourceByUrl", "source readiness must use an indexed configuration lookup");
        False(ui.Contains("appIconTexture", StringComparison.Ordinal), "removed header logo must not keep a cached UI texture");
        Contains(ui, "fallbackIconTexture", "fallback shared texture must be cached");
        False(ui.Contains("Plugin.TextureProvider.GetFromFile(fallbackIconPath).GetWrapOrDefault()", StringComparison.Ordinal),
            "fallback GetFromFile must not run for every tile on every frame");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "variantsByInternalName", "variant lookups must use an index");
        Contains(catalog, "repositoryStatusCache", "repository health must not be rebuilt every frame");
        Contains(catalog, "mainProjectionCache", "stale/source projection must be cached");
        Contains(catalog, "mainVariantIndexCache", "installability lookups must not rescan the marketplace");
        Contains(catalog, "loadedRepositoryUrlSet", "configured-source check must avoid sorting all sources every frame");
        Contains(catalog, "public long Revision", "UI caches need a deterministic catalog invalidation revision");

        var icons = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginIconCache.cs"));
        Contains(icons, "MaximumConcurrentIconLoads = 2", "image downloads/decodes must be bounded");
        Contains(icons, "loadGate.WaitAsync", "icon load concurrency gate must be active");
        Contains(icons, "PluginImageCacheStore", "artwork must reuse persistent local image bytes between sessions");
    }

    internal static void TestMarketplaceTagRules()
    {
        var variants = new[]
        {
            new MarketplacePlugin
            {
                Name = "Alpha",
                InternalName = "Alpha",
                Tags = ["utility", "combat", "UI"],
            },
            new MarketplacePlugin
            {
                Name = "Alpha mirror",
                InternalName = "Alpha",
                Tags = ["Utility", "chat", "ui"],
            },
            new MarketplacePlugin
            {
                Name = "Beta",
                InternalName = "Beta",
                Tags = ["UTILITY", "chat"],
            },
            new MarketplacePlugin
            {
                Name = "Gamma",
                InternalName = "Gamma",
                Tags = ["gpose"],
            },
        };

        var index = MarketplaceTagRules.Build(variants);
        Equal(5, index.Tags.Count, "case-insensitive tag count");

        var utility = index.Tags.Single(x => x.Name.Equals("utility", StringComparison.OrdinalIgnoreCase));
        Equal("utility", utility.Name, "lowercase spelling is preferred when present");
        Equal(2, utility.PluginCount, "duplicate repository variants count once per plugin");

        True(index.MatchesAll("Alpha", ["utility", "chat"]), "Alpha has both required tags across variants");
        False(index.MatchesAll("Beta", ["utility", "combat"]), "AND matching rejects a plugin missing one tag");
        True(index.MatchesAll("Gamma", []), "empty tag selection matches every plugin");
    }

    internal static void TestSearchableTagPickerContract()
    {
        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "Narrow by tag", "tag picker uses Steam-like narrowing language");
        Contains(ui, "##omega-tag-search", "tag picker has searchable input");
        Contains(ui, "all selected tags must match", "multi-tag semantics are explicit AND matching");
        Contains(ui, "Multiple authors use AND matching", "multi-author filters use AND matching too");
        Contains(ui, "OmegaWebsiteReadmeExcerpt", "global search includes README enrichment text");
        Contains(ui, "selected-filter-", "selected filters remain visible as removable pills");
        Contains(ui, "Take(needle.Length == 0 ? 120 : 250)", "tag popup draw work is bounded");
        Contains(ui, "catalog.GetTagIndex(currentApi, selectedSource)", "tag index respects repository filtering");

        var catalog = ReadMarketplaceCatalogServiceSource();
        Contains(catalog, "tagIndexCache", "tag aggregation is cached outside the draw loop");
        Contains(catalog, "MarketplaceTagRules.Build", "production catalog builds the shared tag index helper");

        var project = File.ReadAllText(Path.Combine(Root, "Omega.RegressionTests", "Omega.RegressionTests.csproj"));
        Contains(project, "MarketplaceTagRules.cs", "tag behavior helper is exercised by the build-time regression suite");
    }


    internal static void TestReadmeMarkupRenderingContract()
    {
        var blocks = MarketplaceReadmeMarkup.Parse("# Heading\n<p>Hello <strong>world</strong></p>\n- One\n<blockquote>Quoted</blockquote>\n<pre><code>DoThing();</code></pre><script>evil()</script>");
        True(blocks.Any(x => x.Kind == MarketplaceReadmeBlockKind.Heading && x.Text == "Heading"), "Markdown heading becomes a heading block");
        True(blocks.Any(x => x.Kind == MarketplaceReadmeBlockKind.Bullet && x.Text == "One"), "Markdown list becomes a bullet block");
        True(blocks.Any(x => x.Kind == MarketplaceReadmeBlockKind.Quote && x.Text.Contains("Quoted", StringComparison.Ordinal)), "HTML blockquote becomes a quote block");
        True(blocks.Any(x => x.Kind == MarketplaceReadmeBlockKind.Code && x.Text.Contains("DoThing();", StringComparison.Ordinal)), "HTML pre/code becomes a code block");
        False(blocks.Any(x => x.Text.Contains("evil()", StringComparison.Ordinal)), "script contents are removed rather than rendered");

        var inline = MarketplaceReadmeMarkup.ToInlineText("&lt;p&gt;Questionable&lt;br&gt;&lt;strong&gt;updated&lt;/strong&gt;&lt;/p&gt;");
        Equal("Questionable updated", inline, "entity-encoded manifest HTML is decoded before tag interpretation");
        False(inline.Contains('<'), "inline plugin metadata cannot expose raw HTML tags");
    }

    internal static void TestConciseUiLanguageAndPluginMarkupContract()
    {
        var security = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Sigmascope.cs"));
        var about = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Security.cs"));
        var collections = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Collections.cs"));
        var product = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductPage.cs"));
        var productContent = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductContent.cs"));
        var readmeUi = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductReadme.cs"));
        var presentation = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "MarketplacePresentationRules.cs"));
        var markup = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "MarketplaceReadmeMarkup.cs"));

        DoesNotContain(about, "Sigmascope is Omega's online scanning engine", "About does not explain scanner implementation to users");
        DoesNotContain(about, "Definitions also carry Omega's plugin listings", "About avoids Definitions implementation prose");
        DoesNotContain(collections, "Collections use a folder-style view", "Collections page opens directly on the functional UI");
        DoesNotContain(productContent, "Commands, controls and usage information collected", "usage section does not narrate its data pipeline");
        DoesNotContain(readmeUi, "Fetched from the project's public repository", "README section does not narrate its ingestion pipeline");
        Contains(security, "Findings come from static analysis. No findings is not a safety guarantee.", "security keeps only the concise safety qualifier");

        Contains(product, "DrawMarketplaceMarkupText(description", "plugin descriptions render through the shared rich-text layer");
        Contains(productContent, "DrawMarketplaceMarkupText(entry.Changelog", "plugin changelogs render through the shared rich-text layer");
        Contains(presentation, "MarketplaceReadmeMarkup.ToInlineText(plugin.Punchline)", "card and hero summaries normalize plugin-provided markup");
        Contains(markup, "WebUtility.HtmlDecode(text)", "HTML entities are decoded before markup interpretation");
        Contains(markup, "DangerousHtmlBlockRegex().Replace", "active embedded HTML remains stripped after decoding");
        DoesNotContain(productContent, "ImGui.TextWrapped(entry.Changelog)", "raw changelog HTML is never sent directly to ImGui");
    }

}
