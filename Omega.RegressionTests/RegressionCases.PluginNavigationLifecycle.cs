namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestPreferredPackageUpdateChronology()
    {
        var sameSource = new MarketplacePlugin
        {
            AssemblyVersionText = "2.1.1.2",
            SourceUrl = "https://example.invalid/repo.json",
            LastUpdate = 1_786_000_000,
        };
        True(
            PluginUpdateRules.IsUpdateCandidate(
                new Version(2, 1, 1, 1),
                "https://example.invalid/repo.json",
                1_785_000_000,
                sameSource,
                useTesting: false),
            "same-source monotonic versions remain ordinary updates");

        True(
            PluginUpdateRules.IsSamePublishingSource(
                "OFFICIAL",
                "https://kamori.goats.dev/Plugin/PluginMaster",
                candidateOfficial: true),
            "Dalamud's OFFICIAL installed-source sentinel remains the same publishing lineage as the live official catalog URL");

        var apiShapedOlderMirror = new MarketplacePlugin
        {
            AssemblyVersionText = "15.0.0.0",
            SourceUrl = "https://mirror.invalid/repository.json",
            LastUpdate = 1_770_000_000,
        };
        False(
            PluginUpdateRules.IsUpdateCandidate(
                new Version(0, 2, 2, 8),
                "https://preferred.invalid/repository.json",
                1_780_000_000,
                apiShapedOlderMirror,
                useTesting: false),
            "a numerically larger cross-source version is not newer when its release chronology is older");

        var undatedCrossSource = new MarketplacePlugin
        {
            AssemblyVersionText = "15.0.0.0",
            SourceUrl = "https://mirror.invalid/repository.json",
            LastUpdate = 0,
        };
        False(
            PluginUpdateRules.IsUpdateCandidate(
                new Version(0, 2, 2, 8),
                "https://preferred.invalid/repository.json",
                0,
                undatedCrossSource,
                useTesting: false),
            "cross-source assembly versions are not comparable when release chronology is unknown");

        var datedNewerCrossSource = new MarketplacePlugin
        {
            AssemblyVersionText = "3.0.0.0",
            SourceUrl = "https://preferred.invalid/repository.json",
            LastUpdate = 1_790_000_000,
        };
        True(
            PluginUpdateRules.IsUpdateCandidate(
                new Version(2, 9, 9, 9),
                "https://old-source.invalid/repository.json",
                1_780_000_000,
                datedNewerCrossSource,
                useTesting: false),
            "a cross-source preferred package is an update when both version and chronology are newer");

        var lowerVersionNewerDate = new MarketplacePlugin
        {
            AssemblyVersionText = "0.1.0.0",
            SourceUrl = "https://preferred.invalid/repository.json",
            LastUpdate = 1_790_000_000,
        };
        False(
            PluginUpdateRules.IsUpdateCandidate(
                new Version(0, 2, 2, 8),
                "https://old-source.invalid/repository.json",
                1_780_000_000,
                lowerVersionNewerDate,
                useTesting: false),
            "release date alone does not turn a lower assembly version into an update Dalamud cannot apply normally");

        var details = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Details.cs"));
        var packages = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.SourcePackages.cs"));
        Contains(details, "var candidates = GetInstallCandidates(internalName, currentApi, currentDalamudVersion)", "Updates consider every enabled compatible package instead of only the first repository");
        Contains(details, "PluginUpdateRules.IsUpdateCandidate", "Updates use chronology-aware cross-source comparison");
        Contains(details, "var sameSource = valid", "ordinary same-repository updates remain preferred over repository migration");
        Contains(details, "OrderByDescending(x => PluginUpdateRules.NormalizeUnix(x.Candidate.LastUpdate))", "when the installed repository stops publishing, the newest chronologically proven repository migration is selected");
        Contains(details, "the UI asks the user before moving repositories", "cross-repository update candidates remain explicit user-approved migrations");
        Contains(details, "installedPlugin.Manifest.LastUpdate", "installed release chronology comes from Dalamud's persisted local manifest when available");
        DoesNotContain(details, "foreach (var variant in catalog.GetMainVariants(internalName, currentApi))", "Updates no longer pick the numerically largest version from arbitrary repositories");
        Contains(packages, ".OrderByDescending(x => x.Identity.Equals(preferredIdentity", "the green preferred package is listed before historical package lines");
        Contains(packages, ".ThenByDescending(x => x.ReleaseUnix)", "non-preferred packages use manifest chronology instead of assembly-version magnitude for display order");
        Contains(packages, "Published/updated:", "package details expose the available manifest chronology to the user");
    }

    internal static void TestCanonicalPluginNavigationAndLifecycleContract()
    {
        var artwork = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Artwork.cs"));
        var discover = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Discover.cs"));
        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));
        var spotlight = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Spotlight.cs"));
        var collections = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Collections.cs"));
        var details = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Details.cs"));
        var product = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductPage.cs"));
        var popups = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.UninstallAndSources.cs"));
        var headerLinks = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductHeaderLinks.cs"));
        var chrome = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Chrome.cs"));
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginInstallCoordinator.cs"));
        var installer = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudInstallerBridge.cs"));
        var update = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Update.cs"));
        var pluginEntry = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));

        Contains(pluginEntry, "CommandName = \"/omega\"", "Omega keeps the canonical /omega command");
        Contains(pluginEntry, "CommandAlias = \"/omg\"", "Omega registers /omg as a compact alias");
        Contains(pluginEntry, "CommandManager.AddHandler(CommandAlias", "the /omg alias is registered with Dalamud's command manager");
        Contains(pluginEntry, "CommandManager.RemoveHandler(CommandAlias)", "the /omg alias is removed cleanly on plugin disposal");
        Contains(artwork, "activeView = MarketplaceView.Discover", "canonical plugin selection always enters Discover");
        Contains(artwork, "selectedVariantSource.Remove(plugin.InternalName)", "a fresh plugin selection clears stale repository overrides");
        Contains(artwork, "RepositoryProviderRules.SecurityBaselinePriority", "fresh product navigation uses the stable-provider package baseline ranking");
        DoesNotContain(artwork, ".Where(x => x.SourceIsOfficial)", "fresh product navigation no longer hard-codes an official-only metadata preference");
        Contains(artwork, "selectedPlugin = ResolveDefaultVariant(plugin)", "fresh plugin selection starts from the canonical default repository variant");
        Contains(product, "ResolveProductBaselineVariant(selectedPlugin, currentApi, currentDalamudVersion)", "product-page rendering stays anchored to the preferred stable package baseline");
        Contains(discover, "OpenPluginDetails(plugin)", "Discover selections use canonical product navigation");
        Contains(library, "OpenPluginDetails(plugin)", "Library and Updates selections use canonical product navigation");
        Contains(spotlight, "OpenPluginDetails(plugin)", "Spotlight selections use canonical product navigation");
        Contains(collections, "OpenPluginDetails(plugin)", "Collection selections use canonical product navigation");

        Contains(details, "Process.Start(new ProcessStartInfo(projectUrl) { UseShellExecute = true })", "legacy Project action opens the system browser");
        Contains(headerLinks, "BuildProductProjectLinks", "Discover product header builds bounded classified project actions");
        Contains(headerLinks, "ProjectLinkLabel", "classified project actions expose stable user-facing labels");
        Contains(headerLinks, "Join Discord", "Discord project metadata is exposed as a dedicated action");
        Contains(headerLinks, "Documentation", "documentation project metadata is exposed as a dedicated action");
        Contains(headerLinks, "IsSafeProjectActionUrl", "project actions remain restricted to safe HTTPS URLs");
        Contains(headerLinks, "OpenProductWebsite", "classified project actions open through the system browser");
        DoesNotContain(headerLinks, "FontAwesomeIcon.Globe", "obsolete single-globe project navigation is not reintroduced");
        var appBar = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.AppBar.cs"));
        Contains(appBar, "DrawProductBackButton(searchX)", "product-page back navigation lives on the same application-bar row as search");
        Contains(appBar, "const string label = \"Omega\"", "the application bar keeps the text Omega mark");
        Contains(appBar, "omegaDotCenter", "the Omega wordmark places a red core inside its first O");
        Contains(appBar, "0.88f, 0.16f, 0.20f", "the Omega core mark is visibly red");
        DoesNotContain(appBar, "AddImage(texture.Handle", "the application bar no longer renders the Omega logo in the top-left");
        DoesNotContain(product, "FontAwesomeIcon.ArrowLeft", "the product body no longer renders a detached back arrow below search");
        False(details.Contains("Copy source", StringComparison.Ordinal), "Copy source is not exposed as a product/detail action");
        False(popups.Contains("Known sources###DalagabOmegaKnownSources", StringComparison.Ordinal), "obsolete source-copy popup is removed");

        Contains(product, "GetAvailableUpdateVersion", "Discover product pages detect newer compatible installed-plugin versions");
        Contains(product, "OpenUpdateOrMigration", "installed Discover products execute Omega's selected update lifecycle instead of only opening Dalamud's installer page");
        DoesNotContain(product, "OpenPluginInstallerTo(PluginInstallerOpenKind.UpdateablePlugins", "product Update no longer stops at the passive Dalamud update list");
        Contains(library, "OpenUpdateOrMigration", "Updates rows execute the selected update lifecycle directly");
        DoesNotContain(library, "OpenPluginInstallerTo(PluginInstallerOpenKind.UpdateablePlugins", "Updates rows no longer stop at the passive Dalamud update list");
        Contains(coordinator, "installer.UpdateAsync", "update coordinator delegates the final replacement to Dalamud");
        Contains(coordinator, "EnsureRepositoryReadyAsync", "updates prepare a migrated destination repository before delegating to Dalamud");
        Contains(installer, "UpdateSinglePluginAsync", "Omega invokes Dalamud's actual single-plugin update lifecycle");
        Contains(installer, "AvailablePluginUpdate", "Omega constructs Dalamud update metadata for the selected repository package");
        Contains(installer, "CreateRemoteManifest", "install and update share the same repository-backed manifest construction");
        Contains(update, "Plugin moved repository", "repository migrations are explained in a dedicated confirmation panel");
        Contains(update, "Migrate & update", "repository migrations require an explicit user action");
        Contains(update, "The old repository is not removed", "migration assistance does not break other plugins that may still use the old source");
        Contains(update, "CompareRepositorySecurity", "migration confirmation surfaces package/security differences between old and new repositories");
        Contains(product, "OpenUninstallConfirmation(plugin)", "installed product pages expose uninstall");
        Contains(popups, "Uninstall plugin###DalagabOmegaUninstall", "uninstall is explicitly confirmed");
        Contains(coordinator, "installer.UninstallAsync", "uninstall coordinator delegates lifecycle work");
        Contains(installer, "pluginInterface.InternalName", "uninstall blocks Omega self-removal");
        Contains(installer, "exposed.IsDev", "uninstall protects dev plugins");
        Contains(installer, "UnloadAsync", "loaded plugins are unloaded through Dalamud first");
        Contains(installer, "ScheduleDeletion", "Dalamud deletion scheduling is used");
        Contains(installer, "RemovePlugin", "Dalamud installed-plugin manager remains removal authority");

        Contains(chrome, "notificationCount: counts.Updates", "Updates badge receives the actual pending-update count");
        Contains(chrome, "notificationCount > 99 ? \"99+\" : notificationCount.ToString()", "Updates badge remains compact while preserving useful counts");
        Contains(chrome, "const float badgeHeight = 15f", "Updates badge stays compact on the icon rail");
        Contains(chrome, "0.50f, 0.10f, 0.13f, 0.94f", "Updates counter uses a subdued red rather than alarm-bright red");
        Contains(discover, "queueIfVisible: true", "visible Discover cards queue their real plugin icons");
        Contains(discover, "showOverlays: false", "Discover card identity icons remain clean and overlay-free");
        Contains(discover, "var cardMin = ImGui.GetWindowPos();", "rich Discover hover outline anchors to the child window rather than padded content");
        Contains(discover, "cardMax - new Vector2(0.5f, 0.5f)", "rich Discover hover outline remains aligned to the card bounds");
        Contains(discover, "var rowMin = ImGui.GetWindowPos();", "fallback Discover hover outline anchors to the row child window rather than its padded content cursor");
        Contains(discover, "var rowMax = rowMin + ImGui.GetWindowSize();", "fallback Discover hover outline uses the actual row bounds");
        Contains(discover, "rowMax - new Vector2(0.5f, 0.5f)", "fallback Discover hover outline remains fully inside the child clip rectangle");
        False(discover.Contains("AddRect(start, start + new Vector2(ImGui.GetWindowSize().X - 1f, DiscoverListRowHeight - 1f)", StringComparison.Ordinal), "fallback Discover hover outline must not mix a padded content origin with full child-window dimensions");
    }

    internal static void TestLibraryInstallMetadataConfigActionsContract()
    {
        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));
        var ledger = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginLibraryLedger.cs"));
        var backups = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginConfigBackupService.cs"));
        var pluginEntry = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        var sources = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Sources.cs"));

        Contains(library, "BuildLibraryInstallDateLine", "Library rows expose user-local install timing metadata");
        Contains(library, "installedPlugin.HasConfigUi", "Library checks Dalamud's exposed config-UI capability");
        Contains(library, "installedPlugin.OpenConfigUi()", "Library opens plugin settings through Dalamud's public exposed-plugin API");
        Contains(library, "FontAwesomeIcon.FileArchive", "Library exposes config backup as a compact icon action");
        Contains(library, "configBackups.Backup", "Library delegates backup creation to the bounded config backup service");
        Contains(ledger, "library-metadata.json", "install timing stays in a user-local Omega ledger");
        Contains(ledger, "InstalledAtUtc", "the ledger distinguishes observed installation time from first-seen time");
        Contains(ledger, "ExactInstallTime", "Library can label legacy first-seen dates without pretending they are exact install dates");
        Contains(backups, "Path.Combine(pluginConfigRoot, $\"{internalName}.json\")", "config backup includes Dalamud's canonical per-plugin JSON file");
        Contains(backups, "Path.Combine(pluginConfigRoot, internalName)", "config backup includes the plugin's auxiliary config directory");
        Contains(backups, "ZipFile.Open", "plugin configuration backups are packaged as portable ZIP archives");
        Contains(backups, "omega-backup.json", "portable backups carry an explicit Omega plugin identity manifest");
        Contains(backups, "MaximumUncompressedBytes", "config import rejects oversized archive expansion");
        Contains(backups, "Inspect(string archivePath", "config backups are validated before restore");
        Contains(backups, "Restore(string archivePath", "validated config backups can be imported again");
        Contains(backups, "Path.GetTempPath()", "config backups are temporary rather than persistent Omega state");
        Contains(library, "Import config backup", "Library exposes config restore at the top-level Library controls");
        Contains(library, "OpenFileDialog", "Library uses Dalamud's in-game file picker for backup import");
        Contains(library, "configBackups.Inspect", "selected backup ZIPs are validated before confirmation");
        Contains(library, "configBackups.Restore", "confirmed imports delegate to the bounded restore service");
        Contains(library, "RevealBackupInExplorer", "successful config backups immediately reveal the generated archive");
        DoesNotContain(library, "new ProcessStartInfo(\"explorer.exe\"", "backup reveal must not hard-code Windows Explorer under Wine/Proton");
        Contains(library, "UseShellExecute = true", "backup reveal delegates folder opening to the host shell association");
        Contains(pluginEntry, "PluginInterface.ActivePluginsChanged += OnActivePluginsChanged", "Omega observes plugin lifecycle changes even when the Library is closed");
        Contains(pluginEntry, "PluginInterface.ActivePluginsChanged -= OnActivePluginsChanged", "plugin lifecycle tracking unsubscribes cleanly");
        Contains(sources, "libraryLedger.MarkInstalled(installingInternalName)", "successful Omega installs record an exact local install timestamp");
    }

    internal static void TestLibrarySecurityEnvironmentAndReturnNavigationContract()
    {
        var window = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.cs"));
        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));
        var security = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.LibrarySecurity.cs"));
        var artwork = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Artwork.cs"));
        var appBar = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.AppBar.cs"));

        Contains(window, "Security,", "Library owns a dedicated installed-environment security section");
        Contains(library, "library-tab-security", "Library exposes the security scan as an in-panel destination");
        Contains(security, "Installed environment", "security scan summarizes the current installed environment");
        Contains(security, "ResolveInstalledSecurityVariant", "environment scan matches installed plugins to repository-specific scan results");
        Contains(security, "installedPlugin.Manifest.InstalledFromUrl", "third-party environment scans prefer the actual installed repository URL");
        Contains(security, "Security scan not yet available", "installed plugins without evidence remain visible rather than disappearing");
        Contains(security, "BuildEnvironmentPluginIdentityLine", "Library security rows describe the plugin identity backing each scan without user-facing artifact terminology");
        Contains(security, "scan shared by", "identical package hashes disclose when one canonical scan is shared by mirrors");
        Contains(security, "DrawSecurityDisclaimerPanel", "Library security begins with the prominent static-analysis warning panel");
        Contains(security, "Plugin identity not yet published", "Library security uses plugin terminology for the identity line");
        DoesNotContain(security, "Artifact identity not yet published", "Library security no longer labels the plugin as an artifact");
        var securityVisual = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.PluginSecurity.cs"));
        Contains(securityVisual, "SecuritySeverityRank", "Library security posture uses an explicit shared severity ordering helper");
        Contains(securityVisual, "\"critical\" => 4", "Library security severity ordering keeps critical above lower findings");
        Contains(security, "OpenPluginDetails(entry.SecurityVariant)", "environment scan rows remain actionable into the product security page");
        Contains(artwork, "detailsReturnView = activeView", "opening a product remembers the originating marketplace surface");
        Contains(artwork, "detailsReturnLibrarySection = librarySection", "opening from Library remembers the exact Library section");
        Contains(appBar, "activeView = detailsReturnView", "product Back returns to the original marketplace surface");
        Contains(appBar, "librarySection = detailsReturnLibrarySection", "product Back restores Library instead of incorrectly landing in Discover");
    }

    internal static void TestUpdatePersistenceSelfCheckAndRailAttentionContract()
    {
        var chrome = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Chrome.cs"));
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "CatalogUpdateCoordinator.cs"));
        var state = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "OnlineCatalogClient.cs"));
        var selfUpdate = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "OmegaSelfUpdateService.cs"));
        var config = File.ReadAllText(Path.Combine(Root, "Omega", "Configuration.cs"));

        Contains(state, "AvailableCatalogSha256", "pending Definitions hash is persisted outside the in-memory coordinator");
        Contains(state, "AvailableCatalogRevision", "pending Definitions revision is persisted across game restarts");
        Contains(coordinator, "state.AvailableCatalogSha256", "coordinator rehydrates pending Definitions state at startup");
        Contains(chrome, "definitionsAttention: updates.DefinitionsUpdateAvailable", "Downloads rail receives a dedicated Definitions attention state");
        Contains(chrome, "0.12f, 0.48f, 0.86f", "Definitions attention marker is blue");
        Contains(chrome, "var mark = \"!\"", "Definitions attention marker contains an exclamation point");
        Contains(selfUpdate, "CheckInterval = TimeSpan.FromHours(6)", "Omega application updates are checked on an interval");
        Contains(selfUpdate, "RepositoryManifestUrl", "application update checks use Omega's public Dalamud repository manifest");
        Contains(selfUpdate, "MaximumManifestBytes", "application update checks bound remote manifest size");
        Contains(config, "LastApplicationUpdateCheckUtc", "application update cadence survives restarts");
        Contains(config, "AvailableApplicationVersion", "detected Omega application update state survives restarts");
        Contains(chrome, "Open Dalamud updates", "Omega application updates remain delegated to Dalamud");
        Contains(chrome, "ShouldDrawOperationStatus", "top-level operation status has an explicit transient/error policy");
        Contains(chrome, "message.Contains(\"failed\"", "completed success messages do not remain as a permanent status line");
    }

    internal static void TestRepositorySecurityDifferencePresentationContract()
    {
        var comparison = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.SourceSecurityComparison.cs"));
        var packages = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.SourcePackages.cs"));
        var install = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Install.cs"));

        Contains(comparison, "CompareRepositorySecurity", "repository packages compare their exact security reports across sources");
        Contains(comparison, "sameKnownArtifact", "identical artifact hashes are treated as one canonical package identity");
        Contains(comparison, "Definitions integrity anomaly", "same-hash security disagreement is treated as Definitions corruption rather than a repository risk difference");
        Contains(comparison, "differentKnownArtifact", "packages whose hashes differ from the preferred baseline are explicitly flagged");
        Contains(comparison, "SecurityArtifactSha256", "source divergence can explain differing scanned package artifacts");
        Contains(comparison, "FontAwesomeIcon.ExclamationTriangle", "worse source reports receive an explicit warning icon");
        Contains(packages, "repository.SecurityComparison.Worse", "worse repository lines receive dedicated source-list styling");
        Contains(packages, "0.94f, 0.28f, 0.26f", "worse repository source lines are red");
        Contains(packages, "DrawRepositorySecurityDifferenceIndicator", "source list shows the report-difference explanation icon");
        Contains(install, "sourceComparison.Worse", "repository chooser carries the same source security warning forward to installation");
    }

    internal static void TestRepositoryClientResponseLifetimeContract()
    {
        var repositoryClient = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "RepositoryClient.cs"));

        Contains(repositoryClient, "using var response = await httpClient.SendAsync", "repository fetch declares and owns the HTTP response");
        Contains(repositoryClient, "HttpCompletionOption.ResponseHeadersRead", "repository fetch streams response bodies instead of eagerly buffering them");
        Contains(repositoryClient, "response.EnsureSuccessStatusCode()", "repository fetch rejects unsuccessful HTTP responses");
        Contains(repositoryClient, "response.Content.ReadAsStreamAsync", "repository fetch reads from the declared response");
    }



    internal static void TestPluginDocumentationAndReleaseChangelogContract()
    {
        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));
        var content = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductContent.cs"));
        var usage = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "MarketplaceUsageRules.cs"));
        var store = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "SqliteCatalogStore.cs"));
        var release = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "release.yml"));
        var changelog = File.ReadAllText(Path.Combine(Root, "CHANGELOG.md"));

        Contains(library, "DrawInlineChangelogButton", "Updates exposes changelog access beside the offered version");
        Contains(content, "DrawProductChangelog", "product pages render changelog history");
        Contains(content, "DrawProductUsage", "product pages render how-to-use information");
        Contains(usage, "how to use", "usage extraction recognizes explicit how-to headings");
        Contains(usage, "command prefix", "usage extraction recognizes command metadata such as Questionable's command prefix");
        Contains(store, "ReadPluginChangelogHistory", "Definitions retains and loads historical plugin changelogs from historical variants");
        Contains(store, "WHERE TRIM(v.changelog)<>''", "empty changelog records are not projected into client history");
        Contains(changelog, "## [0.8.74]", "repository changelog has an entry for the current release");
        Contains(changelog, "Availability", "release notes can explain when Definitions-backed features become visible");
        Contains(release, "extract_changelog.py", "release workflow consumes repository CHANGELOG.md");
        Contains(release, "--notes-file release-notes.md", "GitHub Releases receive curated project release notes");
    }
    internal static void TestRepositoryAwarenessAuthorsAndSpotlightPolishContract()
    {
        var authors = MarketplaceAuthorRules.Split("Inf1, Sl0nderman and harbingerftw & Contributors");
        Equal(3, authors.Count, "combined manifest authors are normalized into individual identities");
        True(authors.Contains("Inf1"), "first author identity survives normalization");
        True(authors.Contains("Sl0nderman"), "and-separated author identity survives normalization");
        True(authors.Contains("harbingerftw"), "ampersand-separated author identity survives normalization");
        False(authors.Any(x => x.Equals("Contributors", StringComparison.OrdinalIgnoreCase)), "generic contributor labels are not exposed as author identities");

        var chrome = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Chrome.cs"));
        var spotlight = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.SpotlightShelves.cs"));
        var availability = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Availability.cs"));
        var awareness = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.RepositoryAwareness.cs"));
        var bridge = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudRepositoryBridge.cs"));
        var pluginEntry = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        var sources = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Sources.cs"));
        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));
        var repositoryPresentation = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.RepositoryPresentation.cs"));
        var productAuthors = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Authors.cs"));
        var filters = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Filters.cs"));
        var builder = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "build_sqlite_catalog.py"));

        Contains(chrome, "DrawSidebarViewIcon(MarketplaceView.Spotlight, FontAwesomeIcon.Star, \"Spotlight\", 0)", "Spotlight navigation no longer advertises a meaningless fixed plugin count");
        Contains(spotlight, "Plugins most recently first seen in Omega Definitions", "Latest additions explains its first-seen chronology");
        Contains(spotlight, "most recent known publication/update timestamp", "Latest updates explains its timestamp chronology");
        Contains(availability, "SetReadableTooltip", "listing tooltips have an independent readable style");
        Contains(availability, "ImGuiStyleVar.Alpha, 1f", "unavailable listing alpha no longer dims tooltip content");

        Contains(bridge, "GetConfiguredRepositories", "Omega can enumerate repositories that already exist in Dalamud");
        Contains(pluginEntry, "MergeDalamudRepositoryAwareness", "startup imports existing Dalamud repository awareness");
        Contains(sources, "Dalamud off", "source manager surfaces the live Dalamud repository state");
        Contains(awareness, "artifact.cross-source-hash-mismatch", "repository warnings are grounded in stable-baseline artifact divergence");
        Contains(awareness, "AcknowledgedRepositoryRiskFingerprint", "repository risk acknowledgement survives restarts until the risk set changes");
        Contains(awareness, "Review Sources", "repository warning can take the user directly to source review");
        Contains(sources, "SourceManagerSection.DalamudConfigured", "source review has a dedicated view of every repository configured in Dalamud");
        Contains(sources, "repositoryBridge.GetConfiguredRepositories()", "Dalamud source review is driven by live Dalamud configuration rather than only Omega's filtered inventory");
        Contains(sources, "Acknowledge risk", "a divergent configured source can be acknowledged directly from source review");
        Contains(awareness, "ImGuiWindowFlags.NoScrollbar", "repository warning modal does not show an unnecessary outer scrollbar");

        Contains(library, "DrawInstalledAuthorRepositoryLine", "Library renders repository provenance from the installed plugin rather than the marketplace baseline");
        Contains(repositoryPresentation, "installedPlugin.Manifest.InstalledFromUrl", "installed repository provenance uses Dalamud's persisted install source");

        Contains(productAuthors, "OpenAuthorInDiscover", "individual product authors are clickable navigation targets");
        Contains(filters, "SelectMany(x => x.EffectiveAuthors)", "author filters are built from individual author identities");
        Contains(builder, "authors_json", "normalized individual authors are persisted by the catalog builder");
        Contains(builder, "split_authors", "the backend normalizes manifest author strings during catalog ingestion");
    }

}
