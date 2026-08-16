namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
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
        Contains(headerLinks, "FontAwesomeIcon.Globe", "Discover product header exposes project navigation as a compact globe icon");
        Contains(headerLinks, "OpenProductWebsite", "product-header globe opens the selected project URL");
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
        Contains(product, "DrawProductActionButton(\"Update\"", "installed Discover products replace Installed/Open with Update when an update exists");
        Contains(product, "PluginInstallerOpenKind.UpdateablePlugins", "Discover product Update delegates to Dalamud's update surface");
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
        Contains(backups, "Path.GetTempPath()", "config backups are temporary rather than persistent Omega state");
        Contains(library, "RevealBackupInExplorer", "successful config backups immediately reveal the generated archive");
        Contains(library, "explorer.exe", "Windows Explorer is used to show the backup location after creation");
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

}
