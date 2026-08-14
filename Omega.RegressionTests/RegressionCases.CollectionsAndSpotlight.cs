namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestDalamudCollectionsContract()
    {
        var ui = ReadMarketplaceWindowSource();
        var bridge = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudProfileBridge.cs"));
        var spotlight = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Spotlight.cs"));

        Contains(ui, "LibrarySection.Collections", "Collections is nested inside Library rather than owning a global sidebar destination");
        Contains(ui, "library-tab-collections", "Library exposes Collections as an in-panel section");
        Contains(ui, "DrawCollectionFolders", "collection overview uses folder renderer");
        Contains(ui, "DrawFolderShape", "collections are drawn as desktop-style folders");
        Contains(ui, "DrawCollectionPluginGrid", "opened collection renders plugin icon grid");
        Contains(ui, "Enabled in collection", "collection plugin desired state is visible");
        Contains(ui, "collection-toggle-", "collection folders expose on/off controls");
        Contains(ui, "Task.Run(() => profileBridge.SetCollectionEnabledAsync", "collection changes are delegated asynchronously");
        Contains(ui, "Default plugins", "default Dalamud profile remains visible");
        Contains(ui, "Always on", "default profile is not presented as toggleable");

        Contains(bridge, "Dalamud.Plugin.Internal.Profiles.ProfileManager", "bridge resolves Dalamud ProfileManager");
        Contains(bridge, "Profiles", "bridge reads Dalamud profile collection");
        Contains(bridge, "SetStateAsync", "bridge delegates collection state changes to Dalamud");
        Contains(bridge, "IsDefaultProfile", "bridge protects the default profile");
        False(bridge.Contains("File.Write", StringComparison.Ordinal), "Omega must not persist a second collection model");

        Contains(spotlight, "DrawSpotlightCard", "Spotlight renders card-owned promotional information");
        Contains(spotlight, "SpotlightCardCount = 5", "Spotlight keeps five cards side by side");
        Contains(spotlight, "SpotlightCardMaxWidth", "Spotlight cards stay compact rather than full-width");
        False(spotlight.Contains("spotlight-card-info-", StringComparison.Ordinal), "Spotlight must not regress to split wide cells");
        Contains(spotlight, "DrawSpotlightPitch", "Spotlight card includes only a short promotional pitch");
        Contains(spotlight, "contentStartY + 112f", "Spotlight card identity content is vertically aligned");
        Contains(spotlight, "contentStartY + 178f", "Spotlight pitch begins at the same vertical anchor on every card");
        Contains(spotlight, "OpenSpotlightPluginInDiscover", "whole-card selection hands off to Discover details");
        False(spotlight.Contains("DrawSpotlightActionRow", StringComparison.Ordinal), "Spotlight does not duplicate product-page actions");
        False(spotlight.Contains("DrawSpotlightInfoButton", StringComparison.Ordinal), "Spotlight does not duplicate the Discover info action");
        Contains(spotlight, "NoScrollWithMouse", "Spotlight cards remain fixed non-scrollable promotional cards");
        False(spotlight.Contains("AssemblyVersionText", StringComparison.Ordinal), "Spotlight cards omit version metadata");
        False(spotlight.Contains("DrawDetailsDescription", StringComparison.Ordinal), "Spotlight must not copy the verbose normal details panel");
        Contains(spotlight, "OpenPluginDetails(plugin)", "selecting Spotlight artwork routes through the canonical Discover product-page selection path");

        var shelves = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.SpotlightShelves.cs"));
        var recency = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginRecencyLedger.cs"));
        Contains(shelves, "Latest additions", "Spotlight includes a five-plugin latest-additions shelf");
        Contains(shelves, "Latest updates", "Spotlight includes a five-plugin latest-updates shelf");
        Contains(shelves, ".Take(SpotlightCardCount)", "recency shelves remain bounded to five plugins");
        Contains(shelves, "pluginRecency.GetFirstSeenUnix", "latest additions use durable first-seen ordering");
        Contains(shelves, "NormalizeUnix(x.LastUpdate)", "latest updates use repository LastUpdate ordering");
        Contains(shelves, "showOverlays: false", "recency shelves keep artwork clean");
        Contains(shelves, "OpenSpotlightPluginInDiscover(plugin)", "latest additions and updates use whole-card Discover navigation");
        False(shelves.Contains("Install", StringComparison.Ordinal), "recency shelves do not duplicate install actions");
        False(shelves.Contains("InfoCircle", StringComparison.Ordinal), "recency shelves do not duplicate info buttons");
        Contains(shelves, "NoScrollWithMouse", "recency shelf cards do not scroll independently");
        Contains(recency, "plugin-recency.json", "first-seen state is persisted in Omega's config directory");
        Contains(recency, "baseline && manifestDate > 0", "initial recency baseline uses manifest dates when creation dates are unavailable");
    }

    internal static void TestStoreLibraryNavigationContract()
    {
        var ui = ReadMarketplaceWindowSource();
        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));

        Contains(ui, "MarketplaceView.Library", "installed plugins are owned by Library");
        Contains(ui, "MarketplaceView.Updates", "updates has a dedicated lower utility destination");
        Contains(ui, "sidebar-utility-{view}", "lower icon-rail utility navigation is separate from primary navigation");
        Contains(ui, "DrawSidebarUtilityIcon(MarketplaceView.Updates", "Updates is rendered as a lower icon-rail destination");
        Contains(ui, "DrawSidebarUtilityIcon(MarketplaceView.Library", "Library is rendered as a lower icon-rail destination");
        False(ui.Contains("DrawSidebarView(MarketplaceView.Installed", StringComparison.Ordinal), "Installed is no longer a permanent sidebar destination");
        False(ui.Contains("DrawSidebarView(MarketplaceView.Collections", StringComparison.Ordinal), "Collections is no longer a permanent sidebar destination");
        False(ui.Contains("DrawSidebarView(MarketplaceView.Installable", StringComparison.Ordinal), "Installable is no longer a permanent sidebar destination");
        False(ui.Contains("DrawSidebarView(MarketplaceView.Outdated", StringComparison.Ordinal), "Outdated API is no longer a permanent sidebar destination");

        Contains(library, "library-tab-all", "Library has an All section");
        Contains(library, "library-tab-collections", "Library has a Collections section");
        Contains(library, "BuildLibraryProjection", "Library includes installed plugins even when marketplace metadata is absent");
        Contains(library, "DrawLibraryList", "Library All uses an installed-app row list rather than the marketplace icon grid");
        Contains(library, "DrawUpdatesList", "Updates uses a dedicated update row list");
        Contains(library, "const float rowHeight = 88f", "Library and Updates use a compact three-line metadata row without clipping");
        Contains(library, "InstalledVersionText(installedPlugin)", "installed rows expose the installed version");
        Contains(library, "installedPlugin.IsLoaded ? \"Loaded\" : \"Not loaded\"", "installed rows expose the runtime load state");
        Contains(library, "BuildInstalledMetadataLine", "installed rows expose source and API compatibility metadata");
        Contains(library, "→ v{offered}", "update rows expose installed-to-available version progression");
        Contains(library, "configuration.PreferTestingBuilds", "row compatibility honors the testing-build preference");
        Contains(library, "FontAwesomeIcon.SyncAlt", "Updates use a compact update icon instead of a text button");
        Contains(library, "PluginInstallerOpenKind.UpdateablePlugins", "Update action delegates to Dalamud's update surface");
        Contains(ui, "MarketplaceStatusFilter.Installable", "Discover Status filter preserves Installable grouping");
        Contains(ui, "MarketplaceStatusFilter.OutdatedApi", "Discover Status filter preserves Outdated API grouping");
        Contains(ui, "##filter-status", "status grouping is panel-local inside expanded Filters");
        Contains(ui, "LibraryRuntimeFilter", "Library reuses Discover's full filter layout with a useful loaded/not-loaded status filter");
        Contains(ui, "HasAvailableUpdate", "Updates derives from newer compatible catalog packages");
        Contains(ui, "ImGui.Dummy(new Vector2(0f, 38f))", "left navigation starts below top chrome instead of above right-panel data");
        Contains(ui, "sidebar-settings", "Settings replaces Sources in the lower icon rail");
        Contains(ui, "FontAwesomeIcon.Star", "Spotlight uses an icon");
        Contains(ui, "FontAwesomeIcon.Search", "Discover uses an icon");
        Contains(ui, "FontAwesomeIcon.Download", "Updates uses an icon");
        Contains(ui, "FontAwesomeIcon.List", "Library uses an icon");
    }

    internal static void TestInstalledSnapshotNullSafetyContract()
    {
        var cache = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Cache.cs"));
        var window = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.cs"));
        var details = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Details.cs"));
        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));

        Contains(cache, "plugin.Version?.GetHashCode() ?? 0", "installed signature tolerates a transient null version");
        Contains(cache, "plugin is null", "installed signature tolerates a transient null plugin value");
        Contains(cache, "internalName ?? string.Empty", "installed signature tolerates an unexpected null name");
        Contains(window, ".Where(x => x is not null && !string.IsNullOrWhiteSpace(x.InternalName))", "installed snapshot filters incomplete entries");
        Contains(window, ".GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)", "installed snapshot tolerates duplicate transient names");
        Contains(details, "if (installedVersion is null)", "update comparison waits until Dalamud exposes a version");
        Contains(library, "version pending", "Library renders partial installed state instead of throwing");
        False(cache.Contains("plugin.Version.GetHashCode()", StringComparison.Ordinal), "signature must not dereference a nullable version");
    }

    internal static void TestCleanDetailsArtworkContract()
    {
        var details = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Details.cs"));
        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));

        Contains(details, "showOverlays: false", "detail artwork is rendered as the plain plugin picture");
        Contains(library, "showOverlays: false", "Library row artwork remains plain app-icon artwork");
        False(details.Contains("DrawArtworkSelection", StringComparison.Ordinal), "details must not paint selection state over the image");
    }

    internal static void TestDiscoverStoreListContract()
    {
        var discover = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Discover.cs"));
        var product = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductPage.cs"));
        var storefront = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Storefront.cs"));

        Contains(discover, "Featured", "Discover labels screenshot-rich plugins as Featured");
        Contains(discover, "DiscoverRichColumns = 3", "enhanced Discover listings use Store-style three-wide cards");
        Contains(discover, "const float gridStartX = 0f", "Featured cards align with the content edge instead of floating in a centered narrow grid");
        Contains(discover, "DrawDiscoverRichCard", "Discover renders rich screenshot cards");
        Contains(discover, "The rest", "metadata-only plugins continue below Featured as The rest");
        Contains(discover, "DrawDiscoverResultRow", "Discover retains the compact fallback result row");
        Contains(discover, "StorefrontVirtualization.Calculate", "both Discover tiers remain virtualized for large catalogues");
        Contains(discover, "★", "website-enriched listings receive a visible star");
        Contains(discover, "OpenPluginDetails(plugin)", "selecting either Discover result style opens its product page");
        False(discover.Contains("DrawApiBadge", StringComparison.Ordinal), "Discover results do not paint API badges over artwork");

        Contains(product, "DrawDiscoverProductPage", "Discover selection uses a full-width product page");
        Contains(product, "Screenshots", "product page exposes the screenshot section");
        Contains(product, "MarketplacePresentationContent", "product page consumes the richest presentation variant");
        Contains(product, "Dalamud official", "official plugins receive an explicit Dalamud badge");
        Contains(product, "★ Enhanced", "website-enriched product pages expose the enhanced marker");
        Contains(product, "NSFW", "NSFW-tagged plugins receive a content badge");
        Contains(product, "Install", "product page uses Install as the acquisition action");
        False(product.Contains("Share", StringComparison.OrdinalIgnoreCase), "product page does not add a meaningless share control");
        Contains(storefront, "DrawDiscoverList(filtered", "Discover delegates to the result list");
        Contains(storefront, "DrawDiscoverProductPage", "selected Discover plugins replace the list with the product page");
    }

}
