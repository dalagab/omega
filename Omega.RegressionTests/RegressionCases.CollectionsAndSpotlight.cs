namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestDalamudCollectionsContract()
    {
        var ui = ReadMarketplaceWindowSource();
        var window = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.cs"));
        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));
        var collections = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Collections.cs"));
        var bridge = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudProfileBridge.cs"));
        var spotlight = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Spotlight.cs"));

        Contains(ui, "LibrarySection.Collections", "Collections is nested inside Library rather than owning a global sidebar destination");
        Contains(ui, "library-tab-collections", "Library exposes Collections as an in-panel section");
        Contains(ui, "DrawCollectionFolders", "collection overview uses folder renderer");
        Contains(ui, "DrawFolderShape", "collections are drawn as desktop-style folders");
        Contains(ui, "DrawCollectionDirectoryList", "opened collections render as a stable directory list rather than a staggered marketplace tile grid");
        Contains(ui, "Library / Collections /", "opened collection exposes folder-style breadcrumb navigation");
        DoesNotContain(window, "DrawLibraryCollectionDropShelf", "Library > All must not render collection folders or collection drop targets");
        DoesNotContain(library, "DrawCollectionDragHandle", "Library > All must not expose collection-management drag handles");
        DoesNotContain(collections, "Library > All stays a clean list of installed plugins", "collection overview no longer carries explanatory copy about Library separation");
        Contains(collections, "DrawCollectionAddPicker", "membership additions are managed from inside an opened collection");
        Contains(collections, "Installed plugins not yet in this collection", "opened collections expose a searchable installed-plugin picker");
        Contains(collections, "+ Add plugins", "named collections expose an explicit add-membership action");
        Contains(ui, "DrawProductCollectionMembership", "the Discover individual product page exposes collection membership");
        Contains(ui, "foreach (var membership in memberships)", "the product page renders every named collection membership rather than only one");
        Contains(ui, ".Where(x => !x.Collection.IsDefault)", "the product page separates named collection memberships from Dalamud's default profile");
        Contains(ui, "StartAddPluginToCollection", "the collection-local picker starts a membership operation");
        Contains(ui, "StartRemovePluginFromCollection", "opened named collections support removing membership");
        Contains(ui, "StartCollectionPluginStateChange", "opened collections can change per-plugin desired state");
        Contains(ui, "GetPluginDirectControlState", "Library and Discover derive direct plugin control from Dalamud collection membership");
        Contains(ui, "Open Library > Collections to change its state", "Library collection tooltip points to the actual collection-management location");
        Contains(ui, "OpenCollectionView", "collection membership can navigate directly into the selected collection");
        Contains(ui, "DrawToggleSwitch", "collection and plugin state use semantic toggle switches");
        Contains(ui, "Task.Run(() => profileBridge.SetCollectionEnabledAsync", "collection changes are delegated asynchronously");
        Contains(ui, "Task.Run(() => profileBridge.AddPluginToCollectionAsync", "collection-local membership additions are delegated asynchronously");
        Contains(collections, "var visibleCollections = collectionSnapshot.Where(x => !x.IsDefault).ToArray()", "collection overview hides Dalamud's implicit default profile");
        Contains(library, "var namedCollectionCount = collectionSnapshot.Count(x => !x.IsDefault)", "Collections tab count includes named collections only");
        Contains(collections, "var folderSize = new Vector2(Ui(126f), Ui(82f))", "collection folders use a narrower natural folder silhouette");
        DoesNotContain(collections, "Always active", "hidden default profile does not leak an Always active label into Collections UI");

        Contains(bridge, "Dalamud.Plugin.Internal.Profiles.ProfileManager", "bridge resolves Dalamud ProfileManager");
        Contains(bridge, "Profiles", "bridge reads Dalamud profile collection");
        Contains(bridge, "SetStateAsync", "bridge delegates collection state changes to Dalamud");
        Contains(bridge, "AddOrUpdateAsync", "bridge delegates plugin membership/state changes to Dalamud Profile");
        Contains(bridge, "existing membership in other named profiles is preserved", "adding a plugin to one named collection must not evict it from another named collection");
        Contains(bridge, "Existing named collection memberships were kept", "successful membership feedback confirms additive collection semantics");
        Contains(bridge, "RemoveAsync", "bridge delegates membership removal to Dalamud Profile");
        Contains(bridge, "WorkingPluginId", "bridge resolves Dalamud's canonical installed plugin identity before membership changes");
        Contains(bridge, "IsDefaultProfile", "bridge protects the default profile from manual membership changes");
        False(bridge.Contains("File.Write", StringComparison.Ordinal), "Omega must not persist a second collection model");

        Contains(spotlight, "DrawSpotlightCard", "Spotlight renders card-owned promotional information");
        Contains(spotlight, "SpotlightCardCount = 5", "Spotlight keeps five cards side by side");
        Contains(spotlight, "SpotlightCardMaxWidth", "Spotlight cards stay compact rather than full-width");
        False(spotlight.Contains("spotlight-card-info-", StringComparison.Ordinal), "Spotlight must not regress to split wide cells");
        Contains(spotlight, "DrawSpotlightPitch", "Spotlight card includes only a short promotional pitch");
        Contains(spotlight, "contentStartY + Ui(112f)", "Spotlight card identity content is vertically aligned");
        Contains(spotlight, "contentStartY + Ui(178f)", "Spotlight pitch begins at the same vertical anchor on every card");
        Contains(spotlight, "OpenSpotlightPluginInDiscover", "whole-card selection hands off to Discover details");
        False(spotlight.Contains("DrawSpotlightActionRow", StringComparison.Ordinal), "Spotlight does not duplicate product-page actions");
        False(spotlight.Contains("DrawSpotlightInfoButton", StringComparison.Ordinal), "Spotlight does not duplicate the Discover info action");
        Contains(spotlight, "NoScrollWithMouse", "Spotlight cards remain fixed non-scrollable promotional cards");
        False(spotlight.Contains("AssemblyVersionText", StringComparison.Ordinal), "Spotlight cards omit version metadata");
        False(spotlight.Contains("DrawDetailsDescription", StringComparison.Ordinal), "Spotlight must not copy the verbose normal details panel");
        Contains(spotlight, "OpenPluginDetails(plugin)", "selecting Spotlight artwork routes through the canonical Discover product-page selection path");
        Contains(spotlight, "SpotlightPromotedCardColors(plugin)", "top promoted Spotlight cards derive their palette from the highlighted plugin rather than Omega branding");
        Contains(spotlight, "\"HonseFarm.Client\" =>", "HonseFarm has its own red logo-derived Spotlight palette");
        Contains(spotlight, "\"AetherLovePlugin\" =>", "AetherLove has its own blue logo-derived Spotlight palette");
        Contains(spotlight, "\"InventoryTools\" =>", "Allagan Tools has its own gold logo-derived Spotlight palette");
        Contains(spotlight, "\"GatherBuddy\" =>", "GatherBuddy has its own earthy logo-derived Spotlight palette");
        Contains(spotlight, "\"ChatTwo\" =>", "Chat 2 has its own monochrome logo-derived Spotlight palette");
        Contains(spotlight, "ImGui.PushStyleColor(ImGuiCol.ChildBg, cardColors.Background)", "promoted Spotlight cards apply the plugin-specific background tint");
        Contains(spotlight, "ImGui.PushStyleColor(ImGuiCol.Border, cardColors.Border)", "promoted Spotlight cards apply the matching plugin-specific border tint");
        Contains(spotlight, "showListingRibbons: true", "all five promoted Spotlight cards composite shared ribbons inside artwork");
        Contains(spotlight, "ResolveDefaultVariant(plugin)", "Spotlight resolves the same default repository package as the product page");
        Contains(spotlight, "DrawPluginPanelUpdateState", "Spotlight keeps panel-level update state separate from artwork ribbons");
        DoesNotContain(spotlight, "Omega's primary logo accent", "promoted-card color must not be derived from Omega branding");

        var shelves = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.SpotlightShelves.cs"));
        var recency = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginRecencyLedger.cs"));
        Contains(shelves, "Latest additions", "Spotlight includes a five-plugin latest-additions shelf");
        Contains(shelves, "Latest updates", "Spotlight includes a five-plugin latest-updates shelf");
        Contains(shelves, ".Take(SpotlightCardCount)", "recency shelves remain bounded to five plugins");
        Contains(shelves, "pluginRecency.GetFirstSeenUnix", "latest additions use durable first-seen ordering");
        Contains(shelves, "NormalizeUnix(x.LastUpdate)", "latest updates use repository LastUpdate ordering");
        Contains(shelves, "showOverlays: false", "recency shelves keep artwork clean");
        Contains(shelves, "OpenSpotlightPluginInDiscover(plugin)", "latest additions and updates use whole-card Discover navigation");
        Contains(shelves, "showListingRibbons: true", "latest additions and updates composite shared ribbons inside artwork");
        Contains(shelves, "DrawPluginPanelUpdateState", "recency shelf keeps panel-level update state separate from artwork ribbons");
        DoesNotContain(shelves, "SpotlightPromotedCardColors", "latest additions and updates remain neutral rather than inheriting promoted plugin palettes");
        False(shelves.Contains("Install", StringComparison.Ordinal), "recency shelves do not duplicate install actions");
        False(shelves.Contains("InfoCircle", StringComparison.Ordinal), "recency shelves do not duplicate info buttons");
        Contains(shelves, "NoScrollWithMouse", "recency shelf cards do not scroll independently");
        Contains(recency, "plugin-recency.json", "first-seen state is persisted in Omega's config directory");
        Contains(recency, "baseline && manifestDate > 0", "initial recency baseline uses manifest dates when creation dates are unavailable");
    }

    internal static void TestStoreLibraryNavigationContract()
    {
        var ui = ReadMarketplaceWindowSource();
        var window = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.cs"));
        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));
        var layout = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceLayoutRules.cs"));

        var chrome = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Chrome.cs"));

        Contains(ui, "MarketplaceView.Library", "installed plugins are owned by Library");
        Contains(ui, "MarketplaceView.Updates", "updates has a dedicated lower utility destination");
        Contains(chrome, "sidebar-utility-{view}", "lower icon-rail utility navigation is separate from primary navigation");
        Contains(chrome, "DrawSidebarUtilityIcon(", "lower icon-rail destinations use the utility navigation renderer");
        Contains(chrome, "MarketplaceView.Updates,", "Updates remains a lower icon-rail utility destination");
        Contains(chrome, "FontAwesomeIcon.Download", "Updates keeps its download icon in the lower utility rail");
        Contains(chrome, "counts.Updates + applicationUpdateCount + definitionsUpdateCount", "Updates destination count includes plugin, Omega and Definitions updates");
        Contains(chrome, "notificationCount: counts.Updates + applicationUpdateCount", "red numeric badge excludes Definitions attention");
        Contains(chrome, "definitionsAttention: updates.DefinitionsUpdateAvailable", "Definitions update uses its separate blue exclamation attention marker");
        Contains(chrome, "MarketplaceView.Library,", "Library remains a lower icon-rail utility destination");
        Contains(chrome, "FontAwesomeIcon.List", "Library keeps its list icon in the lower utility rail");
        False(ui.Contains("DrawSidebarView(MarketplaceView.Installed", StringComparison.Ordinal), "Installed is no longer a permanent sidebar destination");
        False(ui.Contains("DrawSidebarView(MarketplaceView.Collections", StringComparison.Ordinal), "Collections is no longer a permanent sidebar destination");
        False(ui.Contains("DrawSidebarView(MarketplaceView.Installable", StringComparison.Ordinal), "Installable is no longer a permanent sidebar destination");
        False(ui.Contains("DrawSidebarView(MarketplaceView.Outdated", StringComparison.Ordinal), "Outdated API is no longer a permanent sidebar destination");

        Contains(library, "library-tab-all", "Library has an All section");
        Contains(library, "library-tab-collections", "Library has a Collections section");
        Contains(library, "BuildLibraryProjection", "Library includes installed plugins even when marketplace metadata is absent");
        Contains(library, "DrawLibraryList", "Library All uses an installed-app row list rather than the marketplace icon grid");
        DoesNotContain(window, "DrawLibraryCollectionDropShelf", "Library All renders no collection-folder shelf above the installed list");
        DoesNotContain(library, "DrawCollectionDragHandle", "Library All rows contain no collection-management affordance");
        Contains(library, "DrawUpdatesList", "Updates uses a dedicated update row list");
        Contains(layout, "public const float LibraryRowHeight = 104f", "the shared Library row-height contract leaves room for install metadata and actions");
        Contains(library, "var rowHeight = Ui(MarketplaceLayoutRules.LibraryRowHeight)", "Library consumes its expanded metadata row-height contract");
        Contains(layout, "public const float UpdatesRowHeight = 88f", "Updates keep their existing compact row height");
        Contains(library, "var rowHeight = Ui(MarketplaceLayoutRules.UpdatesRowHeight)", "Updates consume their compact row-height contract");
        Contains(library, "InstalledVersionText(installedPlugin)", "installed rows expose the installed version");
        Contains(library, "installedPlugin.IsLoaded ? \"Loaded\" : \"Not loaded\"", "installed rows expose the runtime load state");
        Contains(library, "BuildInstalledMetadataLine", "installed rows expose source and API compatibility metadata");
        Contains(library, "→ v{offered}", "update rows expose installed-to-available version progression");
        Contains(library, "configuration.PreferTestingBuilds", "row compatibility honors the testing-build preference");
        Contains(library, "FontAwesomeIcon.SyncAlt", "Updates use a compact update icon instead of a text button");
        Contains(library, "OpenUpdateOrMigration", "Update action performs the selected update or opens repository-migration confirmation");
        Contains(ui, "MarketplaceStatusFilter.Installable", "Discover Status filter preserves Installable grouping");
        Contains(ui, "MarketplaceStatusFilter.OutdatedApi", "Discover Status filter preserves Outdated API grouping");
        Contains(ui, "##filter-status", "status grouping is panel-local inside expanded Filters");
        Contains(ui, "LibraryRuntimeFilter", "Library reuses Discover's full filter layout with a useful loaded/not-loaded status filter");
        Contains(ui, "HasAvailableUpdate", "Updates derives from newer compatible catalog packages");
        Contains(ui, "ImGui.Dummy(Ui(0f, 6f))", "Spotlight and Discover sit close to the top of the icon rail with scale-aware spacing");
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
        Contains(discover, "DiscoverLayoutMode.CompactCards", "Discover can switch every plugin to compact icon-first cards");
        Contains(discover, "DrawDiscoverCompactCard", "compact Discover cards retain plugin icons and listing ribbons without screenshots");
        Contains(discover, "DiscoverLayoutMode.List", "Discover can switch every plugin to the dense list presentation");
        Contains(discover, "DrawDiscoverListResults", "list mode virtualizes every plugin as a result row");
        var ribbons = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Ribbons.cs"));
        Contains(discover, "var resultsWindowSize = ImGui.GetWindowSize()", "Discover derives ribbon clipping from the fixed results-child window rather than scroll-relative content coordinates");
        Contains(discover, "discoverListingClipMin = resultsWindowPos", "Discover ribbon clipping keeps a fixed screen-space top edge while scrolling");
        Contains(discover, "discoverListingClipMax = resultsWindowPos + resultsWindowSize", "Discover ribbon clipping keeps a fixed screen-space bottom edge while scrolling");
        DoesNotContain(discover, "discoverListingClipMin = resultsWindowPos + ImGui.GetWindowContentRegionMin()", "Discover never derives the ribbon viewport from scroll-relative content-region coordinates");
        Contains(ribbons, "Vector2.Max(clipMin, viewportMin)", "listing ribbons clamp their card bounds to the Discover results window");
        Contains(ribbons, "Vector2.Min(clipMax, viewportMax)", "listing ribbons cannot paint past the Discover results window");
        Contains(discover, "The rest", "metadata-only plugins continue below Featured as The rest in Dynamic mode");
        Contains(discover, "DrawDiscoverResultRow", "Discover retains the compact fallback result row");
        Contains(discover, "StorefrontVirtualization.Calculate", "both Discover tiers remain virtualized for large catalogues");
        Contains(discover, "★", "website-enriched listings receive a visible star");
        Contains(discover, "OpenPluginDetails(plugin)", "selecting either Discover result style opens its product page");
        False(discover.Contains("DrawApiBadge", StringComparison.Ordinal), "Discover results do not paint API badges over artwork");

        Contains(product, "DrawDiscoverProductPage", "Discover selection uses a dedicated product page");
        Contains(product, "var heroWidth = Math.Max(Ui(1f), ImGui.GetContentRegionAvail().X)", "Discover product hero spans the full available content width");
        Contains(product, "DrawProductHeroBanner(plugin, heroWidth, heroHeight)", "product hero paints repository artwork as its background surface");
        False(product.Contains("ProductHeroMaxWidth", StringComparison.Ordinal), "product hero no longer reintroduces the old fixed-width inset cap");
        Contains(product, "ProductHeroHeight = 310f", "product hero reserves enough vertical room for its primary action");
        Contains(product, "CleanProductDescriptionForDisplay", "About removes redundant transport provenance from human-readable description copy");
        Contains(product, "product-about-metadata", "About uses a structured metadata table instead of a dense footer paragraph");
        Contains(product, "DrawProductSectionHeading", "About and Security use a shared readable section hierarchy");
        Contains(product, "Screenshots", "product page exposes the screenshot section");
        Contains(product, "style.WindowPadding.Y * 2f", "screenshot strip height reserves its vertical window padding");
        Contains(product, "style.ScrollbarSize + Ui(4f)", "screenshot strip reserves horizontal scrollbar height so a vertical scrollbar is not induced");
        Contains(product, "ImGuiWindowFlags.HorizontalScrollbar | ImGuiWindowFlags.NoScrollWithMouse", "screenshots remain a horizontal-only browsing strip");
        Contains(product, "MarketplacePresentationContent", "product page consumes the canonical presentation selection");
        Contains(product, "DrawDalamudOfficialLogoBadge", "official plugins use the Dalamud logo rather than a text badge");
        Contains(product, "★ Enhanced", "website-enriched product pages expose the enhanced marker");
        Contains(product, "DrawProductProjectLinks(plugin)", "enhanced product pages expose classified project actions outside the badge row");
        Contains(product, "DrawProductSigmascopeSummary(plugin)", "security posture is summarized inside the product hero instead of as a detached block");
        Contains(product, "DrawProductHeroBanner", "product pages support repository-provided .omega background banners");
        Contains(product, "iconCache.GetOrQueue(plugin.OmegaBannerUrl)", "repository banner artwork uses Omega's bounded persistent artwork cache");
        Contains(product, "new Vector4(0f, 0f, 0f, 0.03f)", "product hero child stays effectively transparent so banner artwork owns the top surface");
        Contains(product, "Darken the left and lower areas so text and actions remain readable on bright banners", "product hero retains readability scrims over banner artwork");
        False(product.Contains("new Vector4(0.045f, 0.052f, 0.064f, 0.74f)", StringComparison.Ordinal), "old translucent inset hero panel does not return");
        Contains(product, "DrawProductCollectionMembership(plugin, installedPlugin)", "installed product pages show the plugin's collection membership directly below the hero");
        Contains(product, ".Where(x => !x.Collection.IsDefault)", "product membership excludes Dalamud's Default plugins profile from named collection claims");
        Contains(product, "if (memberships.Length > 0)", "collection membership UI is only rendered when named memberships exist");
        False(product.Contains("Not in a named collection", StringComparison.Ordinal), "plugins without named memberships do not render an empty Collections subsection");
        Contains(product, "DrawProductUsage(content)", "product pages expose collected how-to-use information");
        Contains(product, "DrawProductChangelog(plugin)", "product pages expose plugin release notes");
        Contains(product, "foreach (var membership in memberships)", "all matching collection memberships are iterated instead of reducing membership to a single owner");
        Contains(product, "CollectionDisplayName(collection)", "each Discover collection membership is rendered from its own collection identity");
        False(product.Contains("Enhanced from:", StringComparison.Ordinal), "raw enrichment provenance wording must not return to the About section");
        False(product.Contains("DrawDetailsLinks(plugin)", StringComparison.Ordinal), "product pages do not append a detached project/source button row below About");
        Contains(product, "18+", "adult-content plugins receive the user-facing 18+ badge");
        Contains(product, "Install", "product page uses Install as the acquisition action");
        False(product.Contains("Share", StringComparison.OrdinalIgnoreCase), "product page does not add a meaningless share control");
        Contains(storefront, "DrawDiscoverList(filtered", "Discover delegates to the result list");
        Contains(storefront, "DrawDiscoverProductPage", "selected Discover plugins replace the list with the product page");
    }



    internal static void TestDiscoverRiskOwnershipAndAvailabilityContract()
    {
        var discover = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Discover.cs"));
        var spotlight = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Spotlight.cs"));
        var shelves = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.SpotlightShelves.cs"));
        var ribbons = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Ribbons.cs"));
        var security = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Sigmascope.cs"));
        var artwork = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Artwork.cs"));
        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        var scale = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Scale.cs"));
        var filters = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Filters.cs"));

        Contains(discover, "showListingRibbons: true", "Discover rich and compact listings use the card-top ribbon overlay");
        Contains(spotlight, "showListingRibbons: true", "Spotlight promoted cards use the same card-top ribbon language");
        Contains(shelves, "showListingRibbons: true", "Spotlight shelf cards use the same card-top ribbon language");
        Contains(artwork, "selectedPlugin = ResolveDefaultVariant(plugin)", "fresh product-page navigation starts from the same deterministic default package as listing security");
        Contains(security, "ResolveSigmascopeVisual", "the product page retains the exact-package security resolver");
        Contains(security, "DrawProductSigmascopeSummary", "the product hero consumes the shared exact-package security result");
        Contains(ribbons, "FontAwesomeIcon.Question", "unresolved source attribution uses a neutral question ribbon rather than implying closed source");
        DoesNotContain(ribbons, "shown as closed source", "missing source attribution is never presented as author-declared closed source");
        Contains(ribbons, "outdated ? FontAwesomeIcon.Lock : FontAwesomeIcon.Star", "unsupported indexed plugins use a lock while supported public-source plugins retain the star");
        Contains(ribbons, "highestKnownApi > 0 && highestKnownApi < currentApi", "out-of-date public-source packages are detected against the current Dalamud API");
        Contains(ribbons, "var iconColor = 0xFFFFFFFF", "unsupported indexed packages use a white lock glyph on warning ribbons");
        DoesNotContain(ribbons, "0xFF000000", "the unsupported lock no longer uses a black glyph");
        DoesNotContain(ribbons, "AddCircleFilled(glyphCenter", "ribbon glyphs do not receive a white backing disk");
        Contains(ribbons, "icon == FontAwesomeIcon.Lock", "the unsupported lock receives a dedicated thickness treatment");
        Contains(ribbons, "Ui(0.45f)", "the unsupported lock is reinforced with a restrained sub-pixel double draw");
        Contains(ribbons, "FontAwesomeIcon.Robot => Ui(1.0f)", "the robot ribbon is pulled half a pixel left from the previous non-star correction");
        Contains(ribbons, "FontAwesomeIcon.Folder => Ui(1.0f)", "the folder ribbon is pulled half a pixel left from the previous non-star correction");
        Contains(ribbons, "var glyphScale = icon == FontAwesomeIcon.Folder ? 0.92f : 1f", "the folder glyph is rendered slightly smaller without changing ribbon geometry");
        Contains(ribbons, "_ => Ui(1.5f)", "other non-star ribbon glyphs keep the established optical right correction");
        Contains(ribbons, "Unsupported on Dalamud API", "the lock tooltip states the unsupported API condition directly");
        Contains(ribbons, "\"informational\" or \"info\"", "informational security has its own blue ribbon state");
        Contains(ribbons, "\"none\" or \"\"", "no findings has its own gold ribbon state");
        Contains(ribbons, "\"low\"", "low security findings have their own yellow ribbon state");
        Contains(ribbons, "\"caution\" or \"medium\"", "medium security findings have their own orange ribbon state");
        Contains(ribbons, "\"high\" or \"critical\"", "high and critical findings share the red ribbon state");
        Contains(ribbons, "FontAwesomeIcon.Check", "installed plugins have a dedicated white-check ribbon");
        Contains(ribbons, "0.18f, 0.70f, 0.39f", "installed state uses the requested green ribbon");
        Contains(ribbons, "FontAwesomeIcon.Folder", "named collection membership has a separate folder ribbon");
        Contains(ribbons, ".Where(x => !x.IsDefault", "collection ribbon describes named collections rather than duplicating the automatic default profile");
        Contains(ribbons, "FontAwesomeIcon.Robot", "automation exposure has a dedicated robot ribbon");
        Contains(ribbons, "0.05f, 0.62f, 0.78f", "automation ribbon uses Omega cyan/blue");
        Contains(ribbons, "GetPluginAutomationState(plugin)", "automation ribbon preserves direct and required-dependency automation evidence semantics");
        Contains(artwork, "if (showListingRibbons && listingPanelMin is { } panelMin && listingPanelMax is { } panelMax)", "listing ribbons use explicit card bounds while the artwork child owns the top compositing layer");
        Contains(artwork, "DrawPluginCardTopRibbons(plugin, installedPlugin, currentApi, panelMin, panelMax)", "ribbons are composited after the plugin image while remaining anchored to the card");
        Contains(ribbons, "var leftX = panelMin.X + edgeInset", "ownership and collection ribbons anchor to the card top-left");
        Contains(ribbons, "var rightX = panelMax.X - edgeInset - ribbonWidth", "Sigmascope and automation ribbons anchor to the card top-right");
        Contains(ribbons, "leftX += ribbonWidth + ribbonGap", "ownership and collection ribbons sit side-by-side horizontally");
        Contains(ribbons, "rightX - ribbonWidth - ribbonGap", "Sigmascope and automation ribbons sit side-by-side horizontally");
        Contains(ribbons, "draw.PushClipRect(clipMin, clipMax, false)", "card-top ribbons still expand beyond the artwork child after their card bounds are clamped to the Discover viewport");
        Contains(ribbons, "draw.AddRectFilledMultiColor", "ribbons use a restrained velvet-like vertical shade without changing their semantic colour");
        DoesNotContain(spotlight, "ImGui.SetCursorPosY(contentStartY + Ui(26f))", "Spotlight does not reserve a blank strip; card ribbons may overlap a small part of the logo");
        DoesNotContain(shelves, "ImGui.SetCursorPosY(Ui(34f))", "recency cards do not reserve a blank strip; card ribbons may overlap a small part of the logo");
        DoesNotContain(ribbons, "artworkMin.X", "listing ribbon X coordinates are never anchored to plugin artwork");
        Contains(ribbons, "var glyphCenter = new Vector2(centerX + glyphOffsetX, min.Y + (height * 0.5f))", "ribbon glyphs remain centered against the complete flag shape after their per-icon optical correction");
        DoesNotContain(ribbons, "DrawArtworkStatusFlag", "the 0.9.2 all-status-on-left compact flag regression is removed");
        Contains(ribbons, "FontAwesomeIcon.SyncAlt", "available plugin updates are shown at the panel bottom-right");
        Contains(ribbons, "var min = panelMax - new Vector2(size + inset, size + inset)", "update glyph uses a consistent bottom-right inset");
        DoesNotContain(ribbons, "draw.AddCircleFilled(center, size * 0.53f", "card update indicator no longer draws a circular background");
        DoesNotContain(ribbons, "draw.AddCircle(center, size * 0.53f", "card update indicator no longer draws a circular border");
        Contains(ribbons, "GetAvailableUpdateVersion", "update indicator is based on the actual compatible update resolver");
        DoesNotContain(discover, "DrawDiscoverTopRightIndicators(plugin", "the old star/down-arrow top-right indicator is no longer rendered");
        Contains(discover, "showInstalledMarker: false", "Discover does not render the legacy circular installed marker over artwork");
        Contains(discover, "ImGui.SetCursorPos(Ui(12f, 12f))", "rich-card artwork keeps its normal top position beneath card-top ribbons");
        Contains(discover, "ImGui.SetCursorPos(Ui(12f, 18f))", "horizontal-list artwork keeps its normal top position beneath card-top ribbons");
        DoesNotContain(discover, "installed ? 44f : 12f", "installed list entries never shift artwork to make room for the ribbon");
        DoesNotContain(discover, "var artworkX = installed ?", "installed rich cards never shift artwork to make room for the ribbon");
        Contains(discover, "DrawDalamudOfficialLogoBadge", "official listings retain the Dalamud logo status");
        Contains(discover, "DalamudAsset.LogoSmall", "the official badge uses Dalamud's own shipped logo asset");
        DoesNotContain(discover, "0.10f, 0.035f, 0.045f, 0.78f", "the official Dalamud badge no longer paints a dark-red square behind the logo");
        var repositoryPresentation = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.RepositoryPresentation.cs"));
        Contains(repositoryPresentation, "provider.Kind == RepositoryProviderKind.Dalamud", "repository/source views special-case Dalamud provider artwork");
        Contains(repositoryPresentation, "DalamudAsset.LogoSmall", "repository/source views use Dalamud's shipped logo rather than the Goatcorp avatar");
        DoesNotContain(discover, "DrawDiscoverTextBadge(\"Official\"", "Discover does not regress to an Official text pill");
        Contains(plugin, "IDalamudAssetManager DalamudAssets", "Omega requests the public Dalamud asset service for the official logo");
        Contains(scale, "ImGuiHelpers.GlobalScale", "marketplace pixel geometry follows Dalamud UI scale");
        Contains(scale, "MaximumSupportedUiScale = 2.25f", "marketplace scaling explicitly covers 175% and 200% UI scale");
        Contains(scale, "ResponsiveDefaultWindowLogicalSize", "large UI scale cannot inflate the default window beyond the viewport");
        Contains(scale, "ResponsiveMinimumWindowLogicalSize", "large UI scale cannot inflate the minimum window beyond the viewport");
        Contains(filters, "ResponsiveColumns(available, 230f, 3, 12f)", "filter controls wrap into fewer columns at high UI scale");
        Contains(shelves, "layout.Columns", "Spotlight cards wrap instead of overflowing at high UI scale");
    }


    internal static void TestPluginArtworkAndScreenshotInteractionContract()
    {
        var discover = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Discover.cs"));
        var spotlight = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Spotlight.cs"));
        var shelves = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.SpotlightShelves.cs"));
        var product = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductPage.cs"));
        var viewer = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ScreenshotViewer.cs"));
        var window = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.cs"));

        Contains(discover, "var artworkClicked = DrawDiscoverRichCardHeader(", "Featured plugin icons have their own click path");
        Contains(discover, "if (artworkClicked || (hovered && ImGui.IsMouseClicked", "Featured plugin icon clicks open the canonical product page even through nested child windows");
        Contains(discover, "var artworkClicked = DrawPluginArtwork(", "compact Discover plugin icons retain direct click state");
        Contains(spotlight, "if (artworkClicked || clicked)", "Spotlight plugin icons open Discover without relying on parent-window hover propagation");
        Contains(shelves, "if (artworkClicked || clicked)", "Spotlight shelf plugin icons open Discover without relying on parent-window hover propagation");

        Contains(discover, "var screenshotClicked = DrawDiscoverRichCardScreenshot", "Featured screenshots have their own click path");
        Contains(discover, "OpenScreenshotViewer(url)", "Featured screenshots open the larger viewer instead of relying on the card click");
        Contains(product, "View larger image", "product project images advertise the larger viewer");
        Contains(product, "OpenScreenshotViewer(url)", "clicking a product screenshot requests the larger viewer");
        Contains(window, "ImGui.OpenPopup(ScreenshotPopupId)", "screenshot clicks open a dedicated popup");
        Contains(window, "DrawScreenshotViewerModal();", "the screenshot popup is drawn every open marketplace frame");
        Contains(viewer, "Screenshot###DalagabOmegaScreenshot", "screenshot viewer has a stable dedicated popup identity");
        Contains(viewer, "ImGui.GetMainViewport()", "larger screenshot viewer sizes itself against the game viewport");
        Contains(viewer, "ImGui.Image(texture.Handle, size)", "larger screenshot viewer renders the cached source image");
        var artwork = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Artwork.cs"));
        Contains(artwork, "ImGuiStyleVar.WindowPadding, Vector2.Zero", "plugin artwork containers do not offset images with child-window padding");
        Contains(artwork, "GetWindowContentRegionMin()", "shared image centering accounts for the actual child content origin");
        Contains(artwork, "SetCursorCenteredInCurrentContent", "plugin artwork uses the shared horizontal and vertical centering helper");
        Contains(discover, "SetCursorCenteredInCurrentContent", "Discover project previews use the shared centering helper");
        Contains(product, "SetCursorCenteredInCurrentContent", "product project images use the shared centering helper");
        Contains(viewer, "SetCursorCenteredInCurrentContent", "large image viewer uses the shared centering helper");
        Contains(viewer, "ImGuiWindowFlags.NoTitleBar", "screenshot viewer uses Omega chrome instead of the host/default title bar");
        Contains(viewer, "DrawOmegaModalHeader(\"Screenshot\"", "screenshot viewer uses the shared Omega secondary-panel header");
        DoesNotContain(viewer, "Close##screenshot-viewer-close", "screenshot viewer does not duplicate the top-right close control at the bottom");
    }

    internal static void TestSecondaryPanelChromeContract()
    {
        var chrome = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ModalChrome.cs"));
        var settings = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Sources.cs"));
        var install = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Install.cs"));
        var uninstall = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.UninstallAndSources.cs"));
        var filters = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Filters.cs"));
        var eula = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Eula.cs"));

        Contains(chrome, "DrawOmegaModalHeader", "secondary panels share one Omega chrome implementation");
        Contains(chrome, "DrawApplicationIconButton(FontAwesomeIcon.Times", "secondary-panel X uses the same styled application control as the main panel");
        Contains(settings, "ImGuiWindowFlags.NoTitleBar", "Settings suppresses the host/default title bar");
        Contains(settings, "DrawOmegaModalHeader(\"Settings\"", "Settings uses Omega chrome");
        DoesNotContain(settings, "ImGui.Button(\"Close\")", "Settings has no redundant bottom Close button");
        Contains(install, "ImGuiWindowFlags.NoTitleBar", "install chooser suppresses the host/default title bar");
        Contains(install, "DrawOmegaModalHeader(\"Choose repository\"", "install chooser uses Omega chrome");
        Contains(uninstall, "ImGuiWindowFlags.NoTitleBar", "uninstall confirmation suppresses the host/default title bar");
        Contains(filters, "BeginPopupModal(\"Tags###DalagabOmegaTags\"", "tag picker is an Omega-styled modal panel");
        DoesNotContain(filters, "ImGui.Button(\"Close\")", "tag picker closes from its top-right X rather than a redundant footer button");
        Contains(eula, "DrawOmegaModalHeader(\"End User License Agreement\"", "EULA review uses Omega chrome");
        DoesNotContain(eula, "if (ImGui.Button(\"Close\"))", "EULA review has no redundant bottom Close button");
    }

}
