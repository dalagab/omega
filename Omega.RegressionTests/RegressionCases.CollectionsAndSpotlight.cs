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
        Contains(collections, "Library > All stays a clean list of installed plugins", "collection overview documents the separation between installed-list and collection management");
        Contains(collections, "DrawCollectionAddPicker", "membership additions are managed from inside an opened collection");
        Contains(collections, "Installed plugins not yet in this collection", "opened collections expose a searchable installed-plugin picker");
        Contains(collections, "+ Add plugins", "named collections expose an explicit add-membership action");
        Contains(ui, "DrawProductCollectionMembership", "the Discover individual product page exposes collection membership");
        Contains(ui, "multiple named collections at the same time", "the product page makes overlapping named collection membership explicit");
        Contains(ui, "StartAddPluginToCollection", "the collection-local picker starts a membership operation");
        Contains(ui, "StartRemovePluginFromCollection", "opened named collections support removing membership");
        Contains(ui, "StartCollectionPluginStateChange", "opened collections can change per-plugin desired state");
        Contains(ui, "GetPluginDirectControlState", "Library and Discover derive direct plugin control from Dalamud collection membership");
        Contains(ui, "Direct control is unavailable because this plugin is managed by:", "named collection membership visibly explains why direct plugin control is unavailable");
        Contains(ui, "OpenCollectionView", "collection membership can navigate directly into the selected collection");
        Contains(ui, "DrawToggleSwitch", "collection and plugin state use semantic toggle switches");
        Contains(ui, "Task.Run(() => profileBridge.SetCollectionEnabledAsync", "collection changes are delegated asynchronously");
        Contains(ui, "Task.Run(() => profileBridge.AddPluginToCollectionAsync", "collection-local membership additions are delegated asynchronously");
        Contains(ui, "Default plugins", "default Dalamud profile remains visible");
        Contains(ui, "Always active", "default profile is not presented as toggleable");

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
        Contains(spotlight, "contentStartY + 112f", "Spotlight card identity content is vertically aligned");
        Contains(spotlight, "contentStartY + 178f", "Spotlight pitch begins at the same vertical anchor on every card");
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
        Contains(spotlight, "DrawPluginScanAndAutomationIndicators", "all five promoted Spotlight cards use the shared exact-package scan/automation indicators");
        Contains(spotlight, "ResolveDefaultVariant(plugin)", "Spotlight resolves the same default repository package as the product page");
        Contains(spotlight, "!statusHovered", "Spotlight keeps scan/automation tooltips visible instead of overwriting them with the card tooltip");
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
        Contains(shelves, "DrawPluginScanAndAutomationIndicators", "latest additions and updates use the shared exact-package scan/automation indicators");
        Contains(shelves, "!statusHovered", "recency shelf scan/automation tooltips are not overwritten by the whole-card tooltip");
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
        Contains(chrome, "counts.Updates + definitionsUpdateCount", "Updates badge includes both plugin and Definitions updates");
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
        Contains(layout, "public const float LibraryRowHeight = 88f", "the shared Library row-height contract remains 88px");
        Contains(library, "const float rowHeight = MarketplaceLayoutRules.LibraryRowHeight", "Library and Updates consume the shared tested row-height contract");
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
        Contains(ui, "ImGui.Dummy(new Vector2(0f, 6f))", "Spotlight and Discover sit close to the top of the icon rail");
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

        Contains(product, "DrawDiscoverProductPage", "Discover selection uses a dedicated product page");
        Contains(product, "ProductHeroMaxWidth = 820f", "Discover product hero keeps a bounded right edge instead of stretching across the content pane");
        Contains(product, "Math.Min(ProductHeroMaxWidth, ImGui.GetContentRegionAvail().X)", "product hero remains responsive when the content pane is narrower than its preferred width");
        Contains(product, "ProductHeroHeight = 310f", "product hero reserves enough vertical room for its primary action");
        Contains(product, "CleanProductDescriptionForDisplay", "About removes redundant transport provenance from human-readable description copy");
        Contains(product, "product-about-metadata", "About uses a structured metadata table instead of a dense footer paragraph");
        Contains(product, "DrawProductSectionHeading", "About and Security use a shared readable section hierarchy");
        Contains(product, "Screenshots", "product page exposes the screenshot section");
        Contains(product, "style.WindowPadding.Y * 2f", "screenshot strip height reserves its vertical window padding");
        Contains(product, "style.ScrollbarSize + 4f", "screenshot strip reserves horizontal scrollbar height so a vertical scrollbar is not induced");
        Contains(product, "ImGuiWindowFlags.HorizontalScrollbar | ImGuiWindowFlags.NoScrollWithMouse", "screenshots remain a horizontal-only browsing strip");
        Contains(product, "MarketplacePresentationContent", "product page consumes the canonical presentation selection");
        Contains(product, "DrawDalamudOfficialLogoBadge", "official plugins use the Dalamud logo rather than a text badge");
        Contains(product, "★ Enhanced", "website-enriched product pages expose the enhanced marker");
        Contains(product, "DrawProductWebsiteIcon(plugin, enhancedUrl)", "enhanced product pages place their project link beside the Enhanced badge");
        Contains(product, "DrawProductSecuritySummary(plugin)", "security posture is summarized inside the product hero instead of as a detached block");
        Contains(product, "DrawProductCollectionMembership(plugin, installedPlugin)", "installed product pages show the plugin's collection membership directly below the hero");
        Contains(product, "foreach (var membership in memberships)", "all matching collection memberships are iterated instead of reducing membership to a single owner");
        Contains(product, "CollectionDisplayName(collection)", "each Discover collection membership is rendered from its own collection identity");
        False(product.Contains("Enhanced from:", StringComparison.Ordinal), "raw enrichment provenance wording must not return to the About section");
        False(product.Contains("DrawDetailsLinks(plugin)", StringComparison.Ordinal), "product pages do not append a detached project/source button row below About");
        Contains(product, "NSFW", "NSFW-tagged plugins receive a content badge");
        Contains(product, "Install", "product page uses Install as the acquisition action");
        False(product.Contains("Share", StringComparison.OrdinalIgnoreCase), "product page does not add a meaningless share control");
        Contains(storefront, "DrawDiscoverList(filtered", "Discover delegates to the result list");
        Contains(storefront, "DrawDiscoverProductPage", "selected Discover plugins replace the list with the product page");
    }



    internal static void TestDiscoverRiskOwnershipAndAvailabilityContract()
    {
        var discover = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Discover.cs"));
        var security = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.PluginSecurity.cs"));
        var artwork = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Artwork.cs"));
        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));

        Contains(discover, "DrawPluginScanAndAutomationIndicators", "Discover renders scan state and automation as separate indicators");
        Contains(discover, "ResolveDefaultVariant(plugin)", "Discover scan state is resolved from the same default repository package opened by the product page");
        Contains(artwork, "selectedPlugin = ResolveDefaultVariant(plugin)", "fresh product-page navigation starts from the same deterministic default package as listing security");
        Contains(security, "ResolvePluginSecurityVisual", "card and product-page scan presentation share one exact-package visual resolver");
        Contains(security, "DrawPluginSecurityScanIndicator", "marketplace cards consume the shared scan visual");
        Contains(security, "DrawProductSecuritySummary", "the product hero consumes the same shared scan visual");
        Contains(security, "FontAwesomeIcon.Question", "unscanned packages use a centered Font Awesome question icon");
        Contains(security, "FontAwesomeIcon.ExclamationTriangle", "incomplete and elevated scan results use Font Awesome's warning-triangle glyph");
        Contains(security, "FontAwesomeIcon.InfoCircle", "low/no-finding scans use a semantic info-circle glyph");
        Contains(discover, "UiBuilder.IconFontFixedWidth", "scan glyphs render through Dalamud's fixed-width icon font for reliable centering");
        DoesNotContain(discover, "DrawPluginWarningTriangle", "the old custom punctuation-in-triangle renderer must not return");
        Contains(discover, "DrawPluginRadiationIcon", "automation-capable packages use a dedicated nuclear/radiation icon");
        Contains(discover, "Automation is deliberately separate from scan severity", "automation can no longer replace the scan-result icon");
        Contains(discover, "if (!plugin.HasCompletedSecurityScan)", "automation state is only derived from the exact package after a completed scan");
        Contains(discover, "plugin.SecurityDependencies", "dependency automation starts from the selected package's own dependency evidence");
        DoesNotContain(discover, ".Concat(catalog.GetPresentationVariants(plugin.InternalName))", "scan/automation status must not aggregate a different repository variant");
        Contains(security, "\"No findings\"", "completed scans with no findings are labelled identically on card and product page");
        Contains(security, "0.20f, 0.72f, 0.42f", "no-finding scan icon uses the green success color");
        Contains(security, "0.94f, 0.58f, 0.12f", "medium scan results use the amber warning glyph");
        Contains(security, "0.92f, 0.12f, 0.15f", "critical scan results use the red warning glyph");
        Contains(discover, "DrawDiscoverInstalledMarker", "installed Discover entries get a dedicated installed-state marker on the left");
        Contains(discover, "0.20f, 0.72f, 0.42f", "installed state uses an unambiguous green marker instead of the old blue ownership block");
        Contains(discover, "draw.AddCircleFilled(center", "installed state is rendered as a compact green circle");
        Contains(discover, "draw.AddLine(min + new Vector2(6.5f, 13.2f)", "installed state draws the first stroke of a geometric check mark");
        Contains(discover, "draw.AddLine(min + new Vector2(10.8f, 17.3f)", "installed state draws the second stroke of a geometric check mark");
        DoesNotContain(discover, "for (var i = 0; i < 3; i++)", "the confusing three-bar ownership block must not return");
        Contains(discover, "DrawDiscoverPluginTitle", "installed titles have their own mild dimming path");
        Contains(discover, "\"↓\"", "uninstallable/outdated listings use a red down-arrow marker");
        Contains(discover, "var unavailable = !HasInstallableVariant", "installability decides whether the down arrow replaces the enhanced star");
        Contains(discover, "DrawDalamudOfficialLogoBadge", "official listings show the Dalamud logo instead of an Official text pill");
        Contains(discover, "DalamudAsset.LogoSmall", "the official badge uses Dalamud's own shipped logo asset");
        DoesNotContain(discover, "DrawDiscoverTextBadge(\"Official\"", "Discover no longer labels official plugins with text");
        Contains(plugin, "IDalamudAssetManager DalamudAssets", "Omega requests the public Dalamud asset service for the official logo");
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
        Contains(product, "View larger screenshot", "product screenshots advertise the larger viewer");
        Contains(product, "OpenScreenshotViewer(url)", "clicking a product screenshot requests the larger viewer");
        Contains(window, "ImGui.OpenPopup(ScreenshotPopupId)", "screenshot clicks open a dedicated popup");
        Contains(window, "DrawScreenshotViewerModal();", "the screenshot popup is drawn every open marketplace frame");
        Contains(viewer, "Screenshot###DalagabOmegaScreenshot", "screenshot viewer has a stable dedicated popup identity");
        Contains(viewer, "ImGui.GetMainViewport()", "larger screenshot viewer sizes itself against the game viewport");
        Contains(viewer, "ImGui.Image(texture.Handle, size)", "larger screenshot viewer renders the cached source image");
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
