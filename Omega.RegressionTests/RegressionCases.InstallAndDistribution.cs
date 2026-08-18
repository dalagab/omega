using System.Buffers.Binary;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Dalagab.Omega;

namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestArtworkIconOverlayContract()
    {
        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "FontAwesomeIcon.InfoCircle", "information action uses an icon glyph");
        Contains(ui, "FontAwesomeIcon.Download", "install action uses an icon glyph");
        Contains(ui, "UiBuilder.IconFontFixedWidth", "fixed-width Dalamud icon font keeps action glyphs aligned");
        Contains(ui, "overlayMin = ImGui.GetCursorScreenPos()", "overlay origin follows the rendered image, not the outer tile");
        Contains(ui, "overlaySize = drawSize", "overlay bounds follow the rendered artwork dimensions");
        Contains(ui, "artworkMax = artworkMin + artworkSize", "overlays share one artwork rectangle");
        Contains(ui, "artworkMax.X - badgeWidth - inset", "API badge is inset from the artwork top-right");
        Contains(ui, "actionCount = canInstall ? 2 : 1", "action row packs according to visible actions");
        Contains(ui, "infoX = artworkMax.X - inset - rowWidth", "single info action remains right-aligned");
        Contains(ui, "draw.PushClipRect(clipMin, clipMax, true)", "overlay drawing is clipped to artwork bounds");

        var artwork = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Artwork.cs"));
        var topLayerCall = artwork.IndexOf("DrawArtworkTopLayer(plugin", StringComparison.Ordinal);
        var childEnd = artwork.IndexOf("ImGui.EndChild();", topLayerCall, StringComparison.Ordinal);
        True(topLayerCall >= 0 && childEnd > topLayerCall, "badge and actions are submitted before the artwork child ends so they remain on top");
        False(ui.Contains("primaryLabel = \"Prepare\"", StringComparison.Ordinal), "prepare must not be user-facing on artwork");
        False(ui.Contains("DrawArtworkActionButton(\"Info\"", StringComparison.Ordinal), "text Info pill must not return");
    }

    internal static void TestMarketplaceChromeOwnershipContract()
    {
        var ui = ReadMarketplaceWindowSource();
        var filters = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Filters.cs"));
        False(ui.Contains("CenterText(\"OMEGA\")", StringComparison.Ordinal), "header product title is removed");
        False(ui.Contains("CenterText(\"Dalagab Group\"", StringComparison.Ordinal), "header organization name is removed");
        False(ui.Contains("sidebar-filters", StringComparison.Ordinal), "global sidebar Filters control is removed");
        False(ui.Contains("content-reload", StringComparison.Ordinal), "general header Reload control is removed");
        False(ui.Contains("sidebar-refresh-sources", StringComparison.Ordinal), "manual source refresh no longer lives beside the navigation rail");
        Contains(ui, "FontAwesomeIcon.Cog", "Settings uses an icon-only navigation button");
        Contains(ui, "var rounding = Ui(6f)", "icon rail uses small-radius square navigation hit areas");
        Contains(ui, "##omega-nav-{id}", "icon rail owns dedicated borderless navigation hit boxes");
        Contains(ui, "no pill background and no border", "resting navigation blends into the sidebar panel");
        False(ui.Contains("DrawPillButton(icon.ToIconString()", StringComparison.Ordinal), "sidebar navigation must not regress to rounded pill buttons");
        Contains(ui, "activeView is MarketplaceView.Library or MarketplaceView.Updates", "Discover omits the redundant page-title and transient operation-message header");
        Contains(ui, "OpenSettings()", "Settings owns source-management entry");
        Contains(ui, "CheckForUpdates()", "Settings owns the dedicated update-check action");
        Contains(ui, "updates.CheckForUpdatesAsync()", "Settings update check delegates to the Definitions coordinator");
        Contains(ui, "##omega-about-version", "version remains visible and clickable at the icon-rail footer");
        Contains(ui, "OpenAbout()", "clicking the footer version opens About");
        Contains(ui, "DrawDefinitionsUpdateBanner();", "Updates page renders a Definitions update notice at its content header");
        Contains(ui, "Definitions update available", "pending Definitions state is clearly named for the user");
        Contains(ui, "counts.Updates + applicationUpdateCount + definitionsUpdateCount", "Updates destination count includes plugin, Omega and Definitions updates");
        Contains(ui, "notificationCount: counts.Updates + applicationUpdateCount", "Definitions updates do not inflate the red numeric badge");
        Contains(ui, "definitionsAttention: updates.DefinitionsUpdateAvailable", "Definitions updates use the dedicated blue exclamation marker");
        Contains(ui, "panel-filters-{activeView}", "Filters control belongs to the active content panel");
        Contains(ui, "var triangle = filtersOpen ? \"▲\" : \"▼\"", "Filters control exposes its open/closed state with a triangle");
        Contains(ui, "ImGuiStyleVar.FrameRounding, Ui(4f)", "Filters control uses a compact square-cornered Store-style shape");
        Contains(ui, "var openStylePushed = filtersOpen", "Filters toggle balances its open-state style even when the click closes the panel");
        Contains(ui, "filtersOpen = !filtersOpen", "panel Filters control expands and collapses inline");
        Contains(ui, "contentStartX + Math.Max(0f, contentWidth - buttonWidth)", "Filters button is anchored at the right edge of its owning content panel");
        Contains(ui, "ImGui.SetCursorPosX(contentStartX);", "right-aligned Filters control restores the full-width content origin before expansion");
        Contains(ui, "DrawInlineMarketplaceFilters(currentApi)", "full filter editor is hidden until Filters is expanded");
        var contentFlow = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.cs"));
        var filtersAt = contentFlow.IndexOf("DrawSearchAndCategoryButtons(currentApi)", StringComparison.Ordinal);
        var headerAt = contentFlow.IndexOf("DrawContentHeader(versionInfo.Version, currentApi)", StringComparison.Ordinal);
        var libraryTabsAt = contentFlow.IndexOf("DrawLibraryTabs(installed.Count)", StringComparison.Ordinal);
        True(filtersAt >= 0 && headerAt > filtersAt && libraryTabsAt > headerAt, "Filters must be the top content control before page headings and Library controls");
        var chromeSource = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Chrome.cs"));
        var updateBanner = Capture(chromeSource, @"private void DrawApplicationUpdateBanner\(\)\s*\{([\s\S]*?)\r?\n    \}");
        Contains(updateBanner, "ImGuiStyleVar.ChildRounding, Ui(4f)", "Omega update notice uses a compact square-cornered panel");
        Contains(ui, "DrawSelectedFilterPills()", "active filter pills remain visible while the editor is collapsed");
        Contains(ui, "omega-inline-filters", "expanded filters render in the owning content panel rather than a modal");
        Contains(filters, "CalculateInlineFilterPanelHeight()", "Discover and Library derive inline filter height from the responsive layout");
        Contains(filters, "ResponsiveColumns(available, 230f, 3, 12f)", "inline filter height follows the same responsive grid column rule as the controls");
        Contains(filters, "gridRows * frame * 2.15f", "inline filter height expands with the computed responsive grid row count");
        Contains(filters, "ImGuiStyleVar.ChildRounding, Ui(4f)", "expanded filter panel matches the scale-aware square-cornered Filters control");
        False(ui.Contains("Filters###DalagabOmegaFilters", StringComparison.Ordinal), "filter popup modal must not return");
        Contains(ui, "omega-application-bar", "window chrome is owned by one shared application top bar");
        Contains(ui, "##omega-application-mark", "application bar keeps a small Omega mark at top-left");
        Contains(ui, "##omega-global-search", "application bar owns the centered global plugin search");
        Contains(ui, "ActivateGlobalSearch", "global search routes every page into Discover results");
        Contains(ui, "##omega-appbar-{id}", "application-bar controls use dedicated borderless icon hit boxes");
        Contains(ui, "DrawApplicationIconButton(FontAwesomeIcon.Minus, \"minimize\"", "top-right minimize uses the shared Dalamud icon font");
        Contains(ui, "DrawApplicationIconButton(FontAwesomeIcon.Times, \"close\"", "top-right close uses the shared Dalamud icon font");
        False(ui.Contains("content-minimize", StringComparison.Ordinal), "retired pill-style content minimize control must not return");
        False(ui.Contains("DrawPillButton(\"—\"", StringComparison.Ordinal), "window controls must not regress to pill buttons");
        Contains(ui, "##omega-minimized-icon", "minimized state is one icon-sized interaction");
        Contains(ui, "omegaIconTexture", "minimized state renders the Omega product icon");
        Contains(ui, "ImGui.IsMouseDragging(ImGuiMouseButton.Left, 3f)", "holding and dragging moves the minimized icon");
        Contains(ui, "ImGui.SetWindowPos(ImGui.GetWindowPos() + delta", "minimized drag repositions the icon window");
        Contains(ui, "ImGuiWindowFlags.NoBackground", "minimized icon has no surrounding application panel");
        Contains(ui, "RestoreFromMinimizedMode", "clicking the icon restores the full marketplace");
        var chrome = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Chrome.cs"));
        var minimizeBody = Capture(chrome, @"private void EnterMinimizedMode\(\)\s*\{([\s\S]*?)\r?\n    \}");
        False(minimizeBody.Contains("ImGui.GetWindowSize()", StringComparison.Ordinal), "minimize must not snapshot the application-bar child width as the restore width");
        False(minimizeBody.Contains("ImGui.GetWindowPos()", StringComparison.Ordinal), "minimize must not snapshot the application-bar child position as the restore position");
        Contains(ui, "CaptureExpandedWindowState();", "expanded geometry is captured before entering the application-bar child");
        Contains(ui, "expandedWindowSize = ImGui.GetWindowSize();", "expanded size is captured while the top-level Omega window is current");
        Contains(ui, "if (expandedWindowSize.Y > Ui(96f))", "legacy app-bar-height geometry is detected and repaired with the current Dalamud scale");
        Contains(ui, "expandedWindowSize = preferredPhysical;", "corrupt collapsed geometry falls back to Omega's responsive default expanded size");
        Contains(ui, "ImGui.SetWindowSize(expandedWindowSize, ImGuiCond.Always);", "restore reapplies the remembered expanded size");
        False(ui.Contains("minimized-close", StringComparison.Ordinal), "minimized state must not add extra controls beside the icon");
    }

    internal static void TestMarketplaceMinimumWindowSizeContract()
    {
        var window = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.cs"));
        var chrome = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Chrome.cs"));
        Contains(window, "ForceMainWindow = true", "Omega remains attached to the game main viewport");
        Contains(window, "new(1080f, 840f)", "Omega minimum height reserves enough room for the marketplace shelves and metadata rows");
        Contains(window, "Size = DefaultExpandedWindowSize", "Omega opens at the minimum usable marketplace size on first use");
        Contains(window, "SizeCondition = ImGuiCond.FirstUseEver", "larger user-resized window geometry remains user-owned");
        Contains(window, "MinimumSize = DefaultExpandedWindowSize", "constructor keeps the baseline marketplace minimum before PreDraw applies the viewport-responsive constraint");
        Contains(window, "MaximumSize = new Vector2(float.MaxValue)", "Omega may be resized larger than its minimum");
        Contains(chrome, "SizeConstraints = null;", "minimized icon is exempt from marketplace minimum-size constraints");
        Contains(chrome, "MinimumSize = responsiveMinimum", "expanded mode restores the minimum-size constraint");
        Contains(chrome, "Flags &= ~(ImGuiWindowFlags.NoMove | ImGuiWindowFlags.NoResize)", "expanded Omega remains movable and resizable");
        False(chrome.Contains("ImGui.SetNextWindowSize(viewport.Size", StringComparison.Ordinal), "expanded Omega must not be forced full-screen");
        False(chrome.Contains("ImGui.SetNextWindowPos(viewport.Pos", StringComparison.Ordinal), "expanded Omega must not be pinned to the viewport origin");
        Contains(window, "migrateLegacyFullscreenGeometry = configuration.WindowGeometryRevision < 1", "legacy forced-full-screen geometry is migrated exactly once");
        Contains(chrome, "SizeCondition = ImGuiCond.Always", "migration overrides persisted full-screen size for one frame");
        Contains(chrome, "PositionCondition = ImGuiCond.Always", "migration recenters persisted full-screen geometry for one frame");
        Contains(chrome, "using Dalamud.Interface.Utility;", "geometry migration imports ImGuiHelpers from Dalamud Interface Utility");
        Contains(chrome, "configuration.WindowGeometryRevision = 1", "completed geometry migration is persisted");
        Contains(chrome, "Size = null", "post-migration window size returns to user ownership");
        Contains(chrome, "Position = null", "post-migration window position returns to user ownership");
        var configuration = File.ReadAllText(Path.Combine(Root, "Omega", "Configuration.cs"));
        Contains(configuration, "WindowGeometryRevision", "configuration tracks the one-time geometry migration independently");
    }

    internal static void TestInstallRepositoryChooserContract()
    {
        var ui = ReadMarketplaceWindowSource();
        var details = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Details.cs"));
        var awareness = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.RepositoryAwareness.cs"));
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginInstallCoordinator.cs"));
        var installer = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudInstallerBridge.cs"));

        Contains(ui, "Choose repository###DalagabOmegaInstall", "repository chooser popup");
        Contains(ui, "Choose which repository to use", "repository choice explanation");
        Contains(ui, "GetInstallCandidates", "compatible repository variants");
        Contains(ui, "ImGui.Button(actionLabel", "repository chooser keeps one explicit top action while allowing risk review to replace unsafe install");
        Contains(ui, "StartSelectedInstall", "selected source install flow");
        Contains(ui, "selectedNeedsRiskReview", "unacknowledged divergent repositories cannot be installed by the normal Install action");
        Contains(ui, "OpenInstallRepositoryRiskReview", "risky source selection opens install-specific repository review instead of installing immediately");
        Contains(ui, "DrawInstallRiskReviewModal", "risk review preserves install context and renders source evidence directly");
        Contains(ui, "Acknowledge risk", "risk review requires an explicit acknowledgement action");
        Contains(ui, "pendingInstallRiskAcknowledgementChecked", "risk acknowledgement requires an explicit user checkbox before proceeding");
        DoesNotContain(ui, "OpenDalamudRepositoryRiskReviewFromInstall", "install risk review no longer discards context by jumping to Settings");
        Contains(ui, "pendingInstallSourceUrl = string.Empty", "opening the chooser does not inherit a potentially risky displayed repository as the implicit selection");
        Contains(ui, "ImGuiSelectableFlags.DontClosePopups", "choosing a repository does not close the chooser before Install");
        DoesNotContain(ui, "DrawInstallProviderFilters", "repository chooser does not add a redundant provider-filter row");
        Contains(ui, "DrawRepositoryName", "repository names use shared provider presentation");
        Contains(ui, "MarketplaceLayoutRules.InstallSourceRowHeight", "repository chooser rows use tested deterministic geometry");
        Contains(ui, "DrawInstallRepositoryPresentMarker", "repositories already present in Dalamud receive a check marker");
        Contains(ui, "FontAwesomeIcon.Check", "present repository marker uses a standard icon");
        DoesNotContain(ui, "ImGui.Button(\"Cancel\")", "the modal close X is the only cancel control");
        True(
            ui.IndexOf("ImGui.Button(actionLabel", StringComparison.Ordinal) <
            ui.IndexOf("foreach (var candidate in candidates)", StringComparison.Ordinal),
            "Install/review action renders above repository choices");
        False(ui.Contains("Prepare this repository", StringComparison.Ordinal), "prepare wording hidden from marketplace user");

        Contains(details, ".OrderBy(v => IsPluginPackageArtifactDivergent(v) ? 1 : 0)", "known divergent package variants are demoted before source provider preference");
        Contains(details, "divergentSources.Contains(NormalizeUrl(v.SourceUrl)) ? 1 : 0", "repositories with known package divergence are not auto-preferred when a clean alternative exists");
        Contains(awareness, "AcknowledgedRepositoryRiskByUrl", "risk acknowledgement is source-specific and invalidates when evidence changes");

        Contains(details, "IsInstallSourceSelectable", "install candidates are not incorrectly blocked merely because an Omega source is disabled");
        Contains(details, "DescribeInstallUnavailability", "unavailable API-compatible plugins expose a concrete reason");
        Contains(ui, "ResolveOrCreateInstallSource", "explicit install can prepare a repository known only through Definitions");

        Contains(coordinator, "EnsureRepositoryReadyAsync", "hidden source preparation coordinator");
        Contains(coordinator, "EnsureIntegratedAsync", "Dalamud repository integration before install");
        Contains(coordinator, "SetManagedEnabledAsync", "Omega-managed disabled source recovery");
        Contains(coordinator, "EnableExistingForExplicitInstallAsync", "explicit install may enable a user-managed source without taking ownership");
        Contains(coordinator, "installer.InstallAsync", "coordinator delegates installation");
        Contains(installer, "InstallPluginAsync", "Dalamud remains package installation authority");

        var repositoryBridge = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudRepositoryBridge.cs"));
        Contains(repositoryBridge, "EnableExistingForExplicitInstallAsync", "explicit repository-enable bridge");
        Contains(repositoryBridge, "OwnedByOmega: false", "explicit enable does not steal repository ownership");
    }

    internal static void TestRepositoryProviderPreferenceContract()
    {
        var dalamud = RepositoryProviderRules.Classify("Dalamud official", "", true, 1);
        var puni = RepositoryProviderRules.Classify("Puni.sh — erdelf", "https://puni.sh/plugins", false, 5);
        var nightmare = RepositoryProviderRules.Classify("NightmareXIV", "https://github.com/NightmareXIV/MyDalamudPlugins", false, 5);
        var combatReborn = RepositoryProviderRules.Classify("Combat Reborn", "https://raw.githubusercontent.com/FFXIV-CombatReborn/CombatRebornRepo/main/pluginmaster.json", false, 5);
        var large = RepositoryProviderRules.Classify("Big community repository", "https://example.invalid/repo.json", false, RepositoryProviderRules.LargeRepositoryPluginThreshold);
        var other = RepositoryProviderRules.Classify("Small repository", "https://example.invalid/small.json", false, 2);

        Equal(RepositoryProviderKind.Dalamud, dalamud.Kind, "official repositories are preferred first");
        Equal(RepositoryProviderKind.PuniSh, puni.Kind, "Puni.sh identity is recognized");
        Equal(RepositoryProviderKind.NightmareXiv, nightmare.Kind, "NightmareXIV identity is recognized");
        Equal(RepositoryProviderKind.CombatReborn, combatReborn.Kind, "Combat Reborn is recognized as an explicit preferred provider");
        Equal(RepositoryProviderKind.LargeRepository, large.Kind, "broad repositories receive the promoted community tier");
        Equal(RepositoryProviderKind.Other, other.Kind, "small unrecognized repositories form the final tier");
        True(dalamud.Priority < puni.Priority && puni.Priority < nightmare.Priority && nightmare.Priority < combatReborn.Priority && combatReborn.Priority < large.Priority && large.Priority < other.Priority,
            "provider tiers remain ordered Dalamud, Puni.sh, NightmareXIV, Combat Reborn, broad repositories, other");
        True(!string.IsNullOrWhiteSpace(dalamud.IconUrl) && !string.IsNullOrWhiteSpace(puni.IconUrl) && !string.IsNullOrWhiteSpace(nightmare.IconUrl) && !string.IsNullOrWhiteSpace(combatReborn.IconUrl),
            "recognized preferred providers retain icon identities");
        False(RepositoryProviderRules.Classify("Big community repository", "https://example.invalid/repo.json", false, RepositoryProviderRules.LargeRepositoryPluginThreshold).Label.Contains("large", StringComparison.OrdinalIgnoreCase),
            "broad repository priority is not exposed as a Large list badge");
        True(RepositoryProviderRules.IsStableProvider("Dalamud official", "", true), "Dalamud can establish the package/security baseline");
        True(RepositoryProviderRules.IsStableProvider("Puni.sh", "https://puni.sh/repository", false), "Puni.sh can establish the package/security baseline");
        True(RepositoryProviderRules.IsStableProvider("NightmareXIV", "https://github.com/NightmareXIV/repo", false), "NightmareXIV can establish the package/security baseline");
        True(RepositoryProviderRules.IsStableProvider("Combat Reborn", "https://github.com/FFXIV-CombatReborn/CombatRebornRepo", false), "Combat Reborn can establish the package/security baseline");
        False(RepositoryProviderRules.IsStableProvider("Large community repository", "https://example.invalid/repo.json", false), "catalog size alone never makes a source a security baseline provider");
    }

    internal static void TestCatalogFirstRunLoadingContract()
    {
        var storefront = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Storefront.cs"));
        var loading = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Loading.cs"));
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "CatalogUpdateCoordinator.cs"));

        Contains(storefront, "updates.SeedIfEmpty();", "an empty catalog automatically keeps acquisition alive");
        Contains(storefront, "DrawCatalogLoadingState();", "first-run catalog acquisition uses the shared loading renderer");
        False(storefront.Contains("initial catalog snapshot", StringComparison.OrdinalIgnoreCase), "first-run state must not expose catalog implementation wording");
        False(storefront.Contains("Open Settings", StringComparison.Ordinal), "normal first-run acquisition must not ask the user to configure anything");
        False(storefront.Contains("SQLite catalog", StringComparison.OrdinalIgnoreCase), "normal first-run acquisition must not explain storage internals");

        Contains(loading, "GetContentRegionAvail()", "loading indicator centers within the owning content region");
        Contains(loading, "Environment.TickCount64", "loading indicator is animated rather than static");
        Contains(loading, "AddCircle(center", "loading indicator follows the shared restrained visual language");
        Contains(loading, "AddCircleFilled(dot", "loading indicator exposes visible rotation without user-facing text");
        False(loading.Contains("ImGui.Text", StringComparison.Ordinal), "loading state remains text-free");
        False(loading.Contains("ImGui.Button", StringComparison.Ordinal), "loading state remains action-free");

        Contains(coordinator, "EmptyCatalogRetryDelay", "empty-catalog acquisition retries automatically after bounded failures");
        Contains(coordinator, "nextEmptyCatalogAttemptUtc", "automatic retries are rate-limited rather than occurring every frame");
    }

}
