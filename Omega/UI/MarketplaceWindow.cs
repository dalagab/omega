using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal enum MarketplaceView
{
    Spotlight,
    Discover,
    Installed,
    Installable,
    Outdated,
}

internal enum MarketplaceSort
{
    Name,
    LastUpdated,
    Downloads,
    HighestApi,
    Version,
}

internal enum RepositoryTaskKind
{
    None,
    Integrate,
    Detach,
    SetEnabled,
}

internal enum SourceManagerSection
{
    Curated,
    UserAdded,
}

internal sealed class MarketplaceWindow : Window, IDisposable
{
    private static readonly string[] PromotedInternalNames =
    [
        "HonseFarm.Client",
        "AetherLovePlugin",
        "InventoryTools",
        "GatherBuddyReborn",
        "ChatTwo",
    ];
    private readonly Configuration configuration;
    private readonly MarketplaceCatalogService catalog;
    private readonly CatalogUpdateCoordinator updates;
    private readonly DalamudInstallerBridge installer;
    private readonly DalamudRepositoryBridge repositoryBridge;
    private readonly PluginIconCache iconCache;
    private readonly string iconPath;
    private readonly string fallbackIconPath;

    private string search = string.Empty;
    private string author = string.Empty;
    private string selectedSource = "All sources";
    private string selectedCategory = "All categories";
    private int selectedApi;
    private MarketplaceView activeView;
    private MarketplaceSort sort = MarketplaceSort.Name;
    private bool resetStorefrontScroll;

    private MarketplacePlugin? selectedPlugin;
    private MarketplacePlugin? pendingInstall;
    private Task<InstallResult>? installTask;
    private string installingInternalName = string.Empty;
    private string operationMessage = string.Empty;

    private bool detailsOpen;
    private bool filtersOpen;
    private bool sourcesOpen;
    private bool installPopupOpen;
    private bool addSourceOpen;
    private bool requestInstallPopup;
    private bool requestFiltersPopup;
    private bool requestSourcesPopup;

    private SourceManagerSection sourceSection = SourceManagerSection.Curated;
    private string sourceSearch = string.Empty;
    private string newRepositoryName = string.Empty;
    private string newRepositoryUrl = string.Empty;
    private bool integrateNewRepositoryWithDalamud = true;

    private Task<RepositoryBridgeResult>? repositoryTask;
    private RepositorySource? repositoryTaskSource;
    private RepositoryTaskKind repositoryTaskKind;
    private readonly Dictionary<string, bool> sourceReadyCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> selectedVariantSource = new(StringComparer.OrdinalIgnoreCase);

    public MarketplaceWindow(
        Configuration configuration,
        MarketplaceCatalogService catalog,
        CatalogUpdateCoordinator updates,
        DalamudInstallerBridge installer,
        DalamudRepositoryBridge repositoryBridge,
        PluginIconCache iconCache,
        string iconPath,
        string fallbackIconPath)
        : base("Omega###DalagabOmegaMain")
    {
        this.configuration = configuration;
        this.catalog = catalog;
        this.updates = updates;
        this.installer = installer;
        this.repositoryBridge = repositoryBridge;
        this.iconCache = iconCache;
        this.iconPath = iconPath;
        this.fallbackIconPath = fallbackIconPath;
        Size = new Vector2(980, 720);
        SizeCondition = ImGuiCond.FirstUseEver;
        Flags = ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse;
    }

    public void Dispose()
    {
    }

    public override void Draw()
    {
        CompleteInstallTaskIfReady();
        CompleteRepositoryTaskIfReady();
        var versionInfo = Plugin.PluginInterface.GetDalamudVersion();
        var currentApi = Plugin.PluginInterface.Manifest.DalamudApiLevel;
        var installed = Plugin.PluginInterface.InstalledPlugins
            .ToDictionary(x => x.InternalName, StringComparer.OrdinalIgnoreCase);

        PushOmegaTheme();

        var available = ImGui.GetContentRegionAvail();
        var sidebarWidth = Math.Clamp(available.X * 0.19f, 168f, 194f);
        ImGui.BeginChild("omega-app-sidebar", new Vector2(sidebarWidth, 0f), false,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
        DrawSidebar(installed, currentApi, versionInfo.Version);
        ImGui.EndChild();

        ImGui.SameLine(0f, 16f);
        ImGui.BeginChild("omega-app-content", Vector2.Zero, false, ImGuiWindowFlags.NoScrollbar);
        DrawContentHeader(versionInfo.Version, currentApi);
        if (activeView != MarketplaceView.Spotlight)
            DrawSearchAndCategoryButtons(currentApi);
        else
            ImGui.TextDisabled("Five promoted plugins selected for the Omega Spotlight.");
        ImGui.Spacing();

        ImGui.BeginChild("omega-storefront", Vector2.Zero, false);
        DrawStorefrontLayout(installed, currentApi, versionInfo.Version);
        ImGui.EndChild();
        ImGui.EndChild();

        OpenRequestedPopups();
        DrawInstallModal(currentApi);
        DrawFiltersModal(currentApi);
        DrawSourcesModal();

        PopOmegaTheme();
    }

    private void OpenRequestedPopups()
    {
        if (requestInstallPopup)
        {
            ImGui.OpenPopup("Install plugin###DalagabOmegaInstall");
            requestInstallPopup = false;
        }

        if (requestFiltersPopup)
        {
            ImGui.OpenPopup("Filters###DalagabOmegaFilters");
            requestFiltersPopup = false;
        }

        if (requestSourcesPopup)
        {
            ImGui.OpenPopup("Sources###DalagabOmegaSources");
            requestSourcesPopup = false;
        }
    }

    private static void PushOmegaTheme()
    {
        ImGui.PushStyleColor(ImGuiCol.WindowBg, new Vector4(0.025f, 0.031f, 0.045f, 0.985f));
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0f, 0f, 0f, 0f));
        ImGui.PushStyleColor(ImGuiCol.PopupBg, new Vector4(0.035f, 0.043f, 0.060f, 0.99f));
        ImGui.PushStyleColor(ImGuiCol.FrameBg, new Vector4(0.070f, 0.085f, 0.115f, 0.95f));
        ImGui.PushStyleColor(ImGuiCol.FrameBgHovered, new Vector4(0.095f, 0.120f, 0.155f, 0.98f));
        ImGui.PushStyleColor(ImGuiCol.FrameBgActive, new Vector4(0.105f, 0.145f, 0.180f, 1f));
        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.070f, 0.085f, 0.115f, 0.92f));
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.090f, 0.150f, 0.175f, 1f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive, new Vector4(0.070f, 0.190f, 0.205f, 1f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.12f, 0.17f, 0.21f, 0.65f));
        ImGui.PushStyleColor(ImGuiCol.ScrollbarBg, new Vector4(0f, 0f, 0f, 0f));
        ImGui.PushStyleColor(ImGuiCol.ScrollbarGrab, new Vector4(0.11f, 0.22f, 0.24f, 0.78f));
        ImGui.PushStyleColor(ImGuiCol.ScrollbarGrabHovered, new Vector4(0.12f, 0.34f, 0.34f, 0.95f));

        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(18f, 16f));
        ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, 16f);
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, 14f);
        ImGui.PushStyleVar(ImGuiStyleVar.PopupRounding, 14f);
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 12f);
        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(11f, 7f));
        ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(10f, 8f));
        ImGui.PushStyleVar(ImGuiStyleVar.ScrollbarSize, 9f);
    }

    private static void PopOmegaTheme()
    {
        ImGui.PopStyleVar(8);
        ImGui.PopStyleColor(13);
    }

    private void DrawSidebar(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        const float logoSize = 64f;
        if (File.Exists(iconPath))
        {
            var icon = Plugin.TextureProvider.GetFromFile(iconPath).GetWrapOrDefault();
            if (icon is not null)
            {
                var startX = ImGui.GetCursorPosX();
                var width = ImGui.GetContentRegionAvail().X;
                ImGui.SetCursorPosX(startX + Math.Max(0f, (width - logoSize) * 0.5f));
                ImGui.Image(icon.Handle, new Vector2(logoSize, logoSize));
                ImGui.SetCursorPosX(startX);
            }
        }

        CenterText("OMEGA");
        CenterText("Dalagab Group", disabled: true);
        ImGui.Spacing();
        ImGui.Spacing();

        var mainPlugins = catalog.GetMainProjection(currentApi).Plugins;
        var catalogInstalledCount = mainPlugins.Count(x => installed.ContainsKey(x.InternalName));
        var installableCount = mainPlugins.Count(x =>
            !installed.ContainsKey(x.InternalName) && HasInstallableVariant(x.InternalName, currentApi, currentDalamudVersion));
        var outdatedCount = mainPlugins.Count(x =>
        {
            var highest = HighestKnownApiFor(x.InternalName, currentApi);
            return highest > 0 && highest < currentApi;
        });

        DrawSidebarView(MarketplaceView.Spotlight, "★  Spotlight", PromotedInternalNames.Length);
        DrawSidebarView(MarketplaceView.Discover, "Discover", mainPlugins.Count);
        DrawSidebarView(MarketplaceView.Installed, "Installed", catalogInstalledCount);
        DrawSidebarView(MarketplaceView.Installable, "Installable", installableCount);
        DrawSidebarView(MarketplaceView.Outdated, "Outdated", outdatedCount);

        var bottomControlsHeight = 116f;
        var targetY = Math.Max(ImGui.GetCursorPosY() + 12f, ImGui.GetWindowHeight() - bottomControlsHeight);
        ImGui.SetCursorPosY(targetY);

        var fullWidth = ImGui.GetContentRegionAvail().X;
        if (DrawPillButton("Sources", "sidebar-sources", new Vector2(fullWidth, 34f), sourcesOpen))
        {
            sourceReadyCache.Clear();
            sourcesOpen = true;
            requestSourcesPopup = true;
        }

        if (DrawPillButton("Filters", "sidebar-filters", new Vector2(fullWidth, 34f), filtersOpen))
        {
            filtersOpen = true;
            requestFiltersPopup = true;
        }

        CenterText($"v{BuildInfo.Version}", disabled: true);
    }

    private void DrawSidebarView(MarketplaceView view, string label, int count)
    {
        var active = activeView == view;
        var fullWidth = ImGui.GetContentRegionAvail().X;
        if (DrawPillButton($"{label}   {count}", $"sidebar-view-{view}", new Vector2(fullWidth, 38f), active))
        {
            activeView = view;
            resetStorefrontScroll = true;
        }
    }

    private void DrawContentHeader(Version dalamudVersion, int currentApi)
    {
        ImGui.TextUnformatted(ViewTitle(activeView));
        ImGui.TextDisabled($"Dalamud {dalamudVersion}  •  API {currentApi}");

        var closeWidth = 34f;
        var reloadWidth = 92f;
        var targetX = Math.Max(ImGui.GetCursorPosX(), ImGui.GetWindowWidth() - reloadWidth - closeWidth - 32f);
        ImGui.SameLine();
        ImGui.SetCursorPosX(targetX);
        if (DrawPillButton(updates.IsRefreshing ? "Loading…" : "Reload", "content-reload", new Vector2(reloadWidth, 32f), false) && !updates.IsRefreshing)
        {
            sourceReadyCache.Clear();
            _ = updates.RefreshAsync();
        }

        ImGui.SameLine(0f, 7f);
        if (DrawPillButton("×", "content-close", new Vector2(closeWidth, 32f), false, danger: true))
            IsOpen = false;

        if (!catalog.HasLoaded)
        {
            ImGui.TextDisabled("Local catalog is empty — Reload once to seed it");
        }
        else if (!catalog.MatchesConfiguredSources(configuration.Repositories))
        {
            ImGui.TextDisabled("Local catalog is missing one or more enabled sources — Reload to check them");
        }
        else if (catalog.LastRefresh is not null)
        {
            ImGui.TextDisabled($"{catalog.GetMainProjection(currentApi).Plugins.Count} plugins • {catalog.CachedRepositoryCount} cached sources • {updates.ModeLabel} • checked {catalog.LastRefresh.Value.LocalDateTime:t}");
        }

        if (!string.IsNullOrWhiteSpace(catalog.LastError))
        {
            ImGui.TextDisabled("Some sources failed during the last reload. Hover for details.");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(catalog.LastError);
        }

        if (!string.IsNullOrWhiteSpace(updates.LastOnlineError) && updates.Mode == CatalogAcquisitionMode.LocalFallback)
        {
            ImGui.TextDisabled("Central catalog unavailable — Omega is using the local source fallback.");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(updates.LastOnlineError);
        }

        if (!string.IsNullOrWhiteSpace(operationMessage))
            ImGui.TextWrapped(operationMessage);

        ImGui.Spacing();
    }

    private static bool DrawPillButton(string label, string id, Vector2 size, bool active, bool danger = false)
    {
        var screen = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##omega-pill-{id}", size);
        var hovered = ImGui.IsItemHovered();
        var held = ImGui.IsItemActive();
        var clicked = ImGui.IsItemClicked();
        var draw = ImGui.GetWindowDrawList();

        uint bg;
        uint border;
        if (danger)
        {
            bg = ImGui.ColorConvertFloat4ToU32(held
                ? new Vector4(0.55f, 0.10f, 0.13f, 0.95f)
                : hovered
                    ? new Vector4(0.38f, 0.09f, 0.12f, 0.92f)
                    : new Vector4(0.14f, 0.07f, 0.09f, 0.80f));
            border = ImGui.ColorConvertFloat4ToU32(new Vector4(0.70f, 0.16f, 0.20f, hovered ? 0.95f : 0.55f));
        }
        else
        {
            bg = ImGui.ColorConvertFloat4ToU32(active || held
                ? new Vector4(0.035f, 0.29f, 0.30f, 0.95f)
                : hovered
                    ? new Vector4(0.055f, 0.20f, 0.22f, 0.95f)
                    : new Vector4(0.065f, 0.080f, 0.105f, 0.88f));
            border = ImGui.ColorConvertFloat4ToU32(new Vector4(0.08f, 0.55f, 0.52f, active || hovered ? 0.90f : 0.28f));
        }

        draw.AddRectFilled(screen, screen + size, bg, size.Y * 0.5f);
        draw.AddRect(screen, screen + size, border, size.Y * 0.5f, ImDrawFlags.None, 1f);

        var textSize = ImGui.CalcTextSize(label);
        var textPos = screen + new Vector2((size.X - textSize.X) * 0.5f, (size.Y - textSize.Y) * 0.5f);
        draw.AddText(textPos, ImGui.GetColorU32(ImGuiCol.Text), label);
        return clicked;
    }

    private void DrawSearchAndCategoryButtons(int currentApi)
    {
        if (selectedSource != "All sources" &&
            !catalog.GetRepositoryStatuses(currentApi).Any(x =>
                !x.IsStale && x.SourceName.Equals(selectedSource, StringComparison.OrdinalIgnoreCase)))
        {
            selectedSource = "All sources";
        }

        ImGui.SetNextItemWidth(Math.Min(520f, Math.Max(280f, ImGui.GetContentRegionAvail().X * 0.48f)));
        if (ImGui.InputTextWithHint("##omega-search", "Search plugins, authors, tags...", ref search, 256))
            resetStorefrontScroll = true;
        if (!string.IsNullOrWhiteSpace(search))
        {
            ImGui.SameLine();
            if (DrawPillButton("Clear", "clear-search", new Vector2(62f, 30f), false))
            {
                search = string.Empty;
                resetStorefrontScroll = true;
            }
        }

        var mainProjection = catalog.GetMainProjection(currentApi, selectedSource);
        var mainPlugins = mainProjection.Plugins;

        ImGui.SameLine(0f, 10f);
        ImGui.SetNextItemWidth(170f);
        var authorLabel = string.IsNullOrWhiteSpace(author) ? "All authors" : Shorten(author, 20);
        if (ImGui.BeginCombo("##omega-author-filter", authorLabel))
        {
            if (ImGui.Selectable("All authors", string.IsNullOrWhiteSpace(author)))
            {
                author = string.Empty;
                resetStorefrontScroll = true;
            }

            foreach (var value in mainPlugins
                         .Select(x => x.Author)
                         .Where(x => !string.IsNullOrWhiteSpace(x))
                         .Distinct(StringComparer.OrdinalIgnoreCase)
                         .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                if (ImGui.Selectable(value, author.Equals(value, StringComparison.OrdinalIgnoreCase)))
                {
                    author = value;
                    resetStorefrontScroll = true;
                }
            }
            ImGui.EndCombo();
        }
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Filter the marketplace by plugin author");

        ImGui.SameLine(0f, 10f);
        ImGui.SetNextItemWidth(190f);
        var sourceLabel = selectedSource == "All sources" ? "All repositories" : Shorten(selectedSource, 24);
        if (ImGui.BeginCombo("##omega-repository-filter", sourceLabel))
        {
            if (ImGui.Selectable("All repositories", selectedSource == "All sources"))
            {
                selectedSource = "All sources";
                resetStorefrontScroll = true;
            }

            foreach (var status in catalog.GetRepositoryStatuses(currentApi)
                         .Where(x => !x.IsStale)
                         .OrderBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase))
            {
                if (ImGui.Selectable(status.SourceName, selectedSource.Equals(status.SourceName, StringComparison.OrdinalIgnoreCase)))
                {
                    selectedSource = status.SourceName;
                    author = string.Empty;
                    resetStorefrontScroll = true;
                }
            }
            ImGui.EndCombo();
        }
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Filter the marketplace by repository");

        var categories = mainPlugins
            .SelectMany(x => x.EffectiveCategories)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .GroupBy(x => x, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(x => x.Count())
            .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .Take(7)
            .Select(x => x.Key)
            .ToArray();

        ImGui.Spacing();
        var allCategoriesActive = selectedCategory == "All categories";
        if (DrawPillButton("All", "category-all", new Vector2(62f, 30f), allCategoriesActive))
        {
            selectedCategory = "All categories";
            resetStorefrontScroll = true;
        }

        foreach (var category in categories)
        {
            ImGui.SameLine(0f, 7f);
            var active = selectedCategory.Equals(category, StringComparison.OrdinalIgnoreCase);
            var width = Math.Clamp(ImGui.CalcTextSize(category).X + 26f, 66f, 130f);
            if (DrawPillButton(Shorten(category, 15), $"category-{StableId(category)}", new Vector2(width, 30f), active))
            {
                selectedCategory = category;
                resetStorefrontScroll = true;
            }
        }

        if (mainPlugins.SelectMany(x => x.EffectiveCategories).Distinct(StringComparer.OrdinalIgnoreCase).Count() > categories.Length)
        {
            ImGui.SameLine(0f, 7f);
            if (DrawPillButton("More", "more-filters", new Vector2(72f, 30f), false))
            {
                filtersOpen = true;
                requestFiltersPopup = true;
            }
        }
    }

    private void DrawStorefrontLayout(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (!detailsOpen || selectedPlugin is null)
        {
            DrawStorefront(installed, currentApi, currentDalamudVersion);
            return;
        }

        var available = ImGui.GetContentRegionAvail();
        if (available.X < 760f)
        {
            DrawPluginDetailsPanel(installed, currentApi, currentDalamudVersion);
            return;
        }

        var detailsWidth = Math.Clamp(available.X * 0.34f, 320f, 390f);
        var shelfWidth = Math.Max(320f, available.X - detailsWidth - 14f);

        ImGui.BeginChild("omega-plugin-shelf", new Vector2(shelfWidth, 0f), false);
        DrawStorefront(installed, currentApi, currentDalamudVersion);
        ImGui.EndChild();

        ImGui.SameLine(0f, 14f);
        ImGui.BeginChild("omega-plugin-details", Vector2.Zero, false);
        DrawPluginDetailsPanel(installed, currentApi, currentDalamudVersion);
        ImGui.EndChild();
    }

    private void DrawStorefront(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (resetStorefrontScroll)
        {
            ImGui.SetScrollY(0f);
            resetStorefrontScroll = false;
        }

        if (!catalog.HasLoaded)
        {
            ImGui.Spacing();
            ImGui.Text("Omega needs an initial catalog snapshot.");
            ImGui.TextWrapped("Omega first tries the published catalog database. If that cannot be downloaded or verified, it rebuilds the same local database from the bundled source list. Once seeded, the catalog is reused across restarts.");
            ImGui.Spacing();
            if (DrawPillButton("Reload Sources", "empty-reload", new Vector2(180f, 34f), true))
            {
                sourceReadyCache.Clear();
                _ = updates.RefreshAsync();
            }
            ImGui.SameLine();
            if (DrawPillButton("Manage Sources", "empty-sources", new Vector2(180f, 34f), false))
            {
                sourcesOpen = true;
                requestSourcesPopup = true;
            }
            return;
        }

        var mainProjection = catalog.GetMainProjection(
            currentApi,
            activeView == MarketplaceView.Spotlight ? "All sources" : selectedSource);

        if (activeView == MarketplaceView.Spotlight)
        {
            DrawSpotlightPage(mainProjection.Plugins, installed, currentApi, currentDalamudVersion);
            return;
        }

        var filtered = ApplyFilters(mainProjection.Plugins, installed, currentApi, currentDalamudVersion).ToArray();
        if (filtered.Length == 0)
        {
            ImGui.Text("No plugins match this shelf.");
            if (DrawPillButton("Reset filters", "empty-reset-filters", new Vector2(132f, 32f), false))
            {
                ResetFilters();
                resetStorefrontScroll = true;
            }
            return;
        }

        var availableWidth = ImGui.GetContentRegionAvail().X;
        const float targetTileWidth = 166f;
        const float gap = 16f;
        var columns = Math.Max(1, (int)Math.Floor((availableWidth + gap) / (targetTileWidth + gap)));
        var tileWidth = Math.Max(126f, (availableWidth - ((columns - 1) * gap)) / columns);

        ImGui.Text($"{ViewTitle(activeView)}  •  {filtered.Length} plugin{(filtered.Length == 1 ? string.Empty : "s")}");
        ImGui.SameLine();
        ImGui.TextDisabled("Scroll to browse");
        ImGui.Spacing();

        for (var index = 0; index < filtered.Length; index++)
        {
            var plugin = filtered[index];
            installed.TryGetValue(plugin.InternalName, out var installedPlugin);
            DrawPluginTile(plugin, installedPlugin, currentApi, currentDalamudVersion, tileWidth);

            if ((index + 1) % columns != 0 && index + 1 < filtered.Length)
            {
                ImGui.SameLine(0f, gap);
            }
            else
            {
                ImGui.Spacing();
            }
        }
    }

    private void DrawSpotlightPage(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        var promoted = PromotedInternalNames
            .Select(id => plugins.FirstOrDefault(x => x.InternalName.Equals(id, StringComparison.OrdinalIgnoreCase)))
            .Where(x => x is not null)
            .Cast<MarketplacePlugin>()
            .Take(5)
            .ToList();

        ImGui.TextColored(new Vector4(0.34f, 0.86f, 0.61f, 1f), "OMEGA SPOTLIGHT");
        ImGui.TextDisabled("Five promoted plugins");
        ImGui.Spacing();

        if (promoted.Count == 0)
        {
            ImGui.Text("Spotlight metadata is not in the local catalog yet.");
            ImGui.TextDisabled("Load or import the Omega catalog database to populate the five fixed promotions.");
            return;
        }

        var missingPromotions = PromotedInternalNames
            .Where(id => promoted.All(x => !x.InternalName.Equals(id, StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        if (missingPromotions.Length > 0)
        {
            ImGui.TextDisabled($"Waiting for catalog metadata: {string.Join(", ", missingPromotions)}");
            ImGui.Spacing();
        }

        var availableWidth = ImGui.GetContentRegionAvail().X;
        const float targetTileWidth = 166f;
        const float gap = 18f;
        var columns = Math.Max(1, Math.Min(5, (int)Math.Floor((availableWidth + gap) / (targetTileWidth + gap))));
        var tileWidth = Math.Max(126f, (availableWidth - ((columns - 1) * gap)) / columns);

        for (var index = 0; index < promoted.Count; index++)
        {
            var plugin = promoted[index];
            installed.TryGetValue(plugin.InternalName, out var installedPlugin);
            DrawPluginTile(plugin, installedPlugin, currentApi, currentDalamudVersion, tileWidth);

            if ((index + 1) % columns != 0 && index + 1 < promoted.Count)
                ImGui.SameLine(0f, gap);
            else
                ImGui.Spacing();
        }
    }

    private void DrawPluginTile(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion,
        float width)
    {
        var selectedVariant = plugin;
        var startX = ImGui.GetCursorPosX();
        ImGui.BeginGroup();

        var iconSize = Math.Clamp(width - 16f, 112f, 150f);
        var tileVisible = ImGui.IsRectVisible(new Vector2(width, iconSize + 54f));
        if (DrawPluginArtwork(selectedVariant, installedPlugin, iconSize, width, currentApi, currentDalamudVersion, tileVisible))
            OpenPluginDetails(selectedVariant);

        DrawCenteredTileText(Shorten(selectedVariant.Name, 24), width, false);
        DrawCenteredTileText(Shorten(string.IsNullOrWhiteSpace(selectedVariant.Author) ? "Unknown author" : selectedVariant.Author, 28), width, true);

        ImGui.SetCursorPosX(startX);
        ImGui.Dummy(new Vector2(width, 1f));
        ImGui.EndGroup();
    }

    private bool DrawPluginArtwork(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        float iconSize,
        float layoutWidth,
        int currentApi,
        Version currentDalamudVersion,
        bool queueIfVisible = true)
    {
        var startX = ImGui.GetCursorPosX();
        ImGui.SetCursorPosX(startX + Math.Max(0f, (layoutWidth - iconSize) * 0.5f));
        var artworkScreen = ImGui.GetCursorScreenPos();

        ImGui.PushStyleColor(ImGuiCol.ChildBg, 0u);
        ImGui.BeginChild($"artwork-{plugin.InternalName}-{StableId(plugin.SourceUrl)}", new Vector2(iconSize, iconSize), false,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var clicked = false;
        var texture = queueIfVisible ? iconCache.GetOrQueue(plugin.IconUrl) : null;
        var usingFallback = texture is null;
        if (texture is null && File.Exists(fallbackIconPath))
            texture = Plugin.TextureProvider.GetFromFile(fallbackIconPath).GetWrapOrDefault();

        if (texture is not null && texture.Size.X > 0 && texture.Size.Y > 0)
        {
            var scale = Math.Min(iconSize / texture.Size.X, iconSize / texture.Size.Y);
            var drawSize = texture.Size * scale;
            ImGui.SetCursorPos(new Vector2(
                Math.Max(0f, (iconSize - drawSize.X) * 0.5f),
                Math.Max(0f, (iconSize - drawSize.Y) * 0.5f)));
            ImGui.Image(texture.Handle, drawSize);
            clicked = ImGui.IsItemClicked();
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(usingFallback
                    ? $"{plugin.Name} has no usable artwork. Dalagab Group fallback shown."
                    : string.IsNullOrWhiteSpace(plugin.Punchline) ? $"Open {plugin.Name}" : plugin.Punchline);
        }
        else
        {
            ImGui.InvisibleButton($"artwork-placeholder-{plugin.InternalName}-{StableId(plugin.SourceUrl)}", new Vector2(iconSize, iconSize));
            clicked = ImGui.IsItemClicked();
            var text = "Ω";
            var textSize = ImGui.CalcTextSize(text);
            ImGui.SetCursorPos(new Vector2(
                Math.Max(0f, (iconSize - textSize.X) * 0.5f),
                Math.Max(0f, (iconSize - textSize.Y) * 0.5f)));
            ImGui.TextDisabled(text);
        }

        ImGui.EndChild();
        ImGui.PopStyleColor();

        var isSelected = detailsOpen && selectedPlugin is not null &&
                         selectedPlugin.InternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase) &&
                         NormalizeUrl(selectedPlugin.SourceUrl).Equals(NormalizeUrl(plugin.SourceUrl), StringComparison.OrdinalIgnoreCase);
        DrawArtworkSelection(plugin, artworkScreen, iconSize, isSelected, currentApi);
        DrawApiBadge(plugin, artworkScreen, iconSize, currentApi, currentDalamudVersion);
        var overlayConsumed = DrawArtworkOverlayActions(plugin, installedPlugin, artworkScreen, iconSize, currentApi, currentDalamudVersion);
        ImGui.SetCursorPosX(startX);
        return clicked && !overlayConsumed;
    }

    private void DrawApiBadge(
        MarketplacePlugin plugin,
        Vector2 artworkScreen,
        float iconSize,
        int currentApi,
        Version currentDalamudVersion)
    {
        var stableApi = catalog.GetStableApiLevel(plugin.InternalName, currentApi);
        var api = stableApi > 0
            ? stableApi
            : plugin.DisplayApiLevel(currentApi, configuration.PreferTestingBuilds);
        var supported = stableApi > 0
            ? stableApi == currentApi && catalog.GetVariants(plugin.InternalName).Any(v =>
                v.DalamudApiLevel == stableApi &&
                (v.MinimumDalamudVersion is null || v.MinimumDalamudVersion <= currentDalamudVersion))
            : plugin.SupportsApiLevel(currentApi, configuration.PreferTestingBuilds) &&
              (plugin.MinimumDalamudVersion is null || plugin.MinimumDalamudVersion <= currentDalamudVersion);
        var text = api > 0 ? api.ToString() : "?";
        var textSize = ImGui.CalcTextSize(text);
        var badgeHeight = 24f;
        var badgeWidth = Math.Max(28f, textSize.X + 14f);
        var min = new Vector2(artworkScreen.X + iconSize - badgeWidth - 6f, artworkScreen.Y + 6f);
        var max = min + new Vector2(badgeWidth, badgeHeight);
        var color = supported
            ? new Vector4(0.08f, 0.62f, 0.32f, 0.96f)
            : new Vector4(0.72f, 0.12f, 0.16f, 0.96f);
        var draw = ImGui.GetWindowDrawList();
        draw.AddRectFilled(min, max, ImGui.ColorConvertFloat4ToU32(color), badgeHeight * 0.5f);
        draw.AddText(
            min + new Vector2((badgeWidth - textSize.X) * 0.5f, (badgeHeight - textSize.Y) * 0.5f),
            0xFFFFFFFF,
            text);

        var mouse = ImGui.GetMousePos();
        if (mouse.X >= min.X && mouse.X <= max.X && mouse.Y >= min.Y && mouse.Y <= max.Y)
            ImGui.SetTooltip(stableApi > 0
                ? supported
                    ? $"Stable API {text} supported"
                    : $"Stable API {text} not supported by this Dalamud API {currentApi} build"
                : supported
                    ? $"API {text} supported"
                    : $"API {text} not supported by this Dalamud API {currentApi} build");
    }

    private void DrawArtworkSelection(
        MarketplacePlugin plugin,
        Vector2 artworkScreen,
        float iconSize,
        bool isSelected,
        int currentApi)
    {
        var draw = ImGui.GetWindowDrawList();
        if (isSelected)
        {
            draw.AddRect(
                artworkScreen - new Vector2(3f, 3f),
                artworkScreen + new Vector2(iconSize + 3f, iconSize + 3f),
                ImGui.ColorConvertFloat4ToU32(new Vector4(0.13f, 0.86f, 0.77f, 1f)),
                9f,
                ImDrawFlags.None,
                3f);
            DrawArtworkLabel("Selected", artworkScreen + new Vector2(6f, 6f), new Vector4(0.05f, 0.48f, 0.44f, 0.96f));
        }

        if (plugin.IsUnmaintained(currentApi))
        {
            var y = isSelected ? 34f : 6f;
            DrawArtworkLabel("Unmaintained", artworkScreen + new Vector2(6f, y), new Vector4(0.66f, 0.24f, 0.08f, 0.97f));
        }
    }

    private static void DrawArtworkLabel(string text, Vector2 min, Vector4 color)
    {
        var textSize = ImGui.CalcTextSize(text);
        var size = new Vector2(textSize.X + 12f, 22f);
        var draw = ImGui.GetWindowDrawList();
        draw.AddRectFilled(min, min + size, ImGui.ColorConvertFloat4ToU32(color), 11f);
        draw.AddText(min + new Vector2(6f, (22f - textSize.Y) * 0.5f), 0xFFFFFFFF, text);
    }

    private bool DrawArtworkOverlayActions(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        Vector2 artworkScreen,
        float iconSize,
        int currentApi,
        Version currentDalamudVersion)
    {
        const float gap = 6f;
        var infoWidth = 42f;
        var primaryLabel = string.Empty;
        var primaryWidth = 0f;

        if (installedPlugin is null)
        {
            var variants = catalog.GetVariants(plugin.InternalName);
            if (variants.Count > 1)
            {
                primaryLabel = "Source";
                primaryWidth = 58f;
            }
            else
            {
                var sourceReady = IsSourceReadyForInstall(plugin);
                var packageReady = plugin.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out _) &&
                                   (plugin.MinimumDalamudVersion is null || plugin.MinimumDalamudVersion <= currentDalamudVersion);
                primaryLabel = !sourceReady && !plugin.SourceIsOfficial ? "Prepare" : packageReady ? "Install" : "N/A";
                primaryWidth = primaryLabel == "Prepare" ? 62f : primaryLabel == "Install" ? 58f : 42f;
            }
        }

        var totalWidth = infoWidth + (primaryWidth > 0 ? gap + primaryWidth : 0f);
        var y = artworkScreen.Y + iconSize - 31f;
        var x = artworkScreen.X + Math.Max(5f, (iconSize - totalWidth) * 0.5f);
        var anyHoveredOrClicked = false;

        if (DrawArtworkActionButton("Info", $"art-info-{plugin.InternalName}-{StableId(plugin.SourceUrl)}", new Vector2(x, y), new Vector2(infoWidth, 26f), false, out var infoHovered))
        {
            OpenPluginDetails(plugin);
            anyHoveredOrClicked = true;
        }
        if (infoHovered)
        {
            ImGui.SetTooltip("Open plugin information");
            anyHoveredOrClicked = true;
        }

        if (primaryWidth <= 0f)
            return anyHoveredOrClicked;

        x += infoWidth + gap;
        var danger = primaryLabel == "N/A";
        if (DrawArtworkActionButton(primaryLabel, $"art-primary-{plugin.InternalName}-{StableId(plugin.SourceUrl)}", new Vector2(x, y), new Vector2(primaryWidth, 26f), danger, out var primaryHovered))
        {
            anyHoveredOrClicked = true;
            if (primaryLabel == "Source")
            {
                OpenPluginDetails(plugin);
                operationMessage = $"{plugin.Name} exists in {catalog.GetVariants(plugin.InternalName).Count} sources. Choose the source in Plugin information.";
            }
            else if (primaryLabel == "Prepare")
            {
                var source = FindConfiguredSource(plugin.SourceUrl);
                if (source is not null && repositoryTask is null)
                    StartRepositoryTask(source, RepositoryTaskKind.Integrate, repositoryBridge.EnsureIntegratedAsync(source.Url, source.Enabled));
            }
            else if (primaryLabel == "Install")
            {
                pendingInstall = plugin;
                installPopupOpen = true;
                requestInstallPopup = true;
            }
            else
            {
                OpenPluginDetails(plugin);
            }
        }
        if (primaryHovered)
        {
            ImGui.SetTooltip(primaryLabel switch
            {
                "Source" => "Choose which repository to use",
                "Prepare" => "Prepare this repository in Dalamud",
                "Install" => "Install this plugin",
                _ => "No compatible package is available",
            });
            anyHoveredOrClicked = true;
        }

        return anyHoveredOrClicked;
    }

    private static bool DrawArtworkActionButton(
        string label,
        string id,
        Vector2 screenPos,
        Vector2 size,
        bool danger,
        out bool hovered)
    {
        var restore = ImGui.GetCursorScreenPos();
        ImGui.SetCursorScreenPos(screenPos);
        ImGui.InvisibleButton($"##{id}", size);
        hovered = ImGui.IsItemHovered();
        var active = ImGui.IsItemActive();
        var clicked = ImGui.IsItemClicked();
        var draw = ImGui.GetWindowDrawList();
        var bg = danger
            ? new Vector4(0.55f, 0.10f, 0.13f, active ? 1f : hovered ? 0.96f : 0.90f)
            : new Vector4(0.035f, 0.09f, 0.12f, active ? 1f : hovered ? 0.98f : 0.90f);
        var border = danger
            ? new Vector4(0.95f, 0.28f, 0.30f, 0.95f)
            : new Vector4(0.12f, 0.78f, 0.70f, hovered ? 1f : 0.72f);
        draw.AddRectFilled(screenPos, screenPos + size, ImGui.ColorConvertFloat4ToU32(bg), 8f);
        draw.AddRect(screenPos, screenPos + size, ImGui.ColorConvertFloat4ToU32(border), 8f, ImDrawFlags.None, 1f);
        var textSize = ImGui.CalcTextSize(label);
        draw.AddText(screenPos + new Vector2((size.X - textSize.X) * 0.5f, (size.Y - textSize.Y) * 0.5f), 0xFFFFFFFF, label);
        ImGui.SetCursorScreenPos(restore);
        return clicked;
    }

    private static void DrawCenteredTileText(string text, float width, bool disabled)
    {
        var startX = ImGui.GetCursorPosX();
        var textWidth = ImGui.CalcTextSize(text).X;
        ImGui.SetCursorPosX(startX + Math.Max(0f, (width - textWidth) * 0.5f));
        if (disabled)
            ImGui.TextDisabled(text);
        else
            ImGui.TextUnformatted(text);
        ImGui.SetCursorPosX(startX);
    }

    private void OpenPluginDetails(MarketplacePlugin plugin)
    {
        selectedPlugin = ResolveSelectedVariant(plugin);
        detailsOpen = true;

        // With the central catalog active, opening details does not fan out to curated sources; only
        // matching user-added repositories may be checked. In fallback mode the prior per-plugin
        // conditional source check is retained.
        _ = updates.RefreshPluginSourcesAsync(plugin.InternalName);
    }

    private MarketplacePlugin ResolveSelectedVariant(MarketplacePlugin plugin)
    {
        var variants = catalog.GetVariants(plugin.InternalName);
        if (variants.Count == 0)
            return plugin;

        if (selectedVariantSource.TryGetValue(plugin.InternalName, out var sourceUrl))
        {
            var selected = variants.FirstOrDefault(x =>
                NormalizeUrl(x.SourceUrl).Equals(NormalizeUrl(sourceUrl), StringComparison.OrdinalIgnoreCase));
            if (selected is not null)
                return selected;
        }

        return variants[0];
    }

    private static string StableId(string value)
        => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value ?? string.Empty)))[..10];

    private static void CenterText(string text, bool disabled = false)
    {
        var textWidth = ImGui.CalcTextSize(text).X;
        var available = ImGui.GetContentRegionAvail().X;
        var startX = ImGui.GetCursorPosX();
        if (textWidth < available)
            ImGui.SetCursorPosX(startX + ((available - textWidth) * 0.5f));

        if (disabled)
            ImGui.TextDisabled(text);
        else
            ImGui.TextUnformatted(text);

        ImGui.SetCursorPosX(startX);
    }

    private IEnumerable<MarketplacePlugin> ApplyFilters(
        IEnumerable<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        var query = plugins;

        query = activeView switch
        {
            MarketplaceView.Installed => query.Where(x => installed.ContainsKey(x.InternalName)),
            MarketplaceView.Installable => query.Where(x =>
                !installed.ContainsKey(x.InternalName) && HasInstallableVariant(x.InternalName, currentApi, currentDalamudVersion)),
            MarketplaceView.Outdated => query.Where(x =>
            {
                var highest = HighestKnownApiFor(x.InternalName, currentApi);
                return highest > 0 && highest < currentApi;
            }),
            _ => query,
        };

        if (!string.IsNullOrWhiteSpace(search))
        {
            var needle = search.Trim();
            query = query.Where(x =>
                Contains(x.Name, needle) ||
                Contains(x.InternalName, needle) ||
                Contains(x.Punchline, needle) ||
                Contains(x.Description, needle) ||
                Contains(x.Author, needle) ||
                x.Tags.Any(tag => Contains(tag, needle)) ||
                x.EffectiveCategories.Any(category => Contains(category, needle)));
        }

        if (!string.IsNullOrWhiteSpace(author))
            query = query.Where(x => Contains(x.Author, author.Trim()));


        if (selectedCategory != "All categories")
            query = query.Where(x => x.EffectiveCategories.Contains(selectedCategory, StringComparer.OrdinalIgnoreCase));

        if (selectedApi != 0)
        {
            query = query.Where(x => catalog.GetVariants(x.InternalName).Any(v =>
                v.DalamudApiLevel == selectedApi ||
                v.TestingDalamudApiLevel == selectedApi ||
                (v.OmegaMinimumApiLevel.HasValue &&
                 v.OmegaMaximumApiLevel.HasValue &&
                 v.OmegaMinimumApiLevel.Value <= selectedApi &&
                 v.OmegaMaximumApiLevel.Value >= selectedApi)));
        }

        return sort switch
        {
            MarketplaceSort.LastUpdated => query.OrderByDescending(x => x.LastUpdate).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase),
            MarketplaceSort.Downloads => query.OrderByDescending(x => x.DownloadCount).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase),
            MarketplaceSort.HighestApi => query.OrderByDescending(x => x.HighestKnownApiLevel).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase),
            MarketplaceSort.Version => query.OrderByDescending(x => x.AssemblyVersion).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase),
            _ => query.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase),
        };
    }

    private bool HasInstallableVariant(string internalName, int currentApi, Version currentDalamudVersion)
    {
        return catalog.GetMainVariants(internalName, currentApi).Any(v =>
            v.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out _) &&
            (v.MinimumDalamudVersion is null || v.MinimumDalamudVersion <= currentDalamudVersion) &&
            IsSourceReadyForInstall(v));
    }

    private int HighestKnownApiFor(string internalName, int currentApi)
        => catalog.GetMainVariants(internalName, currentApi).Select(x => x.HighestKnownApiLevel).DefaultIfEmpty(0).Max();

    private void DrawPluginDetailsPanel(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (!detailsOpen || selectedPlugin is null)
            return;

        var plugin = ResolveSelectedVariant(selectedPlugin);
        selectedPlugin = plugin;
        installed.TryGetValue(plugin.InternalName, out var installedPlugin);

        if (DrawPillButton("Back", "details-back", new Vector2(70f, 30f), false))
        {
            detailsOpen = false;
            selectedPlugin = null;
            return;
        }

        ImGui.SameLine();
        ImGui.TextDisabled("Plugin information");
        ImGui.Spacing();

        var detailWidth = ImGui.GetContentRegionAvail().X;
        DrawPluginArtwork(
            plugin,
            installedPlugin,
            Math.Min(150f, Math.Max(112f, detailWidth - 40f)),
            detailWidth,
            currentApi,
            currentDalamudVersion);
        CenterText(plugin.Name);
        CenterText(string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author, disabled: true);
        ImGui.Spacing();

        var variants = catalog.GetVariants(plugin.InternalName);
        if (variants.Count > 1)
        {
            ImGui.TextDisabled($"Available from {variants.Count} sources");
            ImGui.Spacing();
            var rowStart = ImGui.GetCursorPosX();
            var used = 0f;
            var available = ImGui.GetContentRegionAvail().X;
            foreach (var variant in variants)
            {
                var label = $"{variant.SourceName}  •  API {(variant.HighestKnownApiLevel > 0 ? variant.HighestKnownApiLevel.ToString() : "?")}";
                var width = Math.Min(available, Math.Max(120f, ImGui.CalcTextSize(label).X + 28f));
                if (used > 0f && used + width > available)
                {
                    ImGui.NewLine();
                    ImGui.SetCursorPosX(rowStart);
                    used = 0f;
                }
                else if (used > 0f)
                {
                    ImGui.SameLine(0f, 7f);
                    used += 7f;
                }

                var active = NormalizeUrl(variant.SourceUrl).Equals(NormalizeUrl(plugin.SourceUrl), StringComparison.OrdinalIgnoreCase);
                if (DrawPillButton(label, $"variant-{plugin.InternalName}-{StableId(variant.SourceUrl)}", new Vector2(width, 30f), active))
                {
                    selectedVariantSource[plugin.InternalName] = variant.SourceUrl;
                    selectedPlugin = variant;
                    plugin = variant;
                    operationMessage = $"{plugin.Name} will use {plugin.SourceName}.";
                }
                used += width;
            }
            ImGui.NewLine();
        }

        ImGui.Separator();
        if (!string.IsNullOrWhiteSpace(plugin.Punchline))
            ImGui.TextWrapped(plugin.Punchline);
        if (!string.IsNullOrWhiteSpace(plugin.Description))
        {
            ImGui.Spacing();
            ImGui.TextWrapped(plugin.Description);
        }

        ImGui.Spacing();
        ImGui.Text($"Version: {plugin.AssemblyVersionText}");
        var detailsStableApi = catalog.GetStableApiLevel(plugin.InternalName, currentApi);
        ImGui.Text($"Stable API: {(detailsStableApi > 0 ? detailsStableApi.ToString() : "?")}");
        ImGui.Text($"Highest known API: {plugin.HighestKnownApiLevel}");
        if (plugin.TestingDalamudApiLevel is not null || plugin.TestingAssemblyVersion is not null)
            ImGui.TextDisabled($"Testing: {plugin.TestingAssemblyVersionText ?? "?"} / API {plugin.TestingDalamudApiLevel?.ToString() ?? "?"}");
        ImGui.TextWrapped($"Compatibility: {plugin.GetCompatibilityText(currentApi, currentDalamudVersion, configuration.PreferTestingBuilds)}");
        if (plugin.IsUnmaintained(currentApi))
            ImGui.TextColored(new Vector4(0.95f, 0.48f, 0.18f, 1f), $"Unmaintained: highest advertised API is {plugin.HighestKnownApiLevel} ({currentApi - plugin.HighestKnownApiLevel} API levels behind)");
        ImGui.TextWrapped($"Source: {plugin.SourceName}");

        if (plugin.Tags.Count > 0)
            ImGui.TextWrapped("Tags: " + string.Join(", ", plugin.Tags));
        if (plugin.EffectiveCategories.Count > 0)
            ImGui.TextWrapped("Categories: " + string.Join(", ", plugin.EffectiveCategories));

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        DrawDetailsPrimaryAction(plugin, installedPlugin, currentApi, currentDalamudVersion);

        ImGui.Spacing();
        if (!string.IsNullOrWhiteSpace(plugin.SourceUrl))
        {
            if (DrawPillButton("Copy source", $"copy-source-{StableId(plugin.SourceUrl)}", new Vector2(112f, 30f), false))
            {
                ImGui.SetClipboardText(plugin.SourceUrl);
                operationMessage = "Source URL copied.";
            }
        }

        if (!string.IsNullOrWhiteSpace(plugin.RepoUrl))
        {
            if (!string.IsNullOrWhiteSpace(plugin.SourceUrl))
                ImGui.SameLine(0f, 7f);
            if (DrawPillButton("Project", $"copy-project-{plugin.InternalName}", new Vector2(92f, 30f), false))
            {
                ImGui.SetClipboardText(plugin.RepoUrl);
                operationMessage = "Project URL copied.";
            }
        }
    }

    private void DrawDetailsPrimaryAction(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (installedPlugin is not null)
        {
            ImGui.TextDisabled($"Installed {installedPlugin.Version}  •  {(installedPlugin.IsLoaded ? "loaded" : "not loaded")}");
            return;
        }

        var sourceReady = IsSourceReadyForInstall(plugin);
        var packageReady = plugin.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out _) &&
                           (plugin.MinimumDalamudVersion is null || plugin.MinimumDalamudVersion <= currentDalamudVersion);

        if (!sourceReady && !plugin.SourceIsOfficial)
        {
            var source = FindConfiguredSource(plugin.SourceUrl);
            if (source is not null && repositoryTask is null)
            {
                var label = $"Prepare {Shorten(plugin.SourceName, 24)}";
                if (DrawPillButton(label, $"details-prepare-{StableId(plugin.SourceUrl)}", new Vector2(Math.Min(250f, Math.Max(150f, ImGui.CalcTextSize(label).X + 34f)), 36f), true))
                    StartRepositoryTask(source, RepositoryTaskKind.Integrate, repositoryBridge.EnsureIntegratedAsync(source.Url, source.Enabled));
            }
            else
            {
                ImGui.TextDisabled("Preparing source…");
            }

            return;
        }

        if (!packageReady)
        {
            ImGui.TextDisabled($"No compatible API {currentApi} package is advertised by {plugin.SourceName}.");
            return;
        }

        if (installTask is not null && installingInternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase))
        {
            ImGui.TextDisabled("Installing…");
            return;
        }

        var installLabel = $"Install from {Shorten(plugin.SourceName, 24)}";
        if (DrawPillButton(installLabel, $"details-install-{StableId(plugin.SourceUrl)}", new Vector2(Math.Min(270f, Math.Max(160f, ImGui.CalcTextSize(installLabel).X + 34f)), 36f), true))
        {
            pendingInstall = plugin;
            installPopupOpen = true;
            requestInstallPopup = true;
        }
    }

    private void DrawInstallModal(int currentApi)
    {
        if (!installPopupOpen || pendingInstall is null)
            return;

        var keepOpen = installPopupOpen;
        if (!ImGui.BeginPopupModal("Install plugin###DalagabOmegaInstall", ref keepOpen, ImGuiWindowFlags.AlwaysAutoResize))
        {
            installPopupOpen = keepOpen;
            return;
        }

        var plugin = pendingInstall;
        plugin.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out var useTesting);

        ImGui.Text($"Install {plugin.Name}?");
        ImGui.Separator();
        ImGui.Text($"Version: {(useTesting ? plugin.TestingAssemblyVersionText : plugin.AssemblyVersionText)}");
        ImGui.Text($"API: {(useTesting ? plugin.TestingDalamudApiLevel : plugin.DalamudApiLevel)}");
        ImGui.Text($"Source: {plugin.SourceName}");
        ImGui.TextWrapped("Plugin packages execute code inside the FFXIV process. Install only from sources you trust.");

        if (ImGui.Button("Install"))
        {
            installingInternalName = plugin.InternalName;
            operationMessage = $"Installing {plugin.Name}...";
            installTask = installer.InstallAsync(plugin, configuration.PreferTestingBuilds);
            pendingInstall = null;
            installPopupOpen = false;
            ImGui.CloseCurrentPopup();
        }

        ImGui.SameLine();
        if (ImGui.Button("Cancel"))
        {
            pendingInstall = null;
            installPopupOpen = false;
            ImGui.CloseCurrentPopup();
        }

        installPopupOpen = keepOpen && installPopupOpen;
        ImGui.EndPopup();
    }

    private void DrawFiltersModal(int currentApi)
    {
        if (!filtersOpen)
            return;

        var keepOpen = filtersOpen;
        if (!ImGui.BeginPopupModal("Filters###DalagabOmegaFilters", ref keepOpen, ImGuiWindowFlags.AlwaysAutoResize))
        {
            filtersOpen = keepOpen;
            return;
        }

        ImGui.Text("Advanced filters");
        ImGui.TextDisabled("These filters are local and never download source JSON.");
        ImGui.Separator();

        ImGui.SetNextItemWidth(360);
        ImGui.InputTextWithHint("Author##filter-author", "Author contains...", ref author, 128);

        var sources = new[] { "All sources" }
            .Concat(catalog.GetRepositoryStatuses(currentApi)
                .Where(x => !x.IsStale)
                .Select(x => x.SourceName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        DrawStringCombo("Source", ref selectedSource, sources, 360);

        var filterPlugins = catalog.GetMainProjection(currentApi, selectedSource).Plugins;
        var categories = new[] { "All categories" }
            .Concat(filterPlugins
                .SelectMany(x => x.EffectiveCategories)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        DrawStringCombo("Category", ref selectedCategory, categories, 360);

        var apis = filterPlugins
            .SelectMany(x => new[] { x.DalamudApiLevel, x.TestingDalamudApiLevel ?? 0, x.OmegaMaximumApiLevel ?? 0 })
            .Where(x => x > 0)
            .Append(currentApi)
            .Distinct()
            .OrderByDescending(x => x)
            .ToArray();

        ImGui.SetNextItemWidth(360);
        var apiLabel = selectedApi == 0 ? "Any API" : $"API {selectedApi}";
        if (ImGui.BeginCombo("API##filter-api", apiLabel))
        {
            if (ImGui.Selectable("Any API", selectedApi == 0))
                selectedApi = 0;
            foreach (var api in apis)
            {
                if (ImGui.Selectable($"API {api}", selectedApi == api))
                    selectedApi = api;
            }
            ImGui.EndCombo();
        }

        ImGui.SetNextItemWidth(360);
        if (ImGui.BeginCombo("Sort##filter-sort", SortLabel(sort)))
        {
            foreach (var value in Enum.GetValues<MarketplaceSort>())
            {
                if (ImGui.Selectable(SortLabel(value), sort == value))
                    sort = value;
            }
            ImGui.EndCombo();
        }

        var preferTesting = configuration.PreferTestingBuilds;
        if (ImGui.Checkbox("Allow testing builds", ref preferTesting))
        {
            configuration.PreferTestingBuilds = preferTesting;
            configuration.Save();
        }

        ImGui.Separator();
        if (ImGui.Button("Reset filters"))
            ResetFilters();
        ImGui.SameLine();
        if (ImGui.Button("Close"))
        {
            filtersOpen = false;
            ImGui.CloseCurrentPopup();
        }

        filtersOpen = keepOpen && filtersOpen;
        ImGui.EndPopup();
    }

    private void DrawSourcesModal()
    {
        if (!sourcesOpen)
            return;

        var keepOpen = sourcesOpen;
        if (!ImGui.BeginPopupModal("Sources###DalagabOmegaSources", ref keepOpen, ImGuiWindowFlags.AlwaysAutoResize))
        {
            sourcesOpen = keepOpen;
            return;
        }

        var currentApi = Plugin.PluginInterface.Manifest.DalamudApiLevel;
        var curatedCount = configuration.Repositories.Count(x => x.IsCurated);
        var userCount = configuration.Repositories.Count(x => !x.IsCurated);

        ImGui.Text("Omega Sources");
        ImGui.TextWrapped("Checked repositories participate in Omega's local catalog. Uncheck any repository you do not want. Stale repositories stay listed here but their plugins are hidden from the main marketplace.");
        ImGui.TextDisabled(updates.OnlineConfigured
            ? $"Central catalog: configured • current mode: {updates.ModeLabel}"
            : "Central catalog: not configured yet • local source fallback remains available");
        ImGui.Separator();

        if (ImGui.Button(sourceSection == SourceManagerSection.Curated ? $"[Curated ({curatedCount})]" : $"Curated ({curatedCount})"))
        {
            sourceSection = SourceManagerSection.Curated;
            sourceSearch = string.Empty;
        }
        ImGui.SameLine();
        if (ImGui.Button(sourceSection == SourceManagerSection.UserAdded ? $"[My Sources ({userCount})]" : $"My Sources ({userCount})"))
        {
            sourceSection = SourceManagerSection.UserAdded;
            sourceSearch = string.Empty;
        }
        ImGui.SameLine();
        if (ImGui.Button(addSourceOpen ? "Hide add tools" : "Add Sources"))
            addSourceOpen = !addSourceOpen;

        ImGui.SetNextItemWidth(520f);
        ImGui.InputTextWithHint("##source-search", "Filter repositories by name or URL...", ref sourceSearch, 256);

        var shownSources = configuration.Repositories
            .Where(x => sourceSection == SourceManagerSection.Curated ? x.IsCurated : !x.IsCurated)
            .Where(x => string.IsNullOrWhiteSpace(sourceSearch) ||
                        Contains(x.Name, sourceSearch.Trim()) ||
                        Contains(x.Url, sourceSearch.Trim()))
            .OrderByDescending(x => x.IsOfficial)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var statuses = catalog.GetRepositoryStatuses(currentApi)
            .ToDictionary(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase);

        ImGui.Spacing();
        if (ImGui.BeginTable("omega-source-table", 5, ImGuiTableFlags.None, new Vector2(860f, 360f), 0f))
        {
            ImGui.TableSetupColumn("Use");
            ImGui.TableSetupColumn("Repository");
            ImGui.TableSetupColumn("Plugins");
            ImGui.TableSetupColumn("API");
            ImGui.TableSetupColumn("State");
            ImGui.TableHeadersRow();

            foreach (var source in shownSources)
            {
                statuses.TryGetValue(NormalizeUrl(source.Url), out var status);
                ImGui.TableNextRow();

                ImGui.TableSetColumnIndex(0);
                var enabled = source.Enabled;
                if (ImGui.Checkbox($"##source-enabled-{StableId(source.Url)}", ref enabled))
                {
                    source.Enabled = enabled;
                    sourceReadyCache.Clear();
                    configuration.Save();
                    catalog.LoadCached(configuration.Repositories);
                    operationMessage = $"{source.Name} {(enabled ? "enabled" : "disabled")} in Omega.";
                    if (!source.IsOfficial &&
                        source.IntegrateWithDalamud &&
                        source.DalamudManagedByOmega &&
                        repositoryTask is null)
                    {
                        StartRepositoryTask(source, RepositoryTaskKind.SetEnabled, repositoryBridge.SetManagedEnabledAsync(source.Url, enabled));
                    }
                }

                ImGui.TableSetColumnIndex(1);
                ImGui.TextUnformatted(source.Name);
                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip(source.Url);

                ImGui.TableSetColumnIndex(2);
                ImGui.Text(status?.PluginCount.ToString() ?? "—");

                ImGui.TableSetColumnIndex(3);
                ImGui.Text(status is null || status.HighestKnownApiLevel <= 0 ? "?" : status.HighestKnownApiLevel.ToString());

                ImGui.TableSetColumnIndex(4);
                if (!source.Enabled)
                    ImGui.TextDisabled("Disabled");
                else if (status?.IsStale == true)
                {
                    ImGui.TextColored(new Vector4(0.95f, 0.48f, 0.18f, 1f), "Stale");
                    if (ImGui.IsItemHovered())
                        ImGui.SetTooltip("Every cached plugin in this repository is at least three Dalamud API levels behind current. Its plugins are hidden from the main marketplace.");
                }
                else if (status is null)
                    ImGui.TextDisabled("Not cached");
                else
                    ImGui.TextColored(new Vector4(0.34f, 0.86f, 0.61f, 1f), "Active");
            }

            ImGui.EndTable();
        }

        if (addSourceOpen)
            DrawAddSourceTools();

        ImGui.Separator();
        if (ImGui.Button(updates.IsRefreshing ? "Reloading..." : "Reload Sources") && !updates.IsRefreshing)
        {
            sourceReadyCache.Clear();
            _ = updates.RefreshAsync();
        }
        ImGui.SameLine();
        if (ImGui.Button("Close"))
        {
            sourcesOpen = false;
            ImGui.CloseCurrentPopup();
        }

        sourcesOpen = keepOpen && sourcesOpen;
        ImGui.EndPopup();
    }

    private void DrawAddSourceTools()
    {
        ImGui.Separator();
        ImGui.Text("Add one source");
        ImGui.TextDisabled("A source may contain one plugin or many; it still needs to be a PluginMaster-compatible HTTPS JSON endpoint for Dalamud servicing.");
        ImGui.SetNextItemWidth(220);
        ImGui.InputTextWithHint("##newRepoName", "Source name", ref newRepositoryName, 128);
        ImGui.SetNextItemWidth(480);
        ImGui.InputTextWithHint("##newRepoUrl", "https://.../pluginmaster.json", ref newRepositoryUrl, 512);

        ImGui.Checkbox("Register this source with Dalamud", ref integrateNewRepositoryWithDalamud);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("When enabled, Omega also registers the source with Dalamud so plugins installed from it remain serviceable.");

        if (ImGui.Button("Add to My Sources") &&
            Uri.TryCreate(newRepositoryUrl.Trim(), UriKind.Absolute, out var uri) &&
            uri.Scheme == Uri.UriSchemeHttps)
        {
            var normalized = NormalizeUrl(uri.ToString());
            var duplicate = configuration.Repositories.Any(x =>
                NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase));

            if (duplicate)
            {
                operationMessage = "That source URL is already known to Omega.";
            }
            else
            {
                var source = new RepositorySource
                {
                    Name = string.IsNullOrWhiteSpace(newRepositoryName) ? uri.Host : newRepositoryName.Trim(),
                    Url = uri.ToString(),
                    Enabled = true,
                    IsCurated = false,
                    IsExperimental = true,
                };
                configuration.Repositories.Add(source);
                sourceReadyCache.Clear();
                configuration.Save();
                catalog.LoadCached(configuration.Repositories);
                newRepositoryName = string.Empty;
                newRepositoryUrl = string.Empty;
                sourceSection = SourceManagerSection.UserAdded;
                sourceSearch = string.Empty;
                operationMessage = $"Added {source.Name}. Reload Sources once when you want to seed or update its local catalog record.";

                if (integrateNewRepositoryWithDalamud && repositoryTask is null)
                    StartRepositoryTask(source, RepositoryTaskKind.Integrate, repositoryBridge.EnsureIntegratedAsync(source.Url, source.Enabled));
            }
        }

        ImGui.Spacing();
        ImGui.Text("Bulk import");
        ImGui.TextWrapped("Copy many HTTPS PluginMaster JSON URLs and press the button. Bulk imports are added to My Sources only and are not registered with Dalamud automatically.");
        if (ImGui.Button("Paste URL list from clipboard"))
        {
            var result = AddRepositoryList(ImGui.GetClipboardText());
            sourceSection = SourceManagerSection.UserAdded;
            sourceSearch = string.Empty;
            operationMessage = result.Added > 0
                ? $"Added {result.Added} source(s); {result.Duplicates} duplicate(s), {result.Invalid} invalid. Reload Sources when you want to seed/update them."
                : $"No sources added; {result.Duplicates} duplicate(s), {result.Invalid} invalid.";
        }
    }

    private (int Added, int Duplicates, int Invalid) AddRepositoryList(string text)
    {
        var tokens = text.Split(
            new[] { '\r', '\n', '\t', ';', ' ' },
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var added = 0;
        var duplicates = 0;
        var invalid = 0;
        var known = configuration.Repositories
            .Select(x => NormalizeUrl(x.Url))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var token in tokens)
        {
            if (!Uri.TryCreate(token, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            {
                invalid++;
                continue;
            }

            var normalized = NormalizeUrl(uri.ToString());
            if (!known.Add(normalized))
            {
                duplicates++;
                continue;
            }

            configuration.Repositories.Add(new RepositorySource
            {
                Name = uri.Host,
                Url = uri.ToString(),
                Enabled = true,
                IsCurated = false,
                IsExperimental = true,
                IntegrateWithDalamud = false,
                DalamudManagedByOmega = false,
            });
            added++;
        }

        if (added > 0)
        {
            sourceReadyCache.Clear();
            configuration.Save();
            catalog.LoadCached(configuration.Repositories);
        }

        return (added, duplicates, invalid);
    }

    private void StartRepositoryTask(RepositorySource source, RepositoryTaskKind kind, Task<RepositoryBridgeResult> task)
    {
        if (repositoryTask is not null)
            return;

        repositoryTaskSource = source;
        repositoryTaskKind = kind;
        repositoryTask = task;
        operationMessage = kind switch
        {
            RepositoryTaskKind.Integrate => $"Preparing {source.Name} for Dalamud servicing...",
            RepositoryTaskKind.Detach => $"Detaching {source.Name} from Dalamud...",
            RepositoryTaskKind.SetEnabled => $"Synchronizing {source.Name} with Dalamud...",
            _ => "Updating source...",
        };
    }

    private void CompleteRepositoryTaskIfReady()
    {
        if (repositoryTask is null || !repositoryTask.IsCompleted)
            return;

        var source = repositoryTaskSource;
        try
        {
            var result = repositoryTask.GetAwaiter().GetResult();
            operationMessage = result.Message;
            if (source is not null)
            {
                switch (repositoryTaskKind)
                {
                    case RepositoryTaskKind.Integrate when result.Success:
                        source.IntegrateWithDalamud = true;
                        source.DalamudManagedByOmega = result.OwnedByOmega;
                        break;
                    case RepositoryTaskKind.Detach when result.Success:
                        source.IntegrateWithDalamud = false;
                        source.DalamudManagedByOmega = false;
                        break;
                    case RepositoryTaskKind.SetEnabled when !result.Success:
                        var state = repositoryBridge.GetState(source.Url);
                        if (state.Available && state.Present)
                            source.Enabled = state.Enabled;
                        break;
                }

                sourceReadyCache.Clear();
                configuration.Save();
                catalog.LoadCached(configuration.Repositories);
            }
        }
        catch (Exception ex)
        {
            operationMessage = $"Source operation failed: {ex.GetBaseException().Message}";
        }
        finally
        {
            repositoryTask = null;
            repositoryTaskSource = null;
            repositoryTaskKind = RepositoryTaskKind.None;
        }
    }

    private void CompleteInstallTaskIfReady()
    {
        if (installTask is null || !installTask.IsCompleted)
            return;

        try
        {
            operationMessage = installTask.GetAwaiter().GetResult().Message;
        }
        catch (Exception ex)
        {
            operationMessage = $"Install failed: {ex.GetBaseException().Message}";
        }
        finally
        {
            installTask = null;
            installingInternalName = string.Empty;
        }
    }

    private RepositorySource? FindConfiguredSource(string sourceUrl)
    {
        var normalized = NormalizeUrl(sourceUrl);
        return configuration.Repositories.FirstOrDefault(x =>
            NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsSourceReadyForInstall(MarketplacePlugin plugin)
    {
        if (plugin.SourceIsOfficial)
            return true;

        var sourceUrl = NormalizeUrl(plugin.SourceUrl);
        if (sourceReadyCache.TryGetValue(sourceUrl, out var cached))
            return cached;

        var configured = configuration.Repositories.FirstOrDefault(repo =>
            repo.Enabled &&
            repo.IntegrateWithDalamud &&
            NormalizeUrl(repo.Url).Equals(sourceUrl, StringComparison.OrdinalIgnoreCase));

        if (configured is null)
            return sourceReadyCache[sourceUrl] = false;

        var state = repositoryBridge.GetState(configured.Url);
        return sourceReadyCache[sourceUrl] = state.Available && state.Present && state.Enabled;
    }

    private void ResetFilters()
    {
        search = string.Empty;
        author = string.Empty;
        selectedSource = "All sources";
        selectedCategory = "All categories";
        selectedApi = 0;
        sort = MarketplaceSort.Name;
    }

    private static string ViewTitle(MarketplaceView view) => view switch
    {
        MarketplaceView.Spotlight => "Spotlight",
        MarketplaceView.Installed => "Installed plugins",
        MarketplaceView.Installable => "Ready to install",
        MarketplaceView.Outdated => "Outdated API",
        _ => "Discover",
    };

    private static string SortLabel(MarketplaceSort value) => value switch
    {
        MarketplaceSort.LastUpdated => "Recently updated",
        MarketplaceSort.Downloads => "Downloads",
        MarketplaceSort.HighestApi => "Highest API",
        MarketplaceSort.Version => "Version",
        _ => "Name",
    };

    private static void DrawStringCombo(string label, ref string selected, IReadOnlyList<string> values, float width)
    {
        ImGui.SetNextItemWidth(width);
        if (!ImGui.BeginCombo($"{label}##combo-{label}", selected))
            return;

        foreach (var value in values)
        {
            if (ImGui.Selectable(value, selected.Equals(value, StringComparison.OrdinalIgnoreCase)))
                selected = value;
        }

        ImGui.EndCombo();
    }

    private static string Shorten(string value, int max)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length <= max)
            return value;
        return value[..Math.Max(0, max - 1)] + "…";
    }

    private static string NormalizeUrl(string? url) => (url ?? string.Empty).Trim().TrimEnd('/');

    private static bool Contains(string? haystack, string needle)
        => !string.IsNullOrEmpty(haystack) && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
}
