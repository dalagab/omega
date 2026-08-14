using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void DrawSearchAndCategoryButtons(int currentApi)
    {
        EnsureRepositoryFilterIsHealthy(currentApi);

        var mainPlugins = catalog.GetMainProjection(currentApi, selectedSource).Plugins;
        DrawAuthorFilter(mainPlugins);
        DrawRepositoryFilter(currentApi);
        DrawCategoryAndTagFilters(mainPlugins);
    }

    private void EnsureRepositoryFilterIsHealthy(int currentApi)
    {
        if (selectedSource == "All sources")
            return;
        if (catalog.GetRepositoryStatuses(currentApi).Any(x =>
                !x.IsStale && x.SourceName.Equals(selectedSource, StringComparison.OrdinalIgnoreCase)))
            return;
        selectedSource = "All sources";
    }

    private void DrawAuthorFilter(IReadOnlyList<MarketplacePlugin> mainPlugins)
    {
        ImGui.SameLine(0f, 10f);
        ImGui.SetNextItemWidth(170f);
        var authorLabel = string.IsNullOrWhiteSpace(author) ? "All authors" : Shorten(author, 20);
        if (ImGui.BeginCombo("##omega-author-filter", authorLabel))
        {
            DrawAuthorChoices(mainPlugins);
            ImGui.EndCombo();
        }
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Filter the marketplace by plugin author");
    }

    private void DrawAuthorChoices(IReadOnlyList<MarketplacePlugin> mainPlugins)
    {
        if (ImGui.Selectable("All authors", string.IsNullOrWhiteSpace(author)))
        {
            author = string.Empty;
            resetStorefrontScroll = true;
        }

        foreach (var value in mainPlugins.Select(x => x.Author)
                     .Where(x => !string.IsNullOrWhiteSpace(x))
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            if (!ImGui.Selectable(value, author.Equals(value, StringComparison.OrdinalIgnoreCase)))
                continue;
            author = value;
            resetStorefrontScroll = true;
        }
    }

    private void DrawRepositoryFilter(int currentApi)
    {
        ImGui.SameLine(0f, 10f);
        ImGui.SetNextItemWidth(190f);
        var label = selectedSource == "All sources" ? "All repositories" : Shorten(selectedSource, 24);
        if (ImGui.BeginCombo("##omega-repository-filter", label))
        {
            DrawRepositoryChoices(currentApi);
            ImGui.EndCombo();
        }
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Filter the marketplace by repository");
    }

    private void DrawRepositoryChoices(int currentApi)
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
            if (!ImGui.Selectable(status.SourceName, selectedSource.Equals(status.SourceName, StringComparison.OrdinalIgnoreCase)))
                continue;
            selectedSource = status.SourceName;
            author = string.Empty;
            resetStorefrontScroll = true;
        }
    }

    private void DrawCategoryAndTagFilters(IReadOnlyList<MarketplacePlugin> mainPlugins)
    {
        var categories = GetTopCategories(mainPlugins);
        ImGui.Spacing();
        DrawPanelFiltersButton();
        DrawTagPickerButton();
        DrawCategoryButtons(categories);
        DrawSelectedTagChips();
    }

    private void DrawPanelFiltersButton()
    {
        if (DrawPillButton("Filters", $"panel-filters-{activeView}", new Vector2(78f, 30f), filtersOpen))
        {
            filtersOpen = true;
            requestFiltersPopup = true;
        }
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip($"Filter {ViewTitle(activeView)}");
    }

    private void DrawTagPickerButton()
    {
        ImGui.SameLine(0f, 7f);
        var label = selectedTags.Count == 0 ? "Tags" : $"Tags ({selectedTags.Count})";
        var width = selectedTags.Count == 0 ? 68f : 86f;
        if (DrawPillButton(label, "tag-picker", new Vector2(width, 30f), selectedTags.Count > 0))
            requestTagsPopup = true;
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Search and combine marketplace tags");
    }

    private void DrawCategoryButtons(IReadOnlyList<string> categories)
    {
        ImGui.SameLine(0f, 7f);
        var allLabel = activeView == MarketplaceView.Library ? "All categories" : "All";
        var allWidth = activeView == MarketplaceView.Library ? 104f : 62f;
        if (DrawPillButton(allLabel, "category-all", new Vector2(allWidth, 30f), selectedCategory == "All categories"))
        {
            selectedCategory = "All categories";
            resetStorefrontScroll = true;
        }

        foreach (var category in categories)
            DrawCategoryButton(category);

    }

    private void DrawCategoryButton(string category)
    {
        ImGui.SameLine(0f, 7f);
        var active = selectedCategory.Equals(category, StringComparison.OrdinalIgnoreCase);
        var width = Math.Clamp(ImGui.CalcTextSize(category).X + 26f, 66f, 130f);
        if (!DrawPillButton(Shorten(category, 15), $"category-{StableId(category)}", new Vector2(width, 30f), active))
            return;
        selectedCategory = category;
        resetStorefrontScroll = true;
    }

    private void DrawStorefrontLayout(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (activeView == MarketplaceView.Spotlight || ShowingLibraryCollections)
        {
            detailsOpen = false;
            selectedPlugin = null;
            DrawStorefront(installed, currentApi, currentDalamudVersion);
            return;
        }

        if (!detailsOpen || selectedPlugin is null)
        {
            DrawStorefront(installed, currentApi, currentDalamudVersion);
            return;
        }

        var available = ImGui.GetContentRegionAvail();
        if (activeView == MarketplaceView.Discover && available.X < DiscoverSplitMinimumWidth)
        {
            DrawPluginDetailsPanel(installed, currentApi, currentDalamudVersion);
            return;
        }

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
            if (activeView == MarketplaceView.Discover)
                resetDiscoverGridScroll = true;
            else
                ImGui.SetScrollY(0f);
            resetStorefrontScroll = false;
        }

        if (ShowingLibraryCollections)
        {
            DrawCollectionsPage(installed, currentApi, currentDalamudVersion);
            return;
        }

        if (!catalog.HasLoaded)
        {
            ImGui.Spacing();
            ImGui.Text("Omega needs an initial catalog snapshot.");
            ImGui.TextWrapped("Omega first tries the published catalog database. If that cannot be downloaded or verified, it rebuilds the same local database from the bundled source list. Once seeded, the catalog is reused across restarts.");
            ImGui.Spacing();
            if (DrawPillButton("Open Settings", "empty-settings", new Vector2(180f, 34f), true))
                OpenSettings();
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

        var shelfPlugins = activeView == MarketplaceView.Library
            ? BuildLibraryProjection(mainProjection.Plugins, installed)
            : mainProjection.Plugins;
        var filtered = GetFilteredPlugins(shelfPlugins, installed, currentApi, currentDalamudVersion);
        if (filtered.Length == 0)
        {
            ImGui.Text(activeView == MarketplaceView.Updates
                ? "All installed plugins are current in Omega's catalog."
                : "No plugins match this shelf.");
            if (DrawPillButton("Reset filters", "empty-reset-filters", new Vector2(132f, 32f), false))
            {
                ResetFilters();
                resetStorefrontScroll = true;
            }
            return;
        }

        if (activeView == MarketplaceView.Library)
        {
            DrawLibraryList(filtered, installed, currentApi, currentDalamudVersion);
            return;
        }

        if (activeView == MarketplaceView.Updates)
        {
            DrawUpdatesList(filtered, installed, currentApi, currentDalamudVersion);
            return;
        }

        DrawDiscoverGrid(filtered, installed, currentApi, currentDalamudVersion);
    }

}
