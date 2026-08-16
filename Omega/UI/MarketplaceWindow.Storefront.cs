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

        var activeFilters = CountActiveMarketplaceFilters();
        var label = activeFilters == 0 ? "Filters" : $"Filters ({activeFilters})";
        var triangle = filtersOpen ? "▲" : "▼";
        var buttonWidth = activeFilters == 0 ? 98f : 118f;
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 4f);
        var openStylePushed = filtersOpen;
        if (openStylePushed)
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.04f, 0.32f, 0.34f, 0.94f));
        if (ImGui.Button($"{label}  {triangle}##panel-filters-{activeView}", new Vector2(buttonWidth, 30f)))
            filtersOpen = !filtersOpen;
        if (openStylePushed)
            ImGui.PopStyleColor();
        ImGui.PopStyleVar();

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(filtersOpen ? "Hide marketplace filters" : $"Show all filters for {ViewTitle(activeView)}");

        if (!filtersOpen)
            return;

        ImGui.Spacing();
        DrawInlineMarketplaceFilters(currentApi);
    }

    private int CountActiveMarketplaceFilters()
    {
        var count = 0;
        if (!string.IsNullOrWhiteSpace(author))
            count++;
        if (!selectedSource.Equals("All sources", StringComparison.OrdinalIgnoreCase))
            count++;
        if (!selectedCategory.Equals("All categories", StringComparison.OrdinalIgnoreCase))
            count++;
        if (selectedTags.Count > 0)
            count++;
        if (selectedApi > 0)
            count++;
        if (activeView == MarketplaceView.Discover && statusFilter != MarketplaceStatusFilter.All)
            count++;
        if (activeView == MarketplaceView.Library && libraryRuntimeFilter != LibraryRuntimeFilter.All)
            count++;
        if (securityFilter != MarketplaceSecurityFilter.All)
            count++;
        if (contentFilter != MarketplaceContentFilter.All)
            count++;
        if (sort != MarketplaceSort.Name)
            count++;
        return count;
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

    private void DrawStorefrontLayout(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (activeView == MarketplaceView.Spotlight || ShowingLibraryCollections || ShowingLibrarySecurity)
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

        if (activeView == MarketplaceView.Discover)
        {
            DrawDiscoverProductPage(installed, currentApi, currentDalamudVersion);
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
            if (activeView == MarketplaceView.Discover)
                resetDiscoverListScroll = true;
            else
                ImGui.SetScrollY(0f);
            resetStorefrontScroll = false;
        }

        if (ShowingLibraryCollections)
        {
            DrawCollectionsPage(installed, currentApi, currentDalamudVersion);
            return;
        }

        if (ShowingLibrarySecurity)
        {
            DrawLibrarySecurityEnvironment(installed, currentApi, currentDalamudVersion);
            return;
        }

        if (!catalog.HasLoaded)
        {
            updates.SeedIfEmpty();
            DrawCatalogLoadingState();
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
                ? "All installed plugins are current in Omega's Definitions."
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

        DrawDiscoverList(filtered, installed, currentApi, currentDalamudVersion);
    }

}
