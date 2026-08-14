using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void DrawSelectedTagChips()
    {
        if (selectedTags.Count == 0)
            return;

        ImGui.Spacing();
        ImGui.TextDisabled("Selected tags:");
        var first = true;
        foreach (var tag in selectedTags.ToArray())
        {
            var label = $"{Shorten(tag, 18)} ×";
            var width = Math.Clamp(ImGui.CalcTextSize(label).X + 22f, 64f, 154f);
            if (!first && ImGui.GetContentRegionAvail().X < width + 8f)
                ImGui.NewLine();
            else
                ImGui.SameLine(0f, 7f);

            if (DrawPillButton(label, $"selected-tag-{StableId(tag)}", new Vector2(width, 26f), true))
            {
                RemoveSelectedTag(tag);
                resetStorefrontScroll = true;
            }

            first = false;
        }
    }

    private void DrawTagPickerPopup(int currentApi)
    {
        ImGui.SetNextWindowSize(new Vector2(500f, 500f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopup("Tags###DalagabOmegaTags"))
            return;

        var tagIndex = catalog.GetTagIndex(currentApi, selectedSource);
        ImGui.Text("Narrow by tag");
        ImGui.TextDisabled($"{tagIndex.Tags.Count:N0} searchable tags • all selected tags must match");
        ImGui.Separator();

        ImGui.SetNextItemWidth(-1f);
        ImGui.InputTextWithHint("##omega-tag-search", "Search tags...", ref tagSearch, 128);

        var results = GetTagPickerResults(tagIndex, currentApi);
        ImGui.TextDisabled(tagSearch.Trim().Length == 0
            ? $"Popular tags • showing {results.Length:N0}"
            : $"{cachedTagPickerMatchCount:N0} matching tags • showing {results.Length:N0}");

        ImGui.BeginChild("omega-tag-results", new Vector2(0f, 350f), true);
        foreach (var info in results)
        {
            var isSelected = ContainsSelectedTag(info.Name);
            if (ImGui.Checkbox($"##tag-check-{StableId(info.Name)}", ref isSelected))
            {
                if (isSelected)
                    AddSelectedTag(info.Name);
                else
                    RemoveSelectedTag(info.Name);
                resetStorefrontScroll = true;
            }
            ImGui.SameLine();
            ImGui.TextUnformatted(info.Name);
            ImGui.SameLine();
            ImGui.TextDisabled($"({info.PluginCount:N0})");
        }
        ImGui.EndChild();

        if (selectedTags.Count > 0)
        {
            if (ImGui.Button("Clear selected tags"))
            {
                selectedTags.Clear();
                resetStorefrontScroll = true;
            }
            ImGui.SameLine();
        }

        if (ImGui.Button("Close"))
            ImGui.CloseCurrentPopup();

        ImGui.EndPopup();
    }

    private MarketplaceTagInfo[] GetTagPickerResults(MarketplaceTagIndex index, int currentApi)
    {
        var revision = catalog.Revision;
        var selectionKey = TagSelectionKey();
        if (tagPickerCatalogRevision == revision &&
            tagPickerCurrentApi == currentApi &&
            tagPickerSource.Equals(selectedSource, StringComparison.Ordinal) &&
            tagPickerSearchCache.Equals(tagSearch, StringComparison.Ordinal) &&
            tagPickerSelectionCache.Equals(selectionKey, StringComparison.Ordinal))
        {
            return cachedTagPickerResults;
        }

        var needle = tagSearch.Trim();
        IEnumerable<MarketplaceTagInfo> query = index.Tags;
        if (needle.Length > 0)
            query = query.Where(x => Contains(x.Name, needle));

        var materialized = query
            .OrderByDescending(x => ContainsSelectedTag(x.Name))
            .ThenByDescending(x => x.PluginCount)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        cachedTagPickerMatchCount = materialized.Length;
        cachedTagPickerResults = materialized
            .Take(needle.Length == 0 ? 120 : 250)
            .ToArray();
        tagPickerCatalogRevision = revision;
        tagPickerCurrentApi = currentApi;
        tagPickerSource = selectedSource;
        tagPickerSearchCache = tagSearch;
        tagPickerSelectionCache = selectionKey;
        return cachedTagPickerResults;
    }

    private bool ContainsSelectedTag(string tag)
        => selectedTags.Any(x => x.Equals(tag, StringComparison.OrdinalIgnoreCase));

    private void AddSelectedTag(string tag)
    {
        var trimmed = tag.Trim();
        if (trimmed.Length == 0 || ContainsSelectedTag(trimmed))
            return;
        selectedTags.Add(trimmed);
    }

    private void RemoveSelectedTag(string tag)
        => selectedTags.RemoveAll(x => x.Equals(tag, StringComparison.OrdinalIgnoreCase));

    private string TagSelectionKey()
        => string.Join("\u001f", selectedTags.OrderBy(x => x, StringComparer.OrdinalIgnoreCase));

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

        ImGui.Text($"Filters — {ViewTitle(activeView)}");
        ImGui.TextDisabled("These filters are local and never download source JSON.");
        ImGui.Separator();
        DrawAdvancedFilterFields(currentApi);
        DrawAdvancedFilterActions();
        filtersOpen = keepOpen && filtersOpen;
        ImGui.EndPopup();
    }

    private void DrawAdvancedFilterFields(int currentApi)
    {
        ImGui.SetNextItemWidth(360);
        ImGui.InputTextWithHint("Author##filter-author", "Author contains...", ref author, 128);
        if (activeView == MarketplaceView.Discover)
            DrawAdvancedStatusField();
        DrawAdvancedRepositoryField(currentApi);

        var filterPlugins = catalog.GetMainProjection(currentApi, selectedSource).Plugins;
        DrawAdvancedCategoryField(filterPlugins);
        DrawAdvancedTagField();
        DrawAdvancedApiField(filterPlugins, currentApi);
        DrawAdvancedSortField();

        var preferTesting = configuration.PreferTestingBuilds;
        if (!ImGui.Checkbox("Allow testing builds", ref preferTesting))
            return;
        configuration.PreferTestingBuilds = preferTesting;
        configuration.Save();
    }

    private void DrawAdvancedStatusField()
    {
        ImGui.SetNextItemWidth(360);
        if (!ImGui.BeginCombo("Status##filter-status", StatusFilterLabel(statusFilter)))
            return;

        foreach (var value in Enum.GetValues<MarketplaceStatusFilter>())
        {
            if (ImGui.Selectable(StatusFilterLabel(value), statusFilter == value))
            {
                statusFilter = value;
                resetStorefrontScroll = true;
            }
        }
        ImGui.EndCombo();
    }

    private static string StatusFilterLabel(MarketplaceStatusFilter value) => value switch
    {
        MarketplaceStatusFilter.Installed => "Installed",
        MarketplaceStatusFilter.Installable => "Installable",
        MarketplaceStatusFilter.OutdatedApi => "Outdated API",
        _ => "All plugins",
    };

    private void DrawAdvancedRepositoryField(int currentApi)
    {
        var sources = new[] { "All sources" }
            .Concat(catalog.GetRepositoryStatuses(currentApi)
                .Where(x => !x.IsStale)
                .Select(x => x.SourceName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        DrawStringCombo("Source", ref selectedSource, sources, 360);
    }

    private void DrawAdvancedCategoryField(IReadOnlyList<MarketplacePlugin> filterPlugins)
    {
        var categories = new[] { "All categories" }
            .Concat(filterPlugins
                .SelectMany(x => x.EffectiveCategories)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        DrawStringCombo("Category", ref selectedCategory, categories, 360);
    }

    private void DrawAdvancedTagField()
    {
        var summary = selectedTags.Count == 0
            ? "Any tags"
            : string.Join(", ", selectedTags.Select(x => Shorten(x, 18)));
        ImGui.SetNextItemWidth(360);
        if (ImGui.Button($"Tags: {summary}##advanced-tag-picker", new Vector2(360f, 0f)))
        {
            filtersOpen = false;
            ImGui.CloseCurrentPopup();
            requestTagsPopup = true;
        }
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Search tags. Multiple selected tags use AND matching.");
    }

    private void DrawAdvancedApiField(IReadOnlyList<MarketplacePlugin> filterPlugins, int currentApi)
    {
        var apis = filterPlugins
            .SelectMany(x => new[] { x.DalamudApiLevel, x.TestingDalamudApiLevel ?? 0, x.OmegaMaximumApiLevel ?? 0 })
            .Where(x => x > 0)
            .Append(currentApi)
            .Distinct()
            .OrderByDescending(x => x)
            .ToArray();

        ImGui.SetNextItemWidth(360);
        var label = selectedApi == 0 ? "Any API" : $"API {selectedApi}";
        if (!ImGui.BeginCombo("API##filter-api", label))
            return;
        if (ImGui.Selectable("Any API", selectedApi == 0))
            selectedApi = 0;
        foreach (var api in apis)
        {
            if (ImGui.Selectable($"API {api}", selectedApi == api))
                selectedApi = api;
        }
        ImGui.EndCombo();
    }

    private void DrawAdvancedSortField()
    {
        ImGui.SetNextItemWidth(360);
        if (!ImGui.BeginCombo("Sort##filter-sort", SortLabel(sort)))
            return;
        foreach (var value in Enum.GetValues<MarketplaceSort>())
        {
            if (ImGui.Selectable(SortLabel(value), sort == value))
                sort = value;
        }
        ImGui.EndCombo();
    }

    private void DrawAdvancedFilterActions()
    {
        ImGui.Separator();
        if (ImGui.Button("Reset filters"))
            ResetFilters();
        ImGui.SameLine();
        if (!ImGui.Button("Close"))
            return;
        filtersOpen = false;
        ImGui.CloseCurrentPopup();
    }

}