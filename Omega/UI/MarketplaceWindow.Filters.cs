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
        var keepOpen = true;
        if (!ImGui.BeginPopupModal("Tags###DalagabOmegaTags", ref keepOpen, ImGuiWindowFlags.NoTitleBar))
            return;

        if (DrawOmegaModalHeader("Tags", "tags"))
        {
            ImGui.CloseCurrentPopup();
            ImGui.EndPopup();
            return;
        }

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

        if (selectedTags.Count > 0 && ImGui.Button("Clear selected tags"))
        {
            selectedTags.Clear();
            resetStorefrontScroll = true;
        }

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

    private void DrawInlineMarketplaceFilters(int currentApi)
    {
        var filterPlugins = catalog.GetMainProjection(currentApi, selectedSource).Plugins;
        var panelHeight = activeView is MarketplaceView.Discover or MarketplaceView.Library ? 228f : 198f;

        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, 4f);
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 1f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.045f, 0.052f, 0.064f, 0.72f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.16f, 0.20f, 0.24f, 0.52f));
        ImGui.BeginChild("omega-inline-filters", new Vector2(0f, panelHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.TextDisabled("All filters");
        ImGui.Spacing();
        DrawInlineFilterGrid(filterPlugins, currentApi);
        DrawInlineFilterActions();

        ImGui.EndChild();
        ImGui.PopStyleColor(2);
        ImGui.PopStyleVar(2);
    }

    private void DrawInlineFilterGrid(IReadOnlyList<MarketplacePlugin> filterPlugins, int currentApi)
    {
        if (!ImGui.BeginTable("omega-inline-filter-grid", 3, ImGuiTableFlags.SizingStretchSame | ImGuiTableFlags.PadOuterX))
            return;

        ImGui.TableNextColumn();
        DrawInlineAuthorField(filterPlugins);
        ImGui.TableNextColumn();
        DrawInlineRepositoryField(currentApi);
        ImGui.TableNextColumn();
        DrawInlineCategoryField(filterPlugins);

        ImGui.TableNextRow();
        ImGui.TableNextColumn();
        if (activeView is MarketplaceView.Discover or MarketplaceView.Library)
            DrawInlineStatusField();
        else
            DrawInlineTagField();
        ImGui.TableNextColumn();
        DrawInlineApiField(filterPlugins, currentApi);
        ImGui.TableNextColumn();
        DrawInlineSortField();
        ImGui.EndTable();
    }

    private void DrawInlineFilterActions()
    {
        ImGui.Spacing();
        if (activeView is MarketplaceView.Discover or MarketplaceView.Library)
        {
            DrawInlineTagField();
            ImGui.SameLine(0f, 12f);
        }

        DrawInlineSecurityField();
        ImGui.SameLine(0f, 12f);

        DrawInlineContentRatingField();
        ImGui.SameLine(0f, 12f);

        var preferTesting = configuration.PreferTestingBuilds;
        if (ImGui.Checkbox("Allow testing builds", ref preferTesting))
        {
            configuration.PreferTestingBuilds = preferTesting;
            configuration.Save();
            resetStorefrontScroll = true;
        }

        if (CountActiveMarketplaceFilters() == 0)
            return;

        ImGui.SameLine(0f, 12f);
        if (!ImGui.Button("Reset filters"))
            return;
        ResetFilters();
        resetStorefrontScroll = true;
    }

    private void DrawInlineAuthorField(IReadOnlyList<MarketplacePlugin> filterPlugins)
    {
        ImGui.TextDisabled("Author");
        ImGui.SetNextItemWidth(-1f);
        var label = string.IsNullOrWhiteSpace(author) ? "All authors" : Shorten(author, 24);
        if (!ImGui.BeginCombo("##omega-author-filter", label))
            return;

        if (ImGui.Selectable("All authors", string.IsNullOrWhiteSpace(author)))
        {
            author = string.Empty;
            resetStorefrontScroll = true;
        }

        foreach (var value in filterPlugins.SelectMany(x => x.EffectiveAuthors)
                     .Where(x => !string.IsNullOrWhiteSpace(x))
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            if (!ImGui.Selectable(value, author.Equals(value, StringComparison.OrdinalIgnoreCase)))
                continue;
            author = value;
            resetStorefrontScroll = true;
        }
        ImGui.EndCombo();
    }

    private void DrawInlineRepositoryField(int currentApi)
    {
        ImGui.TextDisabled("Repository");
        var label = selectedSource == "All sources" ? "All repositories" : Shorten(selectedSource, 28);
        if (selectedSource != "All sources")
        {
            var selectedStatus = catalog.GetRepositoryStatuses(currentApi)
                .FirstOrDefault(x => x.SourceName.Equals(selectedSource, StringComparison.OrdinalIgnoreCase));
            if (selectedStatus is not null)
            {
                var configured = FindConfiguredSource(selectedStatus.SourceUrl);
                var provider = GetRepositoryProvider(
                    selectedStatus.SourceName,
                    selectedStatus.SourceUrl,
                    configured?.IsOfficial == true,
                    currentApi);
                if (!string.IsNullOrWhiteSpace(provider.IconUrl))
                {
                    DrawRepositoryProviderIcon(provider, 18f);
                    ImGui.SameLine(0f, 7f);
                }
            }
        }
        ImGui.SetNextItemWidth(-1f);
        if (!ImGui.BeginCombo("##omega-repository-filter", label))
            return;

        if (ImGui.Selectable("All repositories", selectedSource == "All sources"))
        {
            selectedSource = "All sources";
            resetStorefrontScroll = true;
        }

        foreach (var status in catalog.GetRepositoryStatuses(currentApi)
                     .Where(x => !x.IsStale)
                     .OrderBy(x => RepositoryProviderRules.SortPriority(x.SourceName, x.SourceUrl, false, x.PluginCount))
                     .ThenByDescending(x => x.PluginCount)
                     .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase))
        {
            var configured = FindConfiguredSource(status.SourceUrl);
            var official = configured?.IsOfficial == true ||
                           RepositoryProviderRules.Classify(status.SourceName, status.SourceUrl, false, status.PluginCount).Kind == RepositoryProviderKind.Dalamud;
            var rowStart = ImGui.GetCursorPos();
            var selected = selectedSource.Equals(status.SourceName, StringComparison.OrdinalIgnoreCase);
            var clicked = ImGui.Selectable(
                $"##repository-filter-{StableId(status.SourceUrl)}",
                selected,
                ImGuiSelectableFlags.None,
                new Vector2(0f, 24f));
            var rowEnd = ImGui.GetCursorPos();
            ImGui.SetCursorPos(rowStart + new Vector2(5f, 3f));
            DrawRepositoryName(status.SourceName, status.SourceUrl, official, currentApi);
            ImGui.SetCursorPos(rowEnd);
            if (!clicked)
                continue;
            selectedSource = status.SourceName;
            author = string.Empty;
            resetStorefrontScroll = true;
        }
        ImGui.EndCombo();
    }

    private void DrawInlineCategoryField(IReadOnlyList<MarketplacePlugin> filterPlugins)
    {
        ImGui.TextDisabled("Category");
        ImGui.SetNextItemWidth(-1f);
        if (!ImGui.BeginCombo("##omega-category-filter", selectedCategory))
            return;

        if (ImGui.Selectable("All categories", selectedCategory == "All categories"))
        {
            selectedCategory = "All categories";
            resetStorefrontScroll = true;
        }

        foreach (var category in filterPlugins.SelectMany(x => x.EffectiveCategories)
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            if (!ImGui.Selectable(category, selectedCategory.Equals(category, StringComparison.OrdinalIgnoreCase)))
                continue;
            selectedCategory = category;
            resetStorefrontScroll = true;
        }
        ImGui.EndCombo();
    }

    private void DrawInlineStatusField()
    {
        if (activeView == MarketplaceView.Library)
        {
            DrawInlineLibraryRuntimeField();
            return;
        }

        ImGui.TextDisabled("Status");
        ImGui.SetNextItemWidth(-1f);
        if (!ImGui.BeginCombo("##filter-status", StatusFilterLabel(statusFilter)))
            return;

        foreach (var value in Enum.GetValues<MarketplaceStatusFilter>())
        {
            if (!ImGui.Selectable(StatusFilterLabel(value), statusFilter == value))
                continue;
            statusFilter = value;
            resetStorefrontScroll = true;
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

    private void DrawInlineTagField()
    {
        var label = selectedTags.Count == 0 ? "Tags: Any" : $"Tags: {selectedTags.Count} selected";
        if (ImGui.Button($"{label}##advanced-tag-picker"))
            requestTagsPopup = true;
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Search tags. Multiple selected tags use AND matching.");
    }

    private void DrawInlineApiField(IReadOnlyList<MarketplacePlugin> filterPlugins, int currentApi)
    {
        var apis = filterPlugins
            .SelectMany(x => new[] { x.DalamudApiLevel, x.TestingDalamudApiLevel ?? 0, x.OmegaMaximumApiLevel ?? 0 })
            .Where(x => x > 0)
            .Append(currentApi)
            .Distinct()
            .OrderByDescending(x => x)
            .ToArray();

        ImGui.TextDisabled("Dalamud API");
        ImGui.SetNextItemWidth(-1f);
        var label = selectedApi == 0 ? "Any API" : $"API {selectedApi}";
        if (!ImGui.BeginCombo("##filter-api", label))
            return;
        if (ImGui.Selectable("Any API", selectedApi == 0))
        {
            selectedApi = 0;
            resetStorefrontScroll = true;
        }
        foreach (var api in apis)
        {
            if (!ImGui.Selectable($"API {api}", selectedApi == api))
                continue;
            selectedApi = api;
            resetStorefrontScroll = true;
        }
        ImGui.EndCombo();
    }

    private void DrawInlineSortField()
    {
        ImGui.TextDisabled("Sort");
        ImGui.SetNextItemWidth(-1f);
        if (!ImGui.BeginCombo("##filter-sort", SortLabel(sort)))
            return;
        foreach (var value in Enum.GetValues<MarketplaceSort>())
        {
            if (!ImGui.Selectable(SortLabel(value), sort == value))
                continue;
            sort = value;
            resetStorefrontScroll = true;
        }
        ImGui.EndCombo();
    }

}
