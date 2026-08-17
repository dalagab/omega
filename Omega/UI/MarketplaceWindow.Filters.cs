using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void DrawTagPickerPopup(int currentApi)
    {
        ImGui.SetNextWindowSize(UiModalSize(500f, 500f), ImGuiCond.Appearing);
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

        ImGui.BeginChild("omega-tag-results", new Vector2(0f, Math.Min(Ui(350f), ImGui.GetMainViewport().WorkSize.Y * 0.55f)), true);
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

    private bool ContainsSelectedAuthor(string value)
        => selectedAuthors.Any(x => x.Equals(value, StringComparison.OrdinalIgnoreCase));

    private void AddSelectedAuthor(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length == 0 || ContainsSelectedAuthor(trimmed))
            return;
        selectedAuthors.Add(trimmed);
    }

    private void RemoveSelectedAuthor(string value)
        => selectedAuthors.RemoveAll(x => x.Equals(value, StringComparison.OrdinalIgnoreCase));

    private string AuthorSelectionKey()
        => string.Join("\u001f", selectedAuthors.OrderBy(x => x, StringComparer.OrdinalIgnoreCase));

    private void DrawInlineMarketplaceFilters(int currentApi)
    {
        var filterPlugins = catalog.GetMainProjection(currentApi, selectedSource).Plugins;
        var panelHeight = CalculateInlineFilterPanelHeight();

        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, Ui(4f));
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

    private float CalculateInlineFilterPanelHeight()
    {
        // High Dalamud UI scales need fewer columns and therefore more vertical room. Compute the
        // number of rows from the same responsive-width rule used by the filter tables instead of
        // assuming the 100% three-column/two-row arrangement.
        var available = Math.Max(Ui(220f), ImGui.GetContentRegionAvail().X);
        var gridColumns = ResponsiveColumns(available, 230f, 3, 12f);
        var gridRows = (int)Math.Ceiling(6f / gridColumns);
        var actionCount = activeView is MarketplaceView.Discover or MarketplaceView.Library ? 4 : 3;
        if (CountActiveMarketplaceFilters() > 0)
            actionCount++;
        var actionColumns = ResponsiveColumns(available, 190f, 4, 12f);
        var actionRows = (int)Math.Ceiling(actionCount / (float)actionColumns);
        var frame = ImGui.GetFrameHeightWithSpacing();
        return Ui(44f) + (gridRows * frame * 2.15f) + (actionRows * frame * 1.65f);
    }

    private void DrawSelectedFilterPills()
    {
        if (CountActiveMarketplaceFilters() == 0)
            return;

        ImGui.Dummy(Ui(1f, 4f));
        ImGui.TextDisabled("Selected:");
        var first = true;

        foreach (var value in selectedAuthors.ToArray())
            DrawSelectedFilterPill($"Author: {Shorten(value, 22)}", $"author-{value}", ref first, () => RemoveSelectedAuthor(value));
        foreach (var value in selectedTags.ToArray())
            DrawSelectedFilterPill($"Tag: {Shorten(value, 22)}", $"tag-{value}", ref first, () => RemoveSelectedTag(value));

        if (selectedSource != "All sources")
            DrawSelectedFilterPill($"Repository: {Shorten(selectedSource, 22)}", "repository", ref first, () => selectedSource = "All sources");
        if (selectedCategory != "All categories")
            DrawSelectedFilterPill($"Category: {Shorten(selectedCategory, 22)}", "category", ref first, () => selectedCategory = "All categories");
        if (selectedApi > 0)
            DrawSelectedFilterPill($"API {selectedApi}", "api", ref first, () => selectedApi = 0);
        if (activeView == MarketplaceView.Discover && statusFilter != MarketplaceStatusFilter.All)
            DrawSelectedFilterPill($"Status: {StatusFilterLabel(statusFilter)}", "status", ref first, () => statusFilter = MarketplaceStatusFilter.All);
        if (activeView == MarketplaceView.Library && libraryRuntimeFilter != LibraryRuntimeFilter.All)
            DrawSelectedFilterPill($"Status: {LibraryRuntimeFilterLabel(libraryRuntimeFilter)}", "library-status", ref first, () => libraryRuntimeFilter = LibraryRuntimeFilter.All);
        if (securityFilter != MarketplaceSecurityFilter.All)
            DrawSelectedFilterPill(SecurityFilterLabel(securityFilter), "security", ref first, () => securityFilter = MarketplaceSecurityFilter.All);
        if (contentFilter != MarketplaceContentFilter.All)
            DrawSelectedFilterPill(ContentFilterLabel(contentFilter), "content", ref first, () => contentFilter = MarketplaceContentFilter.All);
        if (sort != MarketplaceSort.Name)
            DrawSelectedFilterPill($"Sort: {SortLabel(sort)}", "sort", ref first, () => sort = MarketplaceSort.Name);

        ImGui.NewLine();
    }

    private void DrawSelectedFilterPill(string label, string id, ref bool first, Action remove)
    {
        var text = $"{label}  ×";
        var width = Math.Clamp(ImGui.CalcTextSize(text).X + Ui(24f), Ui(78f), Ui(238f));
        if (!first && ImGui.GetContentRegionAvail().X < width + Ui(8f))
            ImGui.NewLine();
        else
            ImGui.SameLine(0f, Ui(7f));

        if (DrawPillButton(text, $"selected-filter-{StableId(id)}", new Vector2(width, Ui(25f)), true))
        {
            remove();
            resetStorefrontScroll = true;
        }

        first = false;
    }

    private void DrawInlineFilterGrid(IReadOnlyList<MarketplacePlugin> filterPlugins, int currentApi)
    {
        var columns = ResponsiveColumns(ImGui.GetContentRegionAvail().X, 230f, 3, 12f);
        if (!ImGui.BeginTable("omega-inline-filter-grid", columns, ImGuiTableFlags.SizingStretchSame | ImGuiTableFlags.PadOuterX))
            return;

        ImGui.TableNextColumn();
        DrawInlineAuthorField(filterPlugins);
        ImGui.TableNextColumn();
        DrawInlineRepositoryField(currentApi);
        ImGui.TableNextColumn();
        DrawInlineCategoryField(filterPlugins);
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
        var actionCount = activeView is MarketplaceView.Discover or MarketplaceView.Library ? 4 : 3;
        if (CountActiveMarketplaceFilters() > 0)
            actionCount++;
        var columns = ResponsiveColumns(ImGui.GetContentRegionAvail().X, 190f, Math.Min(4, actionCount), 12f);
        if (!ImGui.BeginTable("omega-inline-filter-actions", columns, ImGuiTableFlags.SizingStretchSame | ImGuiTableFlags.PadOuterX))
            return;

        if (activeView is MarketplaceView.Discover or MarketplaceView.Library)
        {
            ImGui.TableNextColumn();
            DrawInlineTagField();
        }

        ImGui.TableNextColumn();
        DrawInlineSecurityField();
        ImGui.TableNextColumn();
        DrawInlineContentRatingField();
        ImGui.TableNextColumn();
        var preferTesting = configuration.PreferTestingBuilds;
        if (ImGui.Checkbox("Allow testing builds", ref preferTesting))
        {
            configuration.PreferTestingBuilds = preferTesting;
            configuration.Save();
            resetStorefrontScroll = true;
        }

        if (CountActiveMarketplaceFilters() > 0)
        {
            ImGui.TableNextColumn();
            if (ImGui.Button("Reset filters"))
            {
                ResetFilters();
                resetStorefrontScroll = true;
            }
        }
        ImGui.EndTable();
    }

    private void DrawInlineAuthorField(IReadOnlyList<MarketplacePlugin> filterPlugins)
    {
        ImGui.TextDisabled("Author");
        ImGui.SetNextItemWidth(-1f);
        var label = selectedAuthors.Count switch
        {
            0 => "All authors",
            1 => Shorten(selectedAuthors[0], 24),
            _ => $"{selectedAuthors.Count} authors selected",
        };
        if (!ImGui.BeginCombo("##omega-author-filter", label))
            return;

        ImGui.SetNextItemWidth(-1f);
        ImGui.InputTextWithHint("##omega-author-search", "Search authors...", ref authorSearch, 128);
        ImGui.TextDisabled("Multiple authors use AND matching.");
        ImGui.Separator();

        if (selectedAuthors.Count > 0 && ImGui.Selectable("Clear selected authors"))
        {
            selectedAuthors.Clear();
            resetStorefrontScroll = true;
        }

        var needle = authorSearch.Trim();
        foreach (var value in filterPlugins.SelectMany(x => x.EffectiveAuthors)
                     .Where(x => !string.IsNullOrWhiteSpace(x))
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .Where(x => needle.Length == 0 || Contains(x, needle))
                     .OrderByDescending(ContainsSelectedAuthor)
                     .ThenBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            var isSelected = ContainsSelectedAuthor(value);
            if (!ImGui.Selectable(value, isSelected, ImGuiSelectableFlags.DontClosePopups))
                continue;
            if (isSelected)
                RemoveSelectedAuthor(value);
            else
                AddSelectedAuthor(value);
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
                    ImGui.SameLine(0f, Ui(7f));
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
                new Vector2(0f, Ui(24f)));
            var rowEnd = ImGui.GetCursorPos();
            ImGui.SetCursorPos(rowStart + Ui(5f, 3f));
            DrawRepositoryName(status.SourceName, status.SourceUrl, official, currentApi);
            ImGui.SetCursorPos(rowEnd);
            if (!clicked)
                continue;
            selectedSource = status.SourceName;
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
