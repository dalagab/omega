using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private (int Installed, int Installable, int Outdated, int Updates) GetSidebarCounts(
        IReadOnlyList<MarketplacePlugin> mainPlugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        var installedSignature = GetInstalledSignature(installed);
        var revision = catalog.Revision;
        if (sidebarCatalogRevision == revision &&
            sidebarInstalledSignature == installedSignature &&
            sidebarSourceStateRevision == sourceStateRevision &&
            sidebarCurrentApi == currentApi &&
            Equals(sidebarDalamudVersion, currentDalamudVersion) &&
            sidebarPreferTesting == configuration.PreferTestingBuilds)
        {
            return sidebarCounts;
        }

        var installedCount = 0;
        var installableCount = 0;
        var outdatedCount = 0;
        var updateCount = 0;
        foreach (var plugin in mainPlugins)
        {
            if (installed.TryGetValue(plugin.InternalName, out var installedPlugin))
            {
                installedCount++;
                if (HasAvailableUpdate(plugin.InternalName, installedPlugin, currentApi, currentDalamudVersion))
                    updateCount++;
            }
            else if (HasInstallableVariant(plugin.InternalName, currentApi, currentDalamudVersion))
            {
                installableCount++;
            }

            var highest = HighestKnownApiFor(plugin.InternalName, currentApi);
            if (highest > 0 && highest < currentApi)
                outdatedCount++;
        }

        sidebarCounts = (installedCount, installableCount, outdatedCount, updateCount);
        sidebarCatalogRevision = revision;
        sidebarInstalledSignature = installedSignature;
        sidebarSourceStateRevision = sourceStateRevision;
        sidebarCurrentApi = currentApi;
        sidebarDalamudVersion = currentDalamudVersion;
        sidebarPreferTesting = configuration.PreferTestingBuilds;
        return sidebarCounts;
    }

    private IReadOnlyList<string> GetTopCategories(IReadOnlyList<MarketplacePlugin> mainPlugins)
    {
        var revision = catalog.Revision;
        if (categoryCatalogRevision == revision &&
            categorySource.Equals(selectedSource, StringComparison.OrdinalIgnoreCase))
        {
            return cachedCategories;
        }

        var grouped = mainPlugins
            .SelectMany(x => x.EffectiveCategories)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .GroupBy(x => x, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(x => x.Count())
            .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.Key)
            .ToArray();

        cachedCategories = grouped.Take(7).ToArray();
        cachedHasMoreCategories = grouped.Length > cachedCategories.Length;
        categoryCatalogRevision = revision;
        categorySource = selectedSource;
        return cachedCategories;
    }

    private MarketplacePlugin[] GetFilteredPlugins(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        var installedSignature = GetInstalledSignature(installed);
        var revision = catalog.Revision;
        if (filterCatalogRevision == revision &&
            filterInstalledSignature == installedSignature &&
            filterSourceStateRevision == sourceStateRevision &&
            filterCurrentApi == currentApi &&
            Equals(filterDalamudVersion, currentDalamudVersion) &&
            filterView == activeView &&
            filterSort == sort &&
            filterSearch.Equals(search, StringComparison.Ordinal) &&
            filterAuthor.Equals(author, StringComparison.Ordinal) &&
            filterSource.Equals(selectedSource, StringComparison.Ordinal) &&
            filterCategory.Equals(selectedCategory, StringComparison.Ordinal) &&
            filterTags.Equals(TagSelectionKey(), StringComparison.Ordinal) &&
            filterApi == selectedApi &&
            filterStatus == statusFilter &&
            filterLibraryRuntime == libraryRuntimeFilter &&
            filterSecurity == securityFilter &&
            filterContent == contentFilter &&
            filterPreferTesting == configuration.PreferTestingBuilds)
        {
            return cachedFilteredPlugins;
        }

        cachedFilteredPlugins = ApplyFilters(plugins, installed, currentApi, currentDalamudVersion).ToArray();
        filterCatalogRevision = revision;
        filterInstalledSignature = installedSignature;
        filterSourceStateRevision = sourceStateRevision;
        filterCurrentApi = currentApi;
        filterDalamudVersion = currentDalamudVersion;
        filterView = activeView;
        filterSort = sort;
        filterSearch = search;
        filterAuthor = author;
        filterSource = selectedSource;
        filterCategory = selectedCategory;
        filterTags = TagSelectionKey();
        filterApi = selectedApi;
        filterStatus = statusFilter;
        filterLibraryRuntime = libraryRuntimeFilter;
        filterSecurity = securityFilter;
        filterContent = contentFilter;
        filterPreferTesting = configuration.PreferTestingBuilds;
        return cachedFilteredPlugins;
    }

    private static int GetInstalledSignature(IReadOnlyDictionary<string, IExposedPlugin> installed)
    {
        var hash = 0;
        foreach (var (internalName, plugin) in installed)
        {
            var nameHash = StringComparer.OrdinalIgnoreCase.GetHashCode(internalName ?? string.Empty);
            if (plugin is null)
            {
                hash ^= HashCode.Combine(nameHash, 0, false);
                continue;
            }

            hash ^= HashCode.Combine(
                nameHash,
                plugin.Version?.GetHashCode() ?? 0,
                plugin.IsLoaded);
        }
        return HashCode.Combine(installed.Count, hash);
    }

    private void ResetFilters()
    {
        search = string.Empty;
        author = string.Empty;
        selectedSource = "All sources";
        selectedCategory = "All categories";
        selectedTags.Clear();
        tagSearch = string.Empty;
        selectedApi = 0;
        statusFilter = MarketplaceStatusFilter.All;
        libraryRuntimeFilter = LibraryRuntimeFilter.All;
        securityFilter = MarketplaceSecurityFilter.All;
        contentFilter = MarketplaceContentFilter.All;
        sort = MarketplaceSort.Name;
    }

    private static string ViewTitle(MarketplaceView view) => view switch
    {
        MarketplaceView.Spotlight => "Spotlight",
        MarketplaceView.Library => "Library",
        MarketplaceView.Updates => "Updates & downloads",
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
