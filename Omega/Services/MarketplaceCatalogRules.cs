namespace Dalagab.Omega;

internal sealed record MarketplaceCatalogProjection(
    IReadOnlyList<MarketplacePlugin> Plugins,
    IReadOnlyList<MarketplacePlugin> Variants);

/// <summary>
/// Pure catalog projection rules for duplicate-source variants, presentation selection, and stable
/// API aggregation. These rules are shared directly with regression tests.
/// </summary>
internal static class MarketplaceCatalogRules
{
    public static MarketplaceCatalogProjection Project(IEnumerable<MarketplacePlugin> candidates, int preferredApi = 0)
    {
        var visibleVariants = candidates
            .Where(x => !x.IsHide)
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var merged = visibleVariants
            .GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .Select(group => ChoosePresentationVariant(group, preferredApi))
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new MarketplaceCatalogProjection(merged, visibleVariants);
    }


    /// <summary>
    /// Count logical plugins, not repository/source variants. SQLite-backed rows use the
    /// canonical plugins.id value. Live/legacy overlays are counted by InternalName, except
    /// when that InternalName already belongs to a SQLite plugin represented in the same view.
    /// </summary>
    public static int CountUniquePlugins(IEnumerable<MarketplacePlugin> candidates)
    {
        var visible = candidates.Where(x => !x.IsHide).ToArray();
        var databaseNames = visible
            .Where(x => x.CatalogPluginId > 0)
            .Select(x => (x.InternalName ?? string.Empty).Trim())
            .Where(x => x.Length > 0)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var databasePlugins = visible
            .Where(x => x.CatalogPluginId > 0)
            .Select(x => x.CatalogPluginId)
            .Distinct()
            .Count();

        var overlayOnlyPlugins = visible
            .Where(x => x.CatalogPluginId <= 0)
            .Select(x => (x.InternalName ?? string.Empty).Trim())
            .Where(x => x.Length > 0 && !databaseNames.Contains(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        return databasePlugins + overlayOnlyPlugins;
    }

    public static IReadOnlyList<MarketplacePlugin> GetVariants(
        IEnumerable<MarketplacePlugin> candidates,
        string internalName)
        => candidates
            .Where(x => x.InternalName.Equals(internalName, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(x => x.SourceIsOfficial)
            .ThenByDescending(x => x.AssemblyVersion)
            .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public static int GetStableApiLevel(
        IEnumerable<MarketplacePlugin> candidates,
        string internalName,
        int preferredApi = 0)
    {
        var stableApis = candidates
            .Where(x => x.InternalName.Equals(internalName, StringComparison.OrdinalIgnoreCase))
            .Select(x => x.DalamudApiLevel)
            .Where(x => x > 0)
            .Distinct()
            .ToArray();

        if (preferredApi > 0 && stableApis.Contains(preferredApi))
            return preferredApi;

        return stableApis.DefaultIfEmpty(0).Max();
    }

    private static MarketplacePlugin ChoosePresentationVariant(IEnumerable<MarketplacePlugin> group, int preferredApi)
    {
        var variants = group.ToArray();
        var currentApi = preferredApi > 0
            ? variants.Where(x => x.DalamudApiLevel == preferredApi).ToArray()
            : Array.Empty<MarketplacePlugin>();
        var pool = currentApi.Length > 0 ? currentApi : variants;
        return pool
            .OrderBy(x => RepositoryProviderRules.SecurityBaselinePriority(x.SourceName, x.SourceUrl, x.SourceIsOfficial))
            .ThenByDescending(x => x.AssemblyVersion)
            .ThenByDescending(x => x.HighestKnownApiLevel)
            .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
            .First();
    }
}
