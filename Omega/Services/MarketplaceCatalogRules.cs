namespace Dalagab.Omega;

internal sealed record MarketplaceCatalogProjection(
    IReadOnlyList<MarketplacePlugin> Plugins,
    IReadOnlyList<MarketplacePlugin> Variants);

internal static class MarketplaceCatalogRules
{
    public static MarketplaceCatalogProjection Project(IEnumerable<MarketplacePlugin> candidates)
    {
        var visibleVariants = candidates
            .Where(x => !x.IsHide)
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var merged = visibleVariants
            .GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .Select(ChoosePresentationVariant)
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new MarketplaceCatalogProjection(merged, visibleVariants);
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

    private static MarketplacePlugin ChoosePresentationVariant(IEnumerable<MarketplacePlugin> group)
        => group
            .OrderByDescending(x => x.SourceIsOfficial)
            .ThenByDescending(x => x.AssemblyVersion)
            .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
            .First();
}
