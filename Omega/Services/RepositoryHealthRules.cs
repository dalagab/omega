namespace Dalagab.Omega;

/// <summary>
/// Calculates repository health from cached plugin API metadata, including the conservative stale
/// rule used to hide repositories whose entire known catalog is three or more API levels behind.
/// </summary>
internal static class RepositoryHealthRules
{
    public static IReadOnlyList<RepositoryCatalogStatus> BuildStatuses(
        IEnumerable<MarketplacePlugin> sourceVariants,
        int currentApi)
        => sourceVariants
            .GroupBy(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var entries = group.ToArray();
                var highest = entries.Select(x => x.HighestKnownApiLevel).DefaultIfEmpty(0).Max();
                var stale = entries.Length > 0 &&
                            entries.All(x => x.HighestKnownApiLevel > 0 && x.IsUnmaintained(currentApi));

                return new RepositoryCatalogStatus(
                    entries.Select(x => x.SourceName).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? group.Key,
                    entries[0].SourceUrl,
                    entries.Length,
                    highest,
                    stale);
            })
            .OrderByDescending(x => x.IsStale)
            .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public static bool IsStale(IEnumerable<MarketplacePlugin> plugins, int currentApi)
    {
        var entries = plugins.ToArray();
        return entries.Length > 0 &&
               entries.All(x => x.HighestKnownApiLevel > 0 && x.IsUnmaintained(currentApi));
    }

    private static string NormalizeUrl(string? url) => (url ?? string.Empty).Trim().TrimEnd('/');
}
