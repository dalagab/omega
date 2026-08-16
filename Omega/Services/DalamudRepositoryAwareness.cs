namespace Dalagab.Omega;

/// <summary>
/// Imports repositories that already exist in Dalamud into Omega's source inventory without taking
/// ownership of them. Omega may inspect/present those repositories, but user-managed Dalamud rows
/// are never removed or toggled implicitly.
/// </summary>
internal static class DalamudRepositoryAwareness
{
    public static bool MergeExisting(
        Configuration configuration,
        DalamudRepositoryBridge bridge,
        MarketplaceCatalogService catalog,
        int currentApi)
    {
        var registrations = bridge.GetConfiguredRepositories();
        if (registrations.Count == 0)
            return false;

        var statuses = catalog.GetRepositoryStatuses(currentApi)
            .ToDictionary(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase);
        var changed = false;
        foreach (var registration in registrations)
        {
            var normalized = NormalizeUrl(registration.Url);
            var source = configuration.Repositories.FirstOrDefault(x =>
                NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase));
            if (source is null)
            {
                statuses.TryGetValue(normalized, out var known);
                source = new RepositorySource
                {
                    Name = known?.SourceName ?? RepositoryNameFromUrl(registration.Url),
                    Url = registration.Url,
                    Enabled = registration.Enabled,
                    IsCurated = false,
                    IsExperimental = true,
                    IntegrateWithDalamud = true,
                    DalamudManagedByOmega = false,
                };
                configuration.Repositories.Add(source);
                changed = true;
                continue;
            }

            if (!source.IntegrateWithDalamud)
            {
                source.IntegrateWithDalamud = true;
                changed = true;
            }
        }

        return changed;
    }

    private static string RepositoryNameFromUrl(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host)
            ? uri.Host
            : "Dalamud repository";

    private static string NormalizeUrl(string? url)
        => (url ?? string.Empty).Trim().TrimEnd('/');
}
