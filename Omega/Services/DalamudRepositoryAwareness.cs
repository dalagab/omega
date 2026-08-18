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

        var statuses = catalog.GetRepositoryInventoryStatuses(currentApi)
            .ToDictionary(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase);
        var registeredUrls = registrations
            .Select(x => NormalizeUrl(x.Url))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var changed = false;

        // Local-only Omega sources are retired. A repository that is not part of online Definitions
        // exists locally only while it exists in Dalamud, where it remains user-managed.
        var retiredLocalRows = configuration.Repositories
            .Where(x => !x.IsCurated && !x.IsOfficial)
            .Where(x => !catalog.IsSourceInDefinitions(x.Url))
            .Where(x => !registeredUrls.Contains(NormalizeUrl(x.Url)))
            .ToArray();
        foreach (var source in retiredLocalRows)
        {
            configuration.Repositories.Remove(source);
            changed = true;
        }

        foreach (var registration in registrations)
        {
            var normalized = NormalizeUrl(registration.Url);
            var source = configuration.Repositories.FirstOrDefault(x =>
                NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase));
            if (source is null)
            {
                // Online Definitions already own known source identities. Only unknown Dalamud feeds
                // need an internal unmanaged row so Omega can fetch them as a temporary local overlay.
                if (catalog.IsSourceInDefinitions(registration.Url))
                    continue;

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

            if (!source.IsCurated && source.Enabled != registration.Enabled)
            {
                source.Enabled = registration.Enabled;
                changed = true;
            }
            if (!source.IntegrateWithDalamud)
            {
                source.IntegrateWithDalamud = true;
                changed = true;
            }
            if (!source.IsCurated && source.DalamudManagedByOmega)
            {
                source.DalamudManagedByOmega = false;
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
