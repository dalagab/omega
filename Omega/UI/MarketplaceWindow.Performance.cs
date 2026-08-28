namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private long installCandidateContextCatalogRevision = -1;
    private int installCandidateContextApi = -1;
    private IReadOnlyDictionary<string, RepositoryCatalogStatus> installCandidateRepositoryStatuses =
        new Dictionary<string, RepositoryCatalogStatus>(StringComparer.OrdinalIgnoreCase);
    private IReadOnlySet<string> installCandidateDivergentSources =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Ranking install candidates used to rebuild repository-status and cross-source-divergence
    /// lookups for every plugin in the sidebar. Keep those catalog-wide structures once per
    /// catalog/API revision instead; per-plugin candidate selection can then stay indexed.
    /// </summary>
    private void EnsureInstallCandidateContext(int currentApi)
    {
        var revision = catalog.Revision;
        if (installCandidateContextCatalogRevision == revision &&
            installCandidateContextApi == currentApi)
        {
            return;
        }

        installCandidateRepositoryStatuses = catalog.GetRepositoryStatuses(currentApi)
            .ToDictionary(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase);
        installCandidateDivergentSources = catalog.Variants
            .Where(v => v.SecurityFindings.Any(f =>
                f.RuleId.Equals("artifact.cross-source-hash-mismatch", StringComparison.OrdinalIgnoreCase)))
            .Select(v => NormalizeUrl(v.SourceUrl))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        installCandidateContextCatalogRevision = revision;
        installCandidateContextApi = currentApi;
    }
}
