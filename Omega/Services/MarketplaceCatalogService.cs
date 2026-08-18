namespace Dalagab.Omega;

internal sealed record SqliteCatalogApplyResult(
    int VariantCount,
    IReadOnlyList<CuratedSourceDefinition> SourceDefinitions,
    DateTimeOffset? GeneratedAtUtc,
    string CatalogRevision,
    string SecurityRevision,
    string EvidenceRevision);

/// <summary>
/// Owns Omega's in-memory marketplace projection backed by one SQLite catalog file. The database is
/// authoritative for public catalog data; direct repository reads are temporary overlays for explicit
/// user-added/source checks and are never persisted as a second catalog format.
/// </summary>
internal sealed partial class MarketplaceCatalogService : IDisposable
{
    private readonly RepositoryClient client = new();
    private readonly SqliteCatalogStore store;
    private readonly object sync = new();
    private IReadOnlyList<MarketplacePlugin> plugins = [];
    private IReadOnlyList<MarketplacePlugin> variants = [];
    private IReadOnlyList<MarketplacePlugin> allDatabaseVariants = [];
    private IReadOnlyList<MarketplacePlugin> databaseVariants = [];
    private IReadOnlyList<MarketplacePlugin> defaultPlugins = [];
    private string defaultPluginFingerprint = string.Empty;
    private readonly Dictionary<string, MarketplacePlugin[]> liveOverlayByUrl = new(StringComparer.OrdinalIgnoreCase);
    private IReadOnlyDictionary<string, MarketplacePlugin[]> variantsByInternalName =
        new Dictionary<string, MarketplacePlugin[]>(StringComparer.OrdinalIgnoreCase);
    private IReadOnlyDictionary<string, MarketplacePlugin[]> presentationVariantsByInternalName =
        new Dictionary<string, MarketplacePlugin[]>(StringComparer.OrdinalIgnoreCase);
    private IReadOnlyDictionary<string, IReadOnlyList<MarketplaceChangelogEntry>> changelogHistoryByInternalName =
        new Dictionary<string, IReadOnlyList<MarketplaceChangelogEntry>>(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, IReadOnlyList<RepositoryCatalogStatus>> repositoryStatusCache = new();
    private readonly Dictionary<string, MarketplaceCatalogProjection> mainProjectionCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, IReadOnlyDictionary<string, MarketplacePlugin[]>> mainVariantIndexCache = new();
    private readonly Dictionary<string, MarketplaceTagIndex> tagIndexCache = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? refreshCts;
    private string[] loadedRepositoryUrls = [];
    private HashSet<string> loadedRepositoryUrlSet = new(StringComparer.OrdinalIgnoreCase);
    private long revision;

    public MarketplaceCatalogService(string databasePath)
    {
        store = new SqliteCatalogStore(databasePath);
    }

    public bool ImportBootstrapBundle(string bundlePath)
        => store.ImportBootstrapBundle(bundlePath);

    public SqliteCatalogApplyResult ReplaceFromBundle(
        string zipPath,
        IEnumerable<RepositorySource> repositories)
    {
        store.ReplaceFromBundle(zipPath);
        var snapshot = store.ReadSnapshot();
        ApplySnapshot(snapshot, repositories, preserveLastRefresh: false);
        return new SqliteCatalogApplyResult(
            snapshot.Variants.Count,
            snapshot.SourceDefinitions,
            snapshot.GeneratedAtUtc,
            snapshot.CatalogRevision,
            snapshot.SecurityRevision,
            snapshot.EvidenceRevision);
    }

    public IReadOnlyList<CuratedSourceDefinition> ReadDatabaseSourceDefinitions()
    {
        if (!store.Exists)
            return [];
        return store.ReadSnapshot().SourceDefinitions;
    }

    public bool SetDefaultPlugins(IEnumerable<MarketplacePlugin> pluginsFromDalamud)
    {
        var next = pluginsFromDalamud
            .Where(x => x.SourceIsOfficial && !string.IsNullOrWhiteSpace(x.InternalName))
            .OrderBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .ThenByDescending(x => x.AssemblyVersion)
            .ToArray();
        if (next.Length == 0)
            return false;

        var fingerprint = string.Join("\u001e", next.Select(x => $"{x.InternalName}\u001f{x.AssemblyVersionText}\u001f{x.DalamudApiLevel}"));
        lock (sync)
        {
            if (fingerprint.Equals(defaultPluginFingerprint, StringComparison.Ordinal))
                return false;

            defaultPlugins = next;
            defaultPluginFingerprint = fingerprint;
            RebuildProjectionLocked();
            return true;
        }
    }

    public IReadOnlyList<MarketplacePlugin> Plugins
    {
        get { lock (sync) return plugins; }
    }

    public IReadOnlyList<MarketplacePlugin> Variants
    {
        get { lock (sync) return variants; }
    }

    public IReadOnlyList<MarketplacePlugin> GetVariants(string internalName)
    {
        lock (sync)
            return variantsByInternalName.TryGetValue(internalName, out var group) ? group : [];
    }

    public IReadOnlyList<MarketplacePlugin> GetPresentationVariants(string internalName)
    {
        lock (sync)
            return presentationVariantsByInternalName.TryGetValue(internalName, out var group) ? group : [];
    }

    public IReadOnlyList<MarketplaceChangelogEntry> GetChangelogHistory(string internalName, string? preferredSourceUrl = null)
    {
        lock (sync)
        {
            if (!changelogHistoryByInternalName.TryGetValue(internalName, out var entries))
                return [];
            var normalizedPreferred = NormalizeUrl(preferredSourceUrl);
            return entries
                .OrderByDescending(entry => !string.IsNullOrWhiteSpace(normalizedPreferred) &&
                    NormalizeUrl(entry.SourceUrl).Equals(normalizedPreferred, StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(entry => PluginUpdateRules.NormalizeUnix(entry.LastUpdate))
                .ThenByDescending(entry => Version.TryParse(entry.VersionText, out var parsed) ? parsed : new Version(0, 0))
                .DistinctBy(entry => $"{entry.VersionText}\u001f{entry.Changelog}", StringComparer.Ordinal)
                .Take(20)
                .ToArray();
        }
    }

    public int GetStableApiLevel(string internalName, int preferredApi = 0)
    {
        lock (sync)
        {
            if (!variantsByInternalName.TryGetValue(internalName, out var group))
                return 0;
            return MarketplaceCatalogRules.GetStableApiLevel(group, internalName, preferredApi);
        }
    }

    public MarketplaceCatalogProjection GetMainProjection(int currentApi, string? sourceName = null)
    {
        lock (sync)
            return GetMainProjectionLocked(currentApi, sourceName);
    }

    public IReadOnlyList<MarketplacePlugin> GetMainVariants(string internalName, int currentApi)
    {
        lock (sync)
        {
            if (!mainVariantIndexCache.TryGetValue(currentApi, out var index))
            {
                var projection = GetMainProjectionLocked(currentApi, null);
                index = BuildVariantIndex(projection.Variants);
                mainVariantIndexCache[currentApi] = index;
            }
            return index.TryGetValue(internalName, out var group) ? group : [];
        }
    }

    public MarketplaceTagIndex GetTagIndex(int currentApi, string? sourceName = null)
    {
        lock (sync)
        {
            var sourceKey = string.IsNullOrWhiteSpace(sourceName) ? string.Empty : sourceName.Trim();
            var cacheKey = $"{currentApi}\u001f{sourceKey}";
            if (tagIndexCache.TryGetValue(cacheKey, out var cached))
                return cached;
            var projection = GetMainProjectionLocked(currentApi, sourceName);
            var index = MarketplaceTagRules.Build(projection.Variants);
            tagIndexCache[cacheKey] = index;
            return index;
        }
    }

    public IReadOnlyList<RepositoryCatalogStatus> GetRepositoryStatuses(int currentApi)
    {
        lock (sync)
            return GetRepositoryStatusesLocked(currentApi);
    }

    public RepositoryCatalogStatus? GetRepositoryStatus(string sourceUrl, int currentApi)
    {
        var normalized = NormalizeUrl(sourceUrl);
        lock (sync)
            return GetRepositoryStatusesLocked(currentApi)
                .FirstOrDefault(x => NormalizeUrl(x.SourceUrl).Equals(normalized, StringComparison.OrdinalIgnoreCase));
    }

    private MarketplaceCatalogProjection GetMainProjectionLocked(int currentApi, string? sourceName)
    {
        var sourceKey = string.IsNullOrWhiteSpace(sourceName) ? string.Empty : sourceName.Trim();
        var cacheKey = $"{currentApi}\u001f{sourceKey}";
        if (mainProjectionCache.TryGetValue(cacheKey, out var cached))
            return cached;

        var staleUrls = GetRepositoryStatusesLocked(currentApi)
            .Where(x => x.IsStale)
            .Select(x => NormalizeUrl(x.SourceUrl))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        IEnumerable<MarketplacePlugin> visible = variants;
        if (staleUrls.Count > 0)
            visible = visible.Where(x => !staleUrls.Contains(NormalizeUrl(x.SourceUrl)));
        if (!string.IsNullOrWhiteSpace(sourceKey) && !sourceKey.Equals("All sources", StringComparison.OrdinalIgnoreCase))
            visible = visible.Where(x => x.SourceName.Equals(sourceKey, StringComparison.OrdinalIgnoreCase));

        var projection = MarketplaceCatalogRules.Project(visible, currentApi);
        mainProjectionCache[cacheKey] = projection;
        return projection;
    }

    private IReadOnlyList<RepositoryCatalogStatus> GetRepositoryStatusesLocked(int currentApi)
    {
        if (repositoryStatusCache.TryGetValue(currentApi, out var cached))
            return cached;
        var statuses = RepositoryHealthRules.BuildStatuses(variants, currentApi);
        repositoryStatusCache[currentApi] = statuses;
        return statuses;
    }

    private static IReadOnlyDictionary<string, MarketplacePlugin[]> BuildVariantIndex(IEnumerable<MarketplacePlugin> candidates)
        => candidates
            .GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                x => x.Key,
                x => x.OrderByDescending(v => v.SourceIsOfficial)
                    .ThenByDescending(v => v.AssemblyVersion)
                    .ThenBy(v => v.SourceName, StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                StringComparer.OrdinalIgnoreCase);

    private void RebuildProjectionLocked()
    {
        var runtimeNames = defaultPlugins.Select(x => x.InternalName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var combined = databaseVariants
            .Where(x => !x.SourceIsOfficial || !runtimeNames.Contains(x.InternalName))
            .Concat(defaultPlugins)
            .ToArray();
        var projection = MarketplaceCatalogRules.Project(combined);

        plugins = projection.Plugins;
        variants = projection.Variants;
        variantsByInternalName = BuildVariantIndex(projection.Variants);
        presentationVariantsByInternalName = BuildVariantIndex(databaseVariants.Concat(defaultPlugins));
        repositoryStatusCache.Clear();
        mainProjectionCache.Clear();
        mainVariantIndexCache.Clear();
        tagIndexCache.Clear();
        revision++;
    }

    public long Revision { get { lock (sync) return revision; } }
    public bool IsRefreshing { get; private set; }
    public bool HasLoaded { get; private set; }
    public int CachedRepositoryCount { get; private set; }
    public DateTimeOffset? LastRefresh { get; private set; }
    public string CatalogRevision { get; private set; } = string.Empty;
    public string SecurityRevision { get; private set; } = string.Empty;
    public string EvidenceRevision { get; private set; } = string.Empty;
    public long DatabaseSizeBytes { get; private set; }
    public DateTimeOffset? RevisionUpdatedAtUtc { get; private set; }
    public int CatalogChangelogEntryCount { get; private set; }
    public string LastError { get; private set; } = string.Empty;

    private static string NormalizeUrl(string? url) => (url ?? string.Empty).Trim().TrimEnd('/');
}
