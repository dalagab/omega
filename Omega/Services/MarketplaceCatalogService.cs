namespace Dalagab.Omega;

/// <summary>
/// Owns Omega's local marketplace projection and repository metadata cache. It reads validated
/// catalog records and exposes indexed/filterable plugin views; it does not load or install plugin DLLs.
/// </summary>
internal sealed partial class MarketplaceCatalogService : IDisposable
{
    private readonly RepositoryClient client = new();
    private readonly CatalogDatabase database;
    private readonly object sync = new();
    private IReadOnlyList<MarketplacePlugin> plugins = [];
    private IReadOnlyList<MarketplacePlugin> variants = [];
    private IReadOnlyList<MarketplacePlugin> databaseVariants = [];
    private IReadOnlyList<MarketplacePlugin> defaultPlugins = [];
    private string defaultPluginFingerprint = string.Empty;
    private IReadOnlyDictionary<string, MarketplacePlugin[]> variantsByInternalName =
        new Dictionary<string, MarketplacePlugin[]>(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, IReadOnlyList<RepositoryCatalogStatus>> repositoryStatusCache = new();
    private readonly Dictionary<string, MarketplaceCatalogProjection> mainProjectionCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, IReadOnlyDictionary<string, MarketplacePlugin[]>> mainVariantIndexCache = new();
    private readonly Dictionary<string, MarketplaceTagIndex> tagIndexCache = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? refreshCts;
    private string[] loadedRepositoryUrls = [];
    private HashSet<string> loadedRepositoryUrlSet = new(StringComparer.OrdinalIgnoreCase);
    private long revision;

    public MarketplaceCatalogService(string databaseDirectory)
    {
        database = new CatalogDatabase(databaseDirectory);
    }

    public CatalogBundleImportResult ImportBundle(string zipPath)
        => CatalogBundleImporter.Import(zipPath, database);

    /// <summary>
    /// Replaces the curated catalog with an authoritative prebuilt bundle while preserving
    /// cached official/default and user-added repository records. The same database projection is
    /// used afterward regardless of whether records came from the central bundle or local feeds.
    /// </summary>
    public CatalogBundleImportResult ReplaceFromBundle(
        string zipPath,
        IEnumerable<RepositorySource> repositories)
    {
        var read = CatalogBundleImporter.Read(zipPath);
        if (read.Records.Count == 0)
            throw new InvalidDataException("Online Omega catalog bundle contains no repository records.");

        var preserved = repositories
            .Where(IsOnlineOverlaySource)
            .Select(x => database.TryRead(x.Url))
            .Where(x => x is not null)
            .Cast<CatalogDatabaseRecord>()
            .ToArray();

        database.ReplaceAll(read.Records, preserved);
        RebuildFromDatabase(repositories.Where(IsEligible).ToArray(), preserveLastRefresh: false);
        return read;
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
        get
        {
            lock (sync)
                return plugins;
        }
    }

    public IReadOnlyList<MarketplacePlugin> Variants
    {
        get
        {
            lock (sync)
                return variants;
        }
    }

    public IReadOnlyList<MarketplacePlugin> GetVariants(string internalName)
    {
        lock (sync)
            return variantsByInternalName.TryGetValue(internalName, out var group) ? group : [];
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

        if (!string.IsNullOrWhiteSpace(sourceKey) &&
            !sourceKey.Equals("All sources", StringComparison.OrdinalIgnoreCase))
        {
            visible = visible.Where(x => x.SourceName.Equals(sourceKey, StringComparison.OrdinalIgnoreCase));
        }

        var projection = MarketplaceCatalogRules.Project(visible);
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
                x => x
                    .OrderByDescending(v => v.SourceIsOfficial)
                    .ThenByDescending(v => v.AssemblyVersion)
                    .ThenBy(v => v.SourceName, StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                StringComparer.OrdinalIgnoreCase);

    private void RebuildProjectionLocked()
    {
        var runtimeNames = defaultPlugins
            .Select(x => x.InternalName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var combined = databaseVariants
            .Where(x => !x.SourceIsOfficial || !runtimeNames.Contains(x.InternalName))
            .Concat(defaultPlugins)
            .ToArray();
        var projection = MarketplaceCatalogRules.Project(combined);

        plugins = projection.Plugins;
        variants = projection.Variants;
        variantsByInternalName = BuildVariantIndex(projection.Variants);
        repositoryStatusCache.Clear();
        mainProjectionCache.Clear();
        mainVariantIndexCache.Clear();
        tagIndexCache.Clear();
        revision++;
    }

    private static bool IsOnlineOverlaySource(RepositorySource source)
        => source.Enabled && (source.IsOfficial || !source.IsCurated);

    public long Revision
    {
        get
        {
            lock (sync)
                return revision;
        }
    }

    public bool IsRefreshing { get; private set; }
    public bool HasLoaded { get; private set; }
    public int CachedRepositoryCount { get; private set; }
    public DateTimeOffset? LastRefresh { get; private set; }
    public string LastError { get; private set; } = string.Empty;

    /// <summary>
    /// Rebuilds the marketplace entirely from the local catalog database. No network requests occur.
    /// </summary>
}
