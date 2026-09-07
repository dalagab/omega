namespace Dalagab.Omega;

internal sealed record SqliteCatalogApplyResult(
    int VariantCount,
    IReadOnlyList<CuratedSourceDefinition> SourceDefinitions,
    DateTimeOffset? GeneratedAtUtc,
    string CatalogRevision,
    string DefinitionsRevision,
    string SecurityRevision,
    string EvidenceRevision,
    string DependencyGraphRevision);

/// <summary>
/// Owns Omega's in-memory marketplace projection backed by the compiled client SQLite database.
/// Canonical public catalog state lives in the online JSON snapshot; this database is the bounded
/// daily/manual projection Omega consumes. Direct repository reads remain temporary overlays only.
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
    private const int DetailedVariantCacheLimit = 64;
    private const int ChangelogCacheLimit = 32;
    private readonly Dictionary<string, MarketplacePlugin[]> detailedVariantCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<string> detailedVariantCacheOrder = new();
    private readonly Dictionary<string, IReadOnlyList<MarketplaceChangelogEntry>> changelogCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<string> changelogCacheOrder = new();
    private readonly Dictionary<long, IReadOnlyList<PluginDependencyEdge>> dependenciesByVariantCache = new();
    private readonly Dictionary<long, IReadOnlyList<PluginDependencyEdge>> dependenciesByPluginCache = new();
    private readonly Dictionary<long, IReadOnlyList<PluginDependencyEdge>> dependentsByProviderIdCache = new();
    private readonly Dictionary<string, IReadOnlyList<PluginDependencyEdge>> dependentsByProviderNameCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<long, PluginDependencyProvider?> dependencyProviderByIdCache = new();
    private readonly Dictionary<string, PluginDependencyProvider?> dependencyProviderByNameCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, IReadOnlyList<RepositoryCatalogStatus>> repositoryStatusCache = new();
    private readonly Dictionary<int, IReadOnlyList<RepositoryCatalogStatus>> repositoryInventoryStatusCache = new();
    private readonly Dictionary<string, MarketplaceCatalogProjection> mainProjectionCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, IReadOnlyDictionary<string, MarketplacePlugin[]>> mainVariantIndexCache = new();
    private readonly Dictionary<string, MarketplaceTagIndex> tagIndexCache = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? refreshCts;
    private string[] loadedRepositoryUrls = [];
    private HashSet<string> loadedRepositoryUrlSet = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> definitionsRepositoryUrlSet = new(StringComparer.OrdinalIgnoreCase);
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
            snapshot.DefinitionsRevision,
            snapshot.SecurityRevision,
            snapshot.EvidenceRevision,
            snapshot.DependencyGraphRevision);
    }

    public IReadOnlyList<CuratedSourceDefinition> ReadDatabaseSourceDefinitions()
        => store.ReadSourceDefinitions();

    public IReadOnlyList<PluginDependencyEdge> GetDependenciesForVariant(long variantId)
    {
        if (variantId <= 0)
            return [];
        lock (sync)
        {
            if (!dependenciesByVariantCache.TryGetValue(variantId, out var value))
                dependenciesByVariantCache[variantId] = value = store.ReadDependenciesForVariant(variantId);
            return value;
        }
    }

    public IReadOnlyList<PluginDependencyEdge> GetDependenciesForPlugin(long pluginId)
    {
        if (pluginId <= 0)
            return [];
        lock (sync)
        {
            if (!dependenciesByPluginCache.TryGetValue(pluginId, out var value))
                dependenciesByPluginCache[pluginId] = value = store.ReadDependenciesForPlugin(pluginId);
            return value;
        }
    }

    public IReadOnlyList<PluginDependencyEdge> GetDependentsForProvider(long providerPluginId)
    {
        if (providerPluginId <= 0)
            return [];
        lock (sync)
        {
            if (!dependentsByProviderIdCache.TryGetValue(providerPluginId, out var value))
                dependentsByProviderIdCache[providerPluginId] = value = store.ReadDependentsForProvider(providerPluginId);
            return value;
        }
    }

    public IReadOnlyList<PluginDependencyEdge> GetDependentsForProvider(string internalName)
    {
        var key = (internalName ?? string.Empty).Trim();
        if (key.Length == 0)
            return [];
        lock (sync)
        {
            if (!dependentsByProviderNameCache.TryGetValue(key, out var value))
                dependentsByProviderNameCache[key] = value = store.ReadDependentsForProvider(key);
            return value;
        }
    }

    public PluginDependencyProvider? GetDependencyProvider(long providerPluginId)
    {
        if (providerPluginId <= 0)
            return null;
        lock (sync)
        {
            if (!dependencyProviderByIdCache.TryGetValue(providerPluginId, out var value))
                dependencyProviderByIdCache[providerPluginId] = value = store.ReadDependencyProvider(providerPluginId);
            return value;
        }
    }

    public PluginDependencyProvider? GetDependencyProvider(string internalName)
    {
        var key = (internalName ?? string.Empty).Trim();
        if (key.Length == 0)
            return null;
        lock (sync)
        {
            if (!dependencyProviderByNameCache.TryGetValue(key, out var value))
                dependencyProviderByNameCache[key] = value = store.ReadDependencyProvider(key);
            return value;
        }
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

    /// <summary>
    /// Full repository inventory used by Settings projections. Unlike <see cref="Variants"/>, this
    /// retains disabled Definitions sources so API filtering and repository review remain accurate
    /// without re-reading repositories while the Settings window is open.
    /// </summary>
    public IReadOnlyList<MarketplacePlugin> GetRepositoryInventoryVariants()
    {
        lock (sync)
            return allDatabaseVariants
                .Concat(liveOverlayByUrl.Values.SelectMany(x => x))
                .Concat(defaultPlugins)
                .ToArray();
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

    public MarketplacePlugin HydrateVariant(MarketplacePlugin summary)
    {
        if (string.IsNullOrWhiteSpace(summary.InternalName))
            return summary;

        MarketplacePlugin[] details;
        lock (sync)
        {
            if (!detailedVariantCache.TryGetValue(summary.InternalName, out details!))
            {
                details = store.ReadVariantDetails(summary.InternalName).ToArray();
                detailedVariantCache[summary.InternalName] = details;
                detailedVariantCacheOrder.Enqueue(summary.InternalName);
                while (detailedVariantCacheOrder.Count > DetailedVariantCacheLimit)
                    detailedVariantCache.Remove(detailedVariantCacheOrder.Dequeue());
            }
        }

        var detailed = details.FirstOrDefault(candidate =>
            summary.CatalogPluginId > 0
                ? candidate.CatalogPluginId == summary.CatalogPluginId &&
                  NormalizeUrl(candidate.SourceUrl).Equals(NormalizeUrl(summary.SourceUrl), StringComparison.OrdinalIgnoreCase) &&
                  candidate.AssemblyVersionText.Equals(summary.AssemblyVersionText, StringComparison.OrdinalIgnoreCase)
                : summary.CanInheritSecurityProjectionFrom(candidate));

        if (detailed is null)
            return summary;

        if (summary.CatalogPluginId <= 0)
        {
            // Runtime manifests remain authoritative for fresh install/update metadata.
            // Enriched presentation metadata and the full exact-version Sigmascope projection may
            // be copied from the same source/version database row without replacing live package links.
            summary.OmegaWebsiteLicense = detailed.OmegaWebsiteLicense;
            summary.ApplySecurityProjectionFrom(detailed);
            return summary;
        }

        return detailed;
    }

    public IReadOnlySet<string> SearchInternalNames(string search, string? sourceName = null)
        => store.SearchInternalNames(search, sourceName);

    public IReadOnlySet<string> QueryDiscoverInternalNames(
        string search,
        string? sourceName,
        int apiLevel,
        bool requireInstallableApiBuild,
        bool preferTesting,
        string? category,
        IReadOnlyCollection<string> tags,
        bool? adultOnly,
        int securityFilter)
    {
        string[] enabledSourceUrls;
        lock (sync)
        {
            enabledSourceUrls = databaseVariants
                .Select(x => NormalizeUrl(x.SourceUrl))
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        return store.QueryDiscoverInternalNames(
            search,
            sourceName,
            enabledSourceUrls,
            apiLevel,
            requireInstallableApiBuild,
            preferTesting,
            category,
            tags,
            adultOnly,
            securityFilter);
    }

    public int GetDiscoverCompatibleCount(int currentApi, bool preferTesting)
    {
        string[] enabledSourceUrls;
        MarketplacePlugin[] localVariants;
        lock (sync)
        {
            enabledSourceUrls = databaseVariants
                .Select(x => NormalizeUrl(x.SourceUrl))
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            localVariants = variants.Where(x => x.CatalogPluginId <= 0).ToArray();
        }

        var names = store.QueryDiscoverInternalNames(
            string.Empty,
            "All sources",
            enabledSourceUrls,
            currentApi,
            true,
            preferTesting,
            "All categories",
            [],
            null,
            0).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var variant in localVariants)
        {
            if (variant.HasCurrentApiBuild(currentApi, preferTesting, out _))
                names.Add(variant.InternalName);
        }
        return names.Count;
    }

    public IReadOnlyList<MarketplaceChangelogEntry> GetChangelogHistory(string internalName, string? preferredSourceUrl = null)
    {
        IReadOnlyList<MarketplaceChangelogEntry> entries;
        lock (sync)
        {
            if (!changelogCache.TryGetValue(internalName, out entries!))
            {
                entries = store.ReadChangelogHistory(internalName);
                changelogCache[internalName] = entries;
                changelogCacheOrder.Enqueue(internalName);
                while (changelogCacheOrder.Count > ChangelogCacheLimit)
                    changelogCache.Remove(changelogCacheOrder.Dequeue());
            }
        }

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

    private void ClearLazyCachesLocked()
    {
        detailedVariantCache.Clear();
        detailedVariantCacheOrder.Clear();
        changelogCache.Clear();
        changelogCacheOrder.Clear();
        dependenciesByVariantCache.Clear();
        dependenciesByPluginCache.Clear();
        dependentsByProviderIdCache.Clear();
        dependentsByProviderNameCache.Clear();
        dependencyProviderByIdCache.Clear();
        dependencyProviderByNameCache.Clear();
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

    public MarketplacePopularitySnapshot GetDailyPopularitySnapshot(int currentApi)
    {
        lock (sync)
        {
            // Popularity is anchored to the complete daily SQLite-backed catalog, not runtime
            // Dalamud overlays, temporary user-added sources, or the current source filter.
            var daily = MarketplaceCatalogRules.Project(allDatabaseVariants, currentApi);
            return MarketplacePopularityRules.Build(daily.Plugins);
        }
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

    /// <summary>
    /// Repository inventory for Settings. Unlike the marketplace projection this includes disabled
    /// Definitions sources and temporary unmanaged Dalamud overlays so rows do not disappear merely
    /// because the user disabled them.
    /// </summary>
    public IReadOnlyList<RepositoryCatalogStatus> GetRepositoryInventoryStatuses(int currentApi)
    {
        lock (sync)
        {
            if (repositoryInventoryStatusCache.TryGetValue(currentApi, out var cached))
                return cached;

            var inventory = allDatabaseVariants
                .Concat(liveOverlayByUrl.Values.SelectMany(x => x))
                .Concat(defaultPlugins)
                .ToArray();
            var statuses = RepositoryHealthRules.BuildStatuses(inventory, currentApi);
            repositoryInventoryStatusCache[currentApi] = statuses;
            return statuses;
        }
    }

    public bool IsSourceInDefinitions(string sourceUrl)
    {
        var normalized = NormalizeUrl(sourceUrl);
        lock (sync)
            return definitionsRepositoryUrlSet.Contains(normalized);
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

    private MarketplacePlugin MergeDatabaseSecurityLocked(MarketplacePlugin runtimePlugin)
    {
        // Runtime manifests are deliberately fresher than the compiled catalog for install/update metadata,
        // but they do not carry Omega's server-side Sigmascope projection. Clear any projection inherited
        // during an earlier rebuild first, then reattach only evidence from the same source/package version.
        runtimePlugin.ApplySecurityProjectionFrom(null);
        var security = allDatabaseVariants
            .Where(runtimePlugin.CanInheritSecurityProjectionFrom)
            .Where(x => !string.IsNullOrWhiteSpace(x.SecurityStatus) || !string.IsNullOrWhiteSpace(x.SecurityArtifactSha256))
            .OrderByDescending(x => x.HasCompletedSecurityScan)
            .ThenByDescending(x => x.SecurityScannedAtUtc ?? DateTimeOffset.MinValue)
            .FirstOrDefault();
        runtimePlugin.ApplySecurityProjectionFrom(security);
        return runtimePlugin;
    }

    private void RebuildProjectionLocked()
    {
        var runtimeDefaults = defaultPlugins.Select(MergeDatabaseSecurityLocked).ToArray();
        var runtimeNames = runtimeDefaults.Select(x => x.InternalName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var combined = databaseVariants
            .Where(x => !x.SourceIsOfficial || !runtimeNames.Contains(x.InternalName))
            .Concat(runtimeDefaults)
            .ToArray();
        var projection = MarketplaceCatalogRules.Project(combined);

        plugins = projection.Plugins;
        variants = projection.Variants;
        variantsByInternalName = BuildVariantIndex(projection.Variants);
        presentationVariantsByInternalName = BuildVariantIndex(databaseVariants.Concat(runtimeDefaults));
        repositoryStatusCache.Clear();
        repositoryInventoryStatusCache.Clear();
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
    public string DefinitionsRevision { get; private set; } = string.Empty;
    public string SecurityRevision { get; private set; } = string.Empty;
    public string EvidenceRevision { get; private set; } = string.Empty;
    public string DependencyGraphRevision { get; private set; } = string.Empty;
    public long DatabaseSizeBytes { get; private set; }
    public DateTimeOffset? RevisionUpdatedAtUtc { get; private set; }
    public int CatalogChangelogEntryCount { get; private set; }
    public string LastError { get; private set; } = string.Empty;

    private static string NormalizeUrl(string? url) => (url ?? string.Empty).Trim().TrimEnd('/');
}
