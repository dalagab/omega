namespace Dalagab.Omega;

internal sealed class MarketplaceCatalogService : IDisposable
{
    private readonly RepositoryClient client = new();
    private readonly CatalogDatabase database;
    private readonly object sync = new();
    private IReadOnlyList<MarketplacePlugin> plugins = [];
    private IReadOnlyList<MarketplacePlugin> variants = [];
    private CancellationTokenSource? refreshCts;
    private string[] loadedRepositoryUrls = [];

    public MarketplaceCatalogService(string databaseDirectory)
    {
        database = new CatalogDatabase(databaseDirectory);
    }

    public CatalogBundleImportResult ImportBundle(string zipPath)
        => CatalogBundleImporter.Import(zipPath, database);

    /// <summary>
    /// Replaces the curated catalog with an authoritative prebuilt bundle while preserving
    /// cached records for genuinely user-added repositories. The same database projection is
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
            .Where(x => x.Enabled && !x.IsCurated)
            .Select(x => database.TryRead(x.Url))
            .Where(x => x is not null)
            .Cast<CatalogDatabaseRecord>()
            .ToArray();

        database.ReplaceAll(read.Records, preserved);
        RebuildFromDatabase(repositories.Where(IsEligible).ToArray(), preserveLastRefresh: false);
        return read;
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
            return MarketplaceCatalogRules.GetVariants(variants, internalName);
    }

    public int GetStableApiLevel(string internalName, int preferredApi = 0)
    {
        lock (sync)
            return MarketplaceCatalogRules.GetStableApiLevel(variants, internalName, preferredApi);
    }

    public MarketplaceCatalogProjection GetMainProjection(int currentApi, string? sourceName = null)
    {
        IReadOnlyList<MarketplacePlugin> snapshot;
        lock (sync)
            snapshot = variants;

        var statuses = RepositoryHealthRules.BuildStatuses(snapshot, currentApi);
        var staleUrls = statuses
            .Where(x => x.IsStale)
            .Select(x => NormalizeUrl(x.SourceUrl))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var visible = snapshot.Where(x => !staleUrls.Contains(NormalizeUrl(x.SourceUrl)));
        if (!string.IsNullOrWhiteSpace(sourceName) &&
            !sourceName.Equals("All sources", StringComparison.OrdinalIgnoreCase))
        {
            visible = visible.Where(x => x.SourceName.Equals(sourceName, StringComparison.OrdinalIgnoreCase));
        }

        return MarketplaceCatalogRules.Project(visible);
    }

    public IReadOnlyList<MarketplacePlugin> GetMainVariants(string internalName, int currentApi)
        => MarketplaceCatalogRules.GetVariants(GetMainProjection(currentApi).Variants, internalName);

    public IReadOnlyList<RepositoryCatalogStatus> GetRepositoryStatuses(int currentApi)
    {
        IReadOnlyList<MarketplacePlugin> snapshot;
        lock (sync)
            snapshot = variants;
        return RepositoryHealthRules.BuildStatuses(snapshot, currentApi);
    }

    public RepositoryCatalogStatus? GetRepositoryStatus(string sourceUrl, int currentApi)
    {
        var normalized = NormalizeUrl(sourceUrl);
        return GetRepositoryStatuses(currentApi)
            .FirstOrDefault(x => NormalizeUrl(x.SourceUrl).Equals(normalized, StringComparison.OrdinalIgnoreCase));
    }

    public bool IsRefreshing { get; private set; }
    public bool HasLoaded { get; private set; }
    public int CachedRepositoryCount { get; private set; }
    public DateTimeOffset? LastRefresh { get; private set; }
    public string LastError { get; private set; } = string.Empty;

    /// <summary>
    /// Rebuilds the marketplace entirely from the local catalog database. No network requests occur.
    /// </summary>
    public void LoadCached(IEnumerable<RepositorySource> repositories)
        => RebuildFromDatabase(repositories.Where(IsEligible).ToArray(), preserveLastRefresh: false);

    public bool MatchesConfiguredSources(IEnumerable<RepositorySource> repositories)
    {
        var current = GetEligibleRepositoryUrls(repositories);
        lock (sync)
            return HasLoaded && current.SequenceEqual(loadedRepositoryUrls, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Explicit full-source check. Existing database records use HTTP validators, so unchanged feeds
    /// normally return 304 without downloading their JSON payload again.
    /// </summary>
    public Task RefreshAsync(IEnumerable<RepositorySource> repositories)
    {
        var all = repositories.Where(IsEligible).ToArray();
        return RefreshSelectedAsync(all, all);
    }

    /// <summary>
    /// Refreshes only a selected subset (normally user-added repositories) while rebuilding the
    /// storefront against the complete enabled source set already present in the local database.
    /// </summary>
    public Task RefreshRepositoriesAsync(
        IEnumerable<RepositorySource> selectedRepositories,
        IEnumerable<RepositorySource> allRepositories)
    {
        var all = allRepositories.Where(IsEligible).ToArray();
        var selectedUrls = selectedRepositories
            .Where(IsEligible)
            .Select(x => NormalizeUrl(x.Url))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var selected = all.Where(x => selectedUrls.Contains(NormalizeUrl(x.Url))).ToArray();
        return selected.Length == 0 ? Task.CompletedTask : RefreshSelectedAsync(selected, all);
    }

    /// <summary>
    /// Checks only the known source variants for one plugin, then rebuilds the complete storefront
    /// from the local database. This is used when a user opens plugin details.
    /// </summary>
    public Task RefreshPluginSourcesAsync(string internalName, IEnumerable<RepositorySource> repositories)
    {
        var all = repositories.Where(IsEligible).ToArray();
        var knownUrls = GetVariants(internalName)
            .Select(x => NormalizeUrl(x.SourceUrl))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var selected = all.Where(x => knownUrls.Contains(NormalizeUrl(x.Url))).ToArray();
        return selected.Length == 0 ? Task.CompletedTask : RefreshSelectedAsync(selected, all);
    }

    private Task RefreshSelectedAsync(
        IReadOnlyList<RepositorySource> selected,
        IReadOnlyList<RepositorySource> all)
    {
        if (IsRefreshing)
            return Task.CompletedTask;

        refreshCts?.Cancel();
        refreshCts?.Dispose();
        refreshCts = new CancellationTokenSource();
        return RefreshCoreAsync(selected, all, refreshCts.Token);
    }

    private async Task RefreshCoreAsync(
        IReadOnlyList<RepositorySource> selectedRepositories,
        IReadOnlyList<RepositorySource> allRepositories,
        CancellationToken cancellationToken)
    {
        IsRefreshing = true;
        LastError = string.Empty;
        var errors = new List<string>();
        try
        {
            // Deliberately sequential. Omega may curate many sources, but a refresh should not create
            // a burst of simultaneous network requests from inside the game process.
            foreach (var repository in selectedRepositories)
            {
                try
                {
                    var cached = database.TryRead(repository.Url);
                    var fetched = await client.FetchAsync(repository, cached, cancellationToken).ConfigureAwait(false);
                    var checkedAt = DateTimeOffset.UtcNow;

                    if (fetched.NotModified && cached is not null)
                    {
                        database.MarkChecked(cached, fetched.ETag, fetched.LastModified, checkedAt);
                    }
                    else
                    {
                        database.Store(
                            repository.Url,
                            fetched.ManifestJson,
                            fetched.ETag,
                            fetched.LastModified,
                            checkedAt);
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    errors.Add($"{repository.Name}: {ex.Message}");
                    Plugin.Log.Warning(ex, "Failed to check Omega repository {Repository}; cached data will be retained when available.", repository.Url);
                }
            }

            RebuildFromDatabase(allRepositories, preserveLastRefresh: true);
            LastRefresh = DateTimeOffset.Now;
            LastError = string.Join(" | ", errors);
        }
        catch (OperationCanceledException)
        {
            // A newer explicit check superseded this one.
        }
        finally
        {
            IsRefreshing = false;
        }
    }

    private void RebuildFromDatabase(IReadOnlyList<RepositorySource> repositories, bool preserveLastRefresh)
    {
        var results = new List<MarketplacePlugin>();
        var loadedUrls = new List<string>();
        var errors = new List<string>();
        DateTimeOffset? newestCheck = null;

        foreach (var repository in repositories)
        {
            var cached = database.TryRead(repository.Url);
            if (cached is null)
                continue;

            try
            {
                results.AddRange(RepositoryManifestParser.Parse(cached.ManifestJson, repository));
                loadedUrls.Add(NormalizeUrl(repository.Url));
                if (newestCheck is null || cached.CheckedAtUtc > newestCheck)
                    newestCheck = cached.CheckedAtUtc;
            }
            catch (Exception ex)
            {
                errors.Add($"{repository.Name}: cached manifest invalid ({ex.Message})");
                Plugin.Log.Warning(ex, "Failed to load cached Omega repository {Repository}", repository.Url);
            }
        }

        var projection = MarketplaceCatalogRules.Project(results);
        lock (sync)
        {
            plugins = projection.Plugins;
            variants = projection.Variants;
            loadedRepositoryUrls = repositories
                .Select(x => NormalizeUrl(x.Url))
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            CachedRepositoryCount = loadedUrls.Count;
            HasLoaded = CachedRepositoryCount > 0;
        }

        if (!preserveLastRefresh && newestCheck is not null)
            LastRefresh = newestCheck.Value.ToLocalTime();
        if (errors.Count > 0)
            LastError = string.Join(" | ", errors);
    }

    private static bool IsEligible(RepositorySource source)
    {
        if (!source.Enabled || !Uri.TryCreate(source.Url, UriKind.Absolute, out var uri))
            return false;
        return uri.Scheme == Uri.UriSchemeHttps;
    }

    private static string[] GetEligibleRepositoryUrls(IEnumerable<RepositorySource> repositories)
        => repositories
            .Where(IsEligible)
            .Select(x => NormalizeUrl(x.Url))
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static string NormalizeUrl(string url) => url.Trim().TrimEnd('/');

    public void Dispose()
    {
        refreshCts?.Cancel();
        refreshCts?.Dispose();
        client.Dispose();
    }
}
