namespace Dalagab.Omega;

internal sealed partial class MarketplaceCatalogService
{
    public void LoadCached(IEnumerable<RepositorySource> repositories)
        => RebuildFromDatabase(repositories.Where(IsEligible).ToArray(), preserveLastRefresh: false);

    public bool MatchesConfiguredSources(IEnumerable<RepositorySource> repositories)
    {
        lock (sync)
        {
            if (!HasLoaded)
                return false;

            var availableUrls = loadedRepositoryUrlSet
                .Concat(defaultPlugins.Select(x => NormalizeUrl(x.SourceUrl)))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var configuredUrls = repositories
                .Where(IsEligible)
                .Select(x => NormalizeUrl(x.Url))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            return configuredUrls.SetEquals(availableUrls);
        }
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

        var repositoryUrls = repositories
            .Select(x => NormalizeUrl(x.Url))
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var repositoryUrlSet = repositoryUrls.ToHashSet(StringComparer.OrdinalIgnoreCase);

        lock (sync)
        {
            databaseVariants = results;
            loadedRepositoryUrls = repositoryUrls;
            loadedRepositoryUrlSet = repositoryUrlSet;
            CachedRepositoryCount = loadedUrls.Count;
            RebuildProjectionLocked();
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
