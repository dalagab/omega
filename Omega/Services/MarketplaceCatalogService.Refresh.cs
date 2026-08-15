namespace Dalagab.Omega;

internal sealed partial class MarketplaceCatalogService
{
    public void LoadCached(IEnumerable<RepositorySource> repositories)
    {
        if (!store.Exists)
        {
            lock (sync)
            {
                allDatabaseVariants = [];
                databaseVariants = [];
                HasLoaded = false;
                CachedRepositoryCount = 0;
                CatalogRevision = string.Empty;
                SecurityRevision = string.Empty;
                RevisionUpdatedAtUtc = null;
                CatalogChangelogEntryCount = 0;
                RebuildProjectionLocked();
            }
            return;
        }

        try
        {
            var snapshot = store.ReadSnapshot();
            ApplySnapshot(snapshot, repositories, preserveLastRefresh: false);
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Plugin.Log.Warning(ex, "Omega could not load its SQLite catalog database.");
        }
    }

    public bool MatchesConfiguredSources(IEnumerable<RepositorySource> repositories)
    {
        lock (sync)
        {
            if (!HasLoaded)
                return false;
            var configured = repositories.Where(x => x.Enabled && !x.IsCurated)
                .Select(x => NormalizeUrl(x.Url))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var represented = loadedRepositoryUrlSet
                .Concat(defaultPlugins.Select(x => NormalizeUrl(x.SourceUrl)))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            return configured.All(x => represented.Contains(x));
        }
    }

    /// <summary>
    /// The public catalog is refreshed by CatalogUpdateCoordinator. Direct repository refresh is
    /// intentionally reserved for user-added/explicit source checks and stays in-memory.
    /// </summary>
    public Task RefreshAsync(IEnumerable<RepositorySource> repositories)
    {
        var selected = repositories.Where(x => x.Enabled && !x.IsCurated).ToArray();
        return selected.Length == 0 ? Task.CompletedTask : RefreshRepositoriesAsync(selected, repositories);
    }

    public Task RefreshRepositoriesAsync(
        IEnumerable<RepositorySource> selectedRepositories,
        IEnumerable<RepositorySource> allRepositories)
    {
        var selected = selectedRepositories.Where(IsEligible).ToArray();
        var all = allRepositories.Where(x => x.Enabled).ToArray();
        return selected.Length == 0 ? Task.CompletedTask : RefreshSelectedAsync(selected, all);
    }

    public Task RefreshPluginSourcesAsync(string internalName, IEnumerable<RepositorySource> repositories)
    {
        var knownUrls = GetVariants(internalName)
            .Select(x => NormalizeUrl(x.SourceUrl))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var selected = repositories
            .Where(x => IsEligible(x) && (!x.IsCurated || x.IsOfficial))
            .Where(x => knownUrls.Contains(NormalizeUrl(x.Url)))
            .ToArray();
        return selected.Length == 0 ? Task.CompletedTask : RefreshSelectedAsync(selected, repositories.Where(x => x.Enabled).ToArray());
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
            foreach (var repository in selectedRepositories)
            {
                try
                {
                    var fetched = await client.FetchAsync(repository, cancellationToken).ConfigureAwait(false);
                    var parsed = RepositoryManifestParser.Parse(fetched.ManifestJson, repository).ToArray();
                    lock (sync)
                        liveOverlayByUrl[NormalizeUrl(repository.Url)] = parsed;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    errors.Add($"{repository.Name}: {ex.Message}");
                    Plugin.Log.Warning(ex, "Failed to check Omega repository {Repository}; central SQLite catalog remains active.", repository.Url);
                }
            }

            RebuildForConfiguration(allRepositories, preserveLastRefresh: true);
            LastRefresh = DateTimeOffset.Now;
            LastError = string.Join(" | ", errors);
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            IsRefreshing = false;
        }
    }

    private void ApplySnapshot(
        SqliteCatalogSnapshot snapshot,
        IEnumerable<RepositorySource> repositories,
        bool preserveLastRefresh)
    {
        lock (sync)
        {
            allDatabaseVariants = snapshot.Variants;
            CatalogRevision = snapshot.CatalogRevision;
            SecurityRevision = snapshot.SecurityRevision;
            RevisionUpdatedAtUtc = snapshot.RevisionUpdatedAtUtc;
            CatalogChangelogEntryCount = snapshot.ChangelogEntryCount;
        }
        RebuildForConfiguration(repositories.Where(x => x.Enabled).ToArray(), preserveLastRefresh);
        if (!preserveLastRefresh && snapshot.GeneratedAtUtc is not null)
            LastRefresh = snapshot.GeneratedAtUtc.Value.ToLocalTime();
    }

    private void RebuildForConfiguration(
        IEnumerable<RepositorySource> repositories,
        bool preserveLastRefresh)
    {
        var enabledUrls = repositories
            .Where(x => x.Enabled)
            .Select(x => NormalizeUrl(x.Url))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        lock (sync)
        {
            // Central DB variants are filtered by the user's source switches. A temporary explicit
            // source refresh replaces the same source URL for this process only.
            var baseVariants = allDatabaseVariants
                .Where(x => enabledUrls.Count == 0 || enabledUrls.Contains(NormalizeUrl(x.SourceUrl)))
                .Where(x => !liveOverlayByUrl.ContainsKey(NormalizeUrl(x.SourceUrl)))
                .ToList();
            foreach (var pair in liveOverlayByUrl)
            {
                if (enabledUrls.Contains(pair.Key))
                    baseVariants.AddRange(pair.Value);
            }

            databaseVariants = baseVariants;
            loadedRepositoryUrls = databaseVariants.Select(x => NormalizeUrl(x.SourceUrl))
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            loadedRepositoryUrlSet = loadedRepositoryUrls.ToHashSet(StringComparer.OrdinalIgnoreCase);
            CachedRepositoryCount = loadedRepositoryUrls.Length;
            HasLoaded = databaseVariants.Count > 0;
            RebuildProjectionLocked();
        }

        if (!preserveLastRefresh && LastRefresh is null && HasLoaded)
            LastRefresh = DateTimeOffset.Now;
    }

    private static bool IsEligible(RepositorySource source)
    {
        if (!source.Enabled || !Uri.TryCreate(source.Url, UriKind.Absolute, out var uri))
            return false;
        return uri.Scheme == Uri.UriSchemeHttps;
    }

    public void Dispose()
    {
        refreshCts?.Cancel();
        refreshCts?.Dispose();
        client.Dispose();
    }
}
