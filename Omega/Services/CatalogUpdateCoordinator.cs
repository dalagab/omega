namespace Dalagab.Omega;

internal enum CatalogAcquisitionMode
{
    LocalCache,
    OnlineCatalog,
}

/// <summary>
/// Omega's public catalog is built online and shipped as one validated SQLite database. If the
/// online descriptor cannot be checked, the last-known-good local database remains active; the
/// game client never rebuilds the public catalog by crawling every repository itself.
/// </summary>
internal sealed class CatalogUpdateCoordinator : IDisposable
{
    private readonly Configuration configuration;
    private readonly MarketplaceCatalogService catalog;
    private readonly OnlineCatalogClient onlineClient = new();
    private readonly OnlineCatalogStateStore stateStore;
    private readonly OnlineCatalogEndpointDefinition endpoint;
    private readonly string tempDirectory;
    private readonly CancellationTokenSource cts = new();
    private static readonly TimeSpan EmptyCatalogRetryDelay = TimeSpan.FromSeconds(20);
    private DateTimeOffset nextEmptyCatalogAttemptUtc = DateTimeOffset.MinValue;
    private int running;

    public CatalogUpdateCoordinator(
        Configuration configuration,
        MarketplaceCatalogService catalog,
        string assemblyDirectory,
        string configDirectory)
    {
        this.configuration = configuration;
        this.catalog = catalog;
        endpoint = OnlineCatalogEndpointCatalog.Load(assemblyDirectory, configDirectory);
        stateStore = new OnlineCatalogStateStore(configDirectory);
        tempDirectory = Path.Combine(configDirectory, "catalog-downloads");

        var state = stateStore.Load();
        Mode = catalog.HasLoaded &&
               !string.IsNullOrWhiteSpace(state.CatalogSha256) &&
               state.DescriptorUrl.Equals(endpoint.DescriptorUrl, StringComparison.OrdinalIgnoreCase)
            ? CatalogAcquisitionMode.OnlineCatalog
            : CatalogAcquisitionMode.LocalCache;
    }

    public bool IsRefreshing => Volatile.Read(ref running) != 0 || catalog.IsRefreshing;
    public bool OnlineConfigured => Uri.TryCreate(endpoint.DescriptorUrl, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;
    public CatalogAcquisitionMode Mode { get; private set; }
    public string LastOnlineError { get; private set; } = string.Empty;
    public string ModeLabel => Mode == CatalogAcquisitionMode.OnlineCatalog ? "Online DB" : "Local DB";

    public void SeedIfEmpty()
    {
        if (catalog.HasLoaded || IsRefreshing)
            return;

        var now = DateTimeOffset.UtcNow;
        if (now < nextEmptyCatalogAttemptUtc)
            return;

        nextEmptyCatalogAttemptUtc = now + EmptyCatalogRetryDelay;
        _ = RefreshAsync(cts.Token);
    }

    public Task RefreshAsync() => RefreshAsync(cts.Token);

    /// <summary>
    /// Editorial recovery remains bounded: it can directly check an explicitly requested source,
    /// but this never becomes a second persisted catalog database.
    /// </summary>
    public Task RefreshCuratedSourcesAsync(IEnumerable<string> curatedIds)
    {
        var wanted = curatedIds.Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var selected = configuration.Repositories
            .Where(x => x.Enabled && x.IsCurated && wanted.Contains(x.CuratedId))
            .ToArray();
        return selected.Length == 0
            ? Task.CompletedTask
            : catalog.RefreshRepositoriesAsync(selected, configuration.Repositories);
    }

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref running, 1) != 0)
            return;

        try
        {
            LastOnlineError = string.Empty;
            if (!OnlineConfigured)
            {
                LastOnlineError = "No HTTPS Omega catalog endpoint is configured.";
                Mode = CatalogAcquisitionMode.LocalCache;
                return;
            }

            var onlineApplied = await TryApplyOnlineCatalogAsync(cancellationToken).ConfigureAwait(false);
            Mode = onlineApplied ? CatalogAcquisitionMode.OnlineCatalog : CatalogAcquisitionMode.LocalCache;

            // User-added sources are an explicit local overlay and can still be refreshed directly.
            var userSources = configuration.Repositories.Where(x => x.Enabled && !x.IsCurated).ToArray();
            if (userSources.Length > 0)
                await catalog.RefreshRepositoriesAsync(userSources, configuration.Repositories).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            Interlocked.Exchange(ref running, 0);
        }
    }

    public Task RefreshPluginSourcesAsync(string internalName)
        => catalog.RefreshPluginSourcesAsync(internalName, configuration.Repositories);

    private async Task<bool> TryApplyOnlineCatalogAsync(CancellationToken cancellationToken)
    {
        var state = stateStore.Load();
        var stateMatchesEndpoint = state.DescriptorUrl.Equals(endpoint.DescriptorUrl, StringComparison.OrdinalIgnoreCase);
        var currentHash = stateMatchesEndpoint && catalog.HasLoaded ? state.CatalogSha256 : string.Empty;

        var result = await onlineClient.CheckAsync(
            endpoint.DescriptorUrl,
            currentHash,
            tempDirectory,
            cancellationToken).ConfigureAwait(false);

        if (result.Status == OnlineCatalogCheckStatus.Unavailable)
        {
            LastOnlineError = result.Error;
            Plugin.Log.Warning("Omega online SQLite catalog unavailable; retaining local database. Reason: {Reason}", result.Error);
            return false;
        }

        if (result.Status == OnlineCatalogCheckStatus.Current)
            return catalog.HasLoaded;

        if (result.Status != OnlineCatalogCheckStatus.Downloaded ||
            result.Descriptor is null || string.IsNullOrWhiteSpace(result.BundlePath))
        {
            LastOnlineError = "Online catalog returned no usable SQLite bundle.";
            return false;
        }

        try
        {
            var applied = catalog.ReplaceFromBundle(result.BundlePath, configuration.Repositories);
            if (CuratedSourceCatalog.MergeDefinitionsInto(configuration, applied.SourceDefinitions))
            {
                configuration.Save();
                catalog.LoadCached(configuration.Repositories);
            }

            var generatedAt = DateTimeOffset.TryParse(result.Descriptor.GeneratedAtUtc, out var parsed)
                ? parsed
                : (DateTimeOffset?)null;
            stateStore.Save(new OnlineCatalogState
            {
                SchemaVersion = 1,
                DescriptorUrl = endpoint.DescriptorUrl,
                CatalogSha256 = result.Descriptor.CatalogSha256.ToLowerInvariant(),
                CatalogRevision = applied.CatalogRevision,
                SecurityRevision = applied.SecurityRevision,
                GeneratedAtUtc = generatedAt,
                AppliedAtUtc = DateTimeOffset.UtcNow,
            });

            Plugin.Log.Information(
                "Omega applied SQLite catalog; variants={Variants}; sources={Sources}; catalogRevision={CatalogRevision}; securityRevision={SecurityRevision}; sha256={Hash}",
                applied.VariantCount,
                applied.SourceDefinitions.Count,
                string.IsNullOrWhiteSpace(applied.CatalogRevision) ? "unavailable" : applied.CatalogRevision,
                string.IsNullOrWhiteSpace(applied.SecurityRevision) ? "unavailable" : applied.SecurityRevision,
                result.Descriptor.CatalogSha256);
            return true;
        }
        catch (Exception ex)
        {
            LastOnlineError = ex.Message;
            Plugin.Log.Warning(ex, "Omega rejected the downloaded SQLite catalog; retaining the previous local database.");
            return false;
        }
        finally
        {
            try { File.Delete(result.BundlePath); } catch { }
        }
    }

    public void Dispose()
    {
        cts.Cancel();
        onlineClient.Dispose();
        cts.Dispose();
        try
        {
            if (!Directory.Exists(tempDirectory))
                return;
            foreach (var file in Directory.EnumerateFiles(tempDirectory, "omega-catalog-*.zip"))
            {
                try { File.Delete(file); } catch { }
            }
        }
        catch { }
    }
}
