namespace Dalagab.Omega;

internal enum CatalogAcquisitionMode
{
    LocalCache,
    OnlineCatalog,
    LocalFallback,
}

/// <summary>
/// Preferred/fallback catalog acquisition policy.
///
/// Preferred: check one tiny catalog.json descriptor, download the complete prebuilt database only
/// when its semantic catalog hash changes, then optionally layer user-added repositories on top.
///
/// Fallback: if the online catalog cannot be checked/downloaded/validated, conditionally rebuild
/// the same local database from every enabled repository definition already bundled/configured.
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

    public string ModeLabel => Mode switch
    {
        CatalogAcquisitionMode.OnlineCatalog => "Online DB",
        CatalogAcquisitionMode.LocalFallback => "Local fallback",
        _ => "Local cache",
    };

    /// <summary>
    /// Fresh installs may seed asynchronously. Existing local databases never cause startup
    /// network traffic; their first online hash check remains daily/open/manual.
    /// </summary>
    public void SeedIfEmpty()
    {
        if (catalog.HasLoaded || IsRefreshing)
            return;
        _ = RefreshAsync(cts.Token);
    }

    public Task RefreshAsync() => RefreshAsync(cts.Token);

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref running, 1) != 0)
            return;

        try
        {
            LastOnlineError = string.Empty;
            if (OnlineConfigured)
            {
                var onlineApplied = await TryApplyOnlineCatalogAsync(cancellationToken).ConfigureAwait(false);
                if (onlineApplied)
                {
                    await RefreshUserRepositoriesAsync(cancellationToken).ConfigureAwait(false);
                    Mode = CatalogAcquisitionMode.OnlineCatalog;
                    return;
                }
            }

            // Central catalog unavailable: fall back to the complete local source definition list.
            await catalog.RefreshAsync(configuration.Repositories).ConfigureAwait(false);
            Mode = CatalogAcquisitionMode.LocalFallback;
            stateStore.ClearAppliedCatalog(endpoint.DescriptorUrl);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            Interlocked.Exchange(ref running, 0);
        }
    }

    /// <summary>
    /// When the authoritative online DB is active, opening plugin details only checks user-added
    /// source variants. Curated repository fan-out is unnecessary because the central DB already
    /// represents those records. In fallback mode the prior per-plugin source refresh is retained.
    /// </summary>
    public Task RefreshPluginSourcesAsync(string internalName)
    {
        if (Mode != CatalogAcquisitionMode.OnlineCatalog)
            return catalog.RefreshPluginSourcesAsync(internalName, configuration.Repositories);

        var selected = configuration.Repositories.Where(x =>
            x.Enabled &&
            !x.IsCurated &&
            catalog.GetVariants(internalName).Any(v =>
                NormalizeUrl(v.SourceUrl).Equals(NormalizeUrl(x.Url), StringComparison.OrdinalIgnoreCase)));

        return catalog.RefreshRepositoriesAsync(selected, configuration.Repositories);
    }

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
            Plugin.Log.Warning("Omega online catalog unavailable; using local repository fallback. Reason: {Reason}", result.Error);
            return false;
        }

        if (result.Status == OnlineCatalogCheckStatus.Current)
        {
            // Hash match means the local DB already corresponds to the published central snapshot.
            if (!catalog.HasLoaded)
                return false;
            return true;
        }

        if (result.Status != OnlineCatalogCheckStatus.Downloaded ||
            result.Descriptor is null ||
            string.IsNullOrWhiteSpace(result.BundlePath))
        {
            LastOnlineError = "Online catalog returned no usable database bundle.";
            return false;
        }

        try
        {
            var imported = catalog.ReplaceFromBundle(result.BundlePath, configuration.Repositories);
            var configChanged = CuratedSourceCatalog.MergeDefinitionsInto(configuration, imported.SourceDefinitions);
            if (configChanged)
            {
                configuration.Save();
                // Newly introduced online source definitions should participate in projection.
                catalog.LoadCached(configuration.Repositories);
            }

            var generatedAt = DateTimeOffset.TryParse(result.Descriptor.GeneratedAtUtc, out var parsed)
                ? parsed
                : (DateTimeOffset?)null;
            stateStore.Save(new OnlineCatalogState
            {
                SchemaVersion = 1,
                DescriptorUrl = endpoint.DescriptorUrl,
                CatalogSha256 = OnlineCatalogClient.EffectiveCatalogSha256(result.Descriptor).ToLowerInvariant(),
                GeneratedAtUtc = generatedAt,
                AppliedAtUtc = DateTimeOffset.UtcNow,
            });

            Plugin.Log.Information(
                "Omega applied central catalog database; records={Records}; sources={Sources}; sha256={Hash}",
                imported.Records.Count,
                imported.SourceDefinitions.Count,
                OnlineCatalogClient.EffectiveCatalogSha256(result.Descriptor));
            return true;
        }
        catch (Exception ex)
        {
            LastOnlineError = ex.Message;
            Plugin.Log.Warning(ex, "Omega rejected the downloaded central catalog; using local repository fallback.");
            return false;
        }
        finally
        {
            try { File.Delete(result.BundlePath); } catch { }
        }
    }

    private async Task RefreshUserRepositoriesAsync(CancellationToken cancellationToken)
    {
        var userRepositories = configuration.Repositories
            .Where(x => x.Enabled && !x.IsCurated)
            .ToArray();
        if (userRepositories.Length == 0)
            return; // Central catalog is complete: no repository fan-out is required.

        await catalog.RefreshRepositoriesAsync(userRepositories, configuration.Repositories).ConfigureAwait(false);
    }

    private static string NormalizeUrl(string? url) => (url ?? string.Empty).Trim().TrimEnd('/');

    public void Dispose()
    {
        cts.Cancel();
        onlineClient.Dispose();
        cts.Dispose();
        try
        {
            if (Directory.Exists(tempDirectory))
            {
                foreach (var file in Directory.EnumerateFiles(tempDirectory, "omega-catalog-*.zip"))
                {
                    try { File.Delete(file); } catch { }
                }
            }
        }
        catch { }
    }
}
