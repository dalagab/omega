namespace Dalagab.Omega;

internal enum CatalogAcquisitionMode
{
    LocalCache,
    OnlineCatalog,
}

/// <summary>
/// Omega's public Definitions are built online and shipped as one validated SQLite database. A
/// lightweight descriptor check can advertise a pending Definitions update without downloading it;
/// applying the update remains an explicit action except when Omega must seed an empty catalog.
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
    private int definitionsUpdateAvailable;
    private string availableDefinitionsRevision = string.Empty;

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
        var stateMatchesEndpoint = state.DescriptorUrl.Equals(endpoint.DescriptorUrl, StringComparison.OrdinalIgnoreCase);
        Mode = catalog.HasLoaded &&
               !string.IsNullOrWhiteSpace(state.CatalogSha256) &&
               stateMatchesEndpoint
            ? CatalogAcquisitionMode.OnlineCatalog
            : CatalogAcquisitionMode.LocalCache;

        if (stateMatchesEndpoint &&
            OnlineCatalogClient.IsValidSha256(state.AvailableCatalogSha256) &&
            !state.AvailableCatalogSha256.Equals(state.CatalogSha256, StringComparison.OrdinalIgnoreCase))
        {
            availableDefinitionsRevision = state.AvailableCatalogRevision;
            Volatile.Write(ref definitionsUpdateAvailable, 1);
        }
    }

    public bool IsRefreshing => Volatile.Read(ref running) != 0 || catalog.IsRefreshing;
    public bool OnlineConfigured => Uri.TryCreate(endpoint.DescriptorUrl, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;
    public CatalogAcquisitionMode Mode { get; private set; }
    public string LastOnlineError { get; private set; } = string.Empty;
    public string ModeLabel => Mode == CatalogAcquisitionMode.OnlineCatalog ? "Online Definitions" : "Local Definitions";
    public bool DefinitionsUpdateAvailable => Volatile.Read(ref definitionsUpdateAvailable) != 0;
    public string AvailableDefinitionsRevision => availableDefinitionsRevision;

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
    public Task CheckForUpdatesAsync() => CheckForUpdatesAsync(cts.Token);
    public Task ApplyDefinitionsUpdateAsync() => RefreshAsync(cts.Token);

    /// <summary>
    /// Editorial recovery remains bounded: it can directly check an explicitly requested source,
    /// but this never becomes a second persisted Definitions database.
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

    /// <summary>
    /// Checks the tiny online descriptor and records a pending Definitions update. Unmanaged Dalamud
    /// repositories are refreshed at the same time so the Updates page can reflect their versions.
    /// No central Definitions bundle is downloaded by this method.
    /// </summary>
    public Task CheckDefinitionsForUpdatesAsync(CancellationToken cancellationToken)
        => CheckForUpdatesCoreAsync(refreshUnmanagedDalamudSources: false, cancellationToken);

    public Task CheckForUpdatesAsync(CancellationToken cancellationToken)
        => CheckForUpdatesCoreAsync(refreshUnmanagedDalamudSources: true, cancellationToken);

    private async Task CheckForUpdatesCoreAsync(bool refreshUnmanagedDalamudSources, CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref running, 1) != 0)
            return;

        try
        {
            LastOnlineError = string.Empty;
            if (!OnlineConfigured)
            {
                LastOnlineError = "No HTTPS Omega Definitions endpoint is configured.";
                Mode = CatalogAcquisitionMode.LocalCache;
                return;
            }

            var state = stateStore.Load();
            var stateMatchesEndpoint = state.DescriptorUrl.Equals(endpoint.DescriptorUrl, StringComparison.OrdinalIgnoreCase);
            var currentHash = stateMatchesEndpoint && catalog.HasLoaded ? state.CatalogSha256 : string.Empty;
            var probe = await onlineClient.ProbeAsync(endpoint.DescriptorUrl, currentHash, cancellationToken).ConfigureAwait(false);

            if (probe.Status == OnlineCatalogCheckStatus.Unavailable)
            {
                LastOnlineError = probe.Error;
                Plugin.Log.Warning("Omega Definitions check failed; retaining local Definitions. Reason: {Reason}", probe.Error);
            }
            else if (probe.Descriptor is not null)
            {
                var available = probe.Status == OnlineCatalogCheckStatus.UpdateAvailable;
                availableDefinitionsRevision = available ? probe.Descriptor.CatalogRevision : string.Empty;
                Volatile.Write(ref definitionsUpdateAvailable, available ? 1 : 0);
                state.DescriptorUrl = endpoint.DescriptorUrl;
                state.AvailableCatalogSha256 = available ? probe.Descriptor.CatalogSha256.ToLowerInvariant() : string.Empty;
                state.AvailableCatalogRevision = available ? probe.Descriptor.CatalogRevision : string.Empty;
                state.CheckedAtUtc = DateTimeOffset.UtcNow;
                stateStore.Save(state);
                Mode = catalog.HasLoaded ? CatalogAcquisitionMode.OnlineCatalog : CatalogAcquisitionMode.LocalCache;
            }

            if (refreshUnmanagedDalamudSources)
                await RefreshUnmanagedDalamudSourcesAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            Interlocked.Exchange(ref running, 0);
        }
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
                LastOnlineError = "No HTTPS Omega Definitions endpoint is configured.";
                Mode = CatalogAcquisitionMode.LocalCache;
                return;
            }

            var onlineApplied = await TryApplyOnlineCatalogAsync(cancellationToken).ConfigureAwait(false);
            Mode = onlineApplied ? CatalogAcquisitionMode.OnlineCatalog : CatalogAcquisitionMode.LocalCache;
            await RefreshUnmanagedDalamudSourcesAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            Interlocked.Exchange(ref running, 0);
        }
    }

    private Task RefreshUnmanagedDalamudSourcesAsync()
    {
        var unmanagedDalamudSources = configuration.Repositories.Where(x => x.Enabled && !x.IsCurated).ToArray();
        return unmanagedDalamudSources.Length == 0
            ? Task.CompletedTask
            : catalog.RefreshRepositoriesAsync(unmanagedDalamudSources, configuration.Repositories);
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
            Plugin.Log.Warning("Omega online Definitions unavailable; retaining local Definitions. Reason: {Reason}", result.Error);
            return false;
        }

        if (result.Status == OnlineCatalogCheckStatus.Current)
        {
            ClearPendingDefinitionsUpdate(state);
            return catalog.HasLoaded;
        }

        if (result.Status != OnlineCatalogCheckStatus.Downloaded ||
            result.Descriptor is null || string.IsNullOrWhiteSpace(result.BundlePath))
        {
            LastOnlineError = "Online Definitions returned no usable SQLite bundle.";
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
                EvidenceRevision = applied.EvidenceRevision,
                GeneratedAtUtc = generatedAt,
                AppliedAtUtc = DateTimeOffset.UtcNow,
                CheckedAtUtc = DateTimeOffset.UtcNow,
            });
            availableDefinitionsRevision = string.Empty;
            Volatile.Write(ref definitionsUpdateAvailable, 0);

            Plugin.Log.Information(
                "Omega applied Definitions; variants={Variants}; sources={Sources}; definitionsRevision={DefinitionsRevision}; securityRevision={SecurityRevision}; evidenceRevision={EvidenceRevision}; sha256={Hash}",
                applied.VariantCount,
                applied.SourceDefinitions.Count,
                string.IsNullOrWhiteSpace(applied.CatalogRevision) ? "unavailable" : applied.CatalogRevision,
                string.IsNullOrWhiteSpace(applied.SecurityRevision) ? "unavailable" : applied.SecurityRevision,
                string.IsNullOrWhiteSpace(applied.EvidenceRevision) ? "unavailable" : applied.EvidenceRevision,
                result.Descriptor.CatalogSha256);
            return true;
        }
        catch (Exception ex)
        {
            LastOnlineError = ex.Message;
            Plugin.Log.Warning(ex, "Omega rejected the downloaded Definitions; retaining the previous local Definitions.");
            return false;
        }
        finally
        {
            try { File.Delete(result.BundlePath); } catch { }
        }
    }

    private void ClearPendingDefinitionsUpdate(OnlineCatalogState state)
    {
        availableDefinitionsRevision = string.Empty;
        Volatile.Write(ref definitionsUpdateAvailable, 0);
        if (string.IsNullOrWhiteSpace(state.AvailableCatalogSha256) && string.IsNullOrWhiteSpace(state.AvailableCatalogRevision))
            return;
        state.AvailableCatalogSha256 = string.Empty;
        state.AvailableCatalogRevision = string.Empty;
        state.CheckedAtUtc = DateTimeOffset.UtcNow;
        stateStore.Save(state);
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
