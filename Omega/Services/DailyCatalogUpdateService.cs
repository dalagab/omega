namespace Dalagab.Omega;

/// <summary>
/// Performs at most one automatic catalog check per 24 hours. The coordinator first checks the
/// tiny online catalog descriptor/hash. Only a changed central database is downloaded. If the
/// central path fails, the same job falls back to conditional checks of the local repository list.
/// </summary>
internal sealed class DailyCatalogUpdateService : IDisposable
{
    private static readonly TimeSpan InitialDelay = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan PollInterval = TimeSpan.FromHours(1);

    private readonly Configuration configuration;
    private readonly MarketplaceCatalogService catalog;
    private readonly CatalogUpdateCoordinator updates;
    private readonly CancellationTokenSource cts = new();
    private readonly Task worker;
    private int running;

    public DailyCatalogUpdateService(
        Configuration configuration,
        MarketplaceCatalogService catalog,
        CatalogUpdateCoordinator updates)
    {
        this.configuration = configuration;
        this.catalog = catalog;
        this.updates = updates;
        worker = RunAsync(cts.Token);
    }

    public void TriggerIfDue()
    {
        if (!IsDue())
            return;
        _ = CheckNowAsync(cts.Token);
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(InitialDelay, cancellationToken).ConfigureAwait(false);
            while (!cancellationToken.IsCancellationRequested)
            {
                if (IsDue())
                    await CheckNowAsync(cancellationToken).ConfigureAwait(false);
                await Task.Delay(PollInterval, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private bool IsDue()
    {
        if (!catalog.HasLoaded && updates.IsRefreshing)
            return false;
        var last = configuration.LastDailyUpdateCheckUtc;
        return last is null || DateTimeOffset.UtcNow - last.Value >= TimeSpan.FromDays(1);
    }

    private async Task CheckNowAsync(CancellationToken cancellationToken)
    {
        if (updates.IsRefreshing || Interlocked.Exchange(ref running, 1) != 0)
            return;

        try
        {
            await updates.RefreshAsync(cancellationToken).ConfigureAwait(false);
            configuration.LastDailyUpdateCheckUtc = DateTimeOffset.UtcNow;
            configuration.Save();
            Plugin.Log.Information(
                "Omega daily catalog check completed; mode={Mode}; cachedSources={SourceCount}",
                updates.ModeLabel,
                catalog.CachedRepositoryCount);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega daily catalog update failed; cached catalog remains active.");
        }
        finally
        {
            Interlocked.Exchange(ref running, 0);
        }
    }

    public void Dispose()
    {
        cts.Cancel();
        try { worker.Wait(TimeSpan.FromMilliseconds(250)); } catch { }
        cts.Dispose();
    }
}
