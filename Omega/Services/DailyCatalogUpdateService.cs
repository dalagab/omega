using Dalamud.Plugin.Services;

namespace Dalagab.Omega;

/// <summary>
/// Performs lightweight automatic Definitions checks while Omega is loaded. The tiny online descriptor
/// is checked hourly without downloading a changed central database; a pending Definitions update is
/// surfaced in Omega and announced once through Dalamud notifications for each newly seen revision.
/// User-added repositories are refreshed during the same check.
/// </summary>
internal sealed class DailyCatalogUpdateService : IDisposable
{
    private static readonly TimeSpan InitialDelay = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan AutomaticCheckCadence = TimeSpan.FromHours(1);

    private readonly Configuration configuration;
    private readonly MarketplaceCatalogService catalog;
    private readonly CatalogUpdateCoordinator updates;
    private readonly INotificationManager notifications;
    private readonly CancellationTokenSource cts = new();
    private readonly Task worker;
    private int running;

    public DailyCatalogUpdateService(
        Configuration configuration,
        MarketplaceCatalogService catalog,
        CatalogUpdateCoordinator updates,
        INotificationManager notifications)
    {
        this.configuration = configuration;
        this.catalog = catalog;
        this.updates = updates;
        this.notifications = notifications;
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
        var last = configuration.LastDefinitionsUpdateCheckUtc ?? configuration.LastDailyUpdateCheckUtc;
        return last is null || DateTimeOffset.UtcNow - last.Value >= AutomaticCheckCadence;
    }

    private async Task CheckNowAsync(CancellationToken cancellationToken)
    {
        if (updates.IsRefreshing || Interlocked.Exchange(ref running, 1) != 0)
            return;

        try
        {
            await updates.CheckDefinitionsForUpdatesAsync(cancellationToken).ConfigureAwait(false);
            configuration.LastDefinitionsUpdateCheckUtc = DateTimeOffset.UtcNow;
            NotifyIfNewDefinitionsRevision();
            configuration.Save();
            Plugin.Log.Information(
                "Omega Definitions check completed; mode={Mode}; cachedSources={SourceCount}; definitionsUpdateAvailable={DefinitionsUpdateAvailable}; availableRevision={AvailableRevision}",
                updates.ModeLabel,
                catalog.CachedRepositoryCount,
                updates.DefinitionsUpdateAvailable,
                updates.AvailableDefinitionsRevision);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega automatic Definitions check failed; cached Definitions remain active.");
        }
        finally
        {
            Interlocked.Exchange(ref running, 0);
        }
    }

    private void NotifyIfNewDefinitionsRevision()
    {
        if (!updates.DefinitionsUpdateAvailable)
            return;

        var revision = string.IsNullOrWhiteSpace(updates.AvailableDefinitionsRevision)
            ? "pending"
            : updates.AvailableDefinitionsRevision.Trim();
        if (string.Equals(configuration.LastNotifiedDefinitionsRevision, revision, StringComparison.Ordinal))
            return;

        notifications.AddNotification(new Dalamud.Interface.ImGuiNotification.Notification
        {
            Title = "Omega Definitions update available",
            Content = revision == "pending"
                ? "New marketplace Definitions are ready. Open Omega > Updates to review and apply them."
                : $"Definitions {revision} are ready. Open Omega > Updates to review and apply them.",
            Type = Dalamud.Interface.ImGuiNotification.NotificationType.Info,
            InitialDuration = TimeSpan.FromSeconds(12),
            ExtensionDurationSinceLastInterest = TimeSpan.FromSeconds(6),
            Minimized = false,
        });

        configuration.LastNotifiedDefinitionsRevision = revision;
    }

    public void Dispose()
    {
        cts.Cancel();
        try { worker.Wait(TimeSpan.FromMilliseconds(250)); } catch { }
        cts.Dispose();
    }
}
