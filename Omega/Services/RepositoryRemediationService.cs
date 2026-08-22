using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed record RepositoryRemediationPluginPlan(
    string InternalName,
    string Name,
    string FromUrl,
    MarketplacePlugin Target,
    bool SameVersion,
    IReadOnlyList<MarketplacePermissionConcern> PermissionConcerns);

internal sealed record RepositoryRemediationPlan(
    string SourceUrl,
    string SourceName,
    IReadOnlyList<RepositoryRemediationPluginPlan> Moves,
    IReadOnlyList<string> BlockedPlugins)
{
    public bool CanRemediate => Moves.Count > 0;
}

internal sealed record RepositoryRemediationResult(
    int Moved,
    int Failed,
    int Blocked,
    int RepositoriesDisabled,
    string Message);

/// <summary>
/// Moves installed plugins away from repositories with concrete package-divergence evidence.
/// "Risky" is intentionally independent from unrecognized-source identity. Preferred destinations
/// must be recognized stable providers and must not themselves carry cross-source divergence evidence.
///
/// Newer target versions use the normal Dalamud update lifecycle. Equal-version source moves use the
/// same Dalamud UpdateSinglePluginAsync lifecycle but explicitly allow an equal version so the selected
/// preferred package actually replaces the installed package. No plugin DLLs are copied by Omega.
///
/// Once every installed plugin has left a risky repository, Omega disables that repository. If Omega
/// originally created the repository row, it is removed on a later clean launch after usage is checked
/// again. User-owned rows are never silently deleted.
/// </summary>
internal sealed class RepositoryRemediationService : IDisposable
{
    private const string DivergenceRule = "artifact.cross-source-hash-mismatch";
    private static readonly TimeSpan CleanupDelay = TimeSpan.FromSeconds(12);

    private readonly Configuration configuration;
    private readonly MarketplaceCatalogService catalog;
    private readonly PluginInstallCoordinator installer;
    private readonly DalamudRepositoryBridge repositories;
    private readonly CancellationTokenSource cts = new();
    private readonly Task cleanupWorker;

    public RepositoryRemediationService(
        Configuration configuration,
        MarketplaceCatalogService catalog,
        PluginInstallCoordinator installer,
        DalamudRepositoryBridge repositories)
    {
        this.configuration = configuration;
        this.catalog = catalog;
        this.installer = installer;
        this.repositories = repositories;
        cleanupWorker = CleanupPreviousRunAsync(cts.Token);
    }

    public IReadOnlyList<RepositoryRemediationPlan> BuildPlans(IEnumerable<string> sourceUrls)
    {
        var installed = Plugin.PluginInterface.InstalledPlugins
            .Where(x => x is not null && !string.IsNullOrWhiteSpace(x.InternalName))
            .ToArray();
        var currentApi = Plugin.PluginInterface.Manifest.DalamudApiLevel;
        var dalamudVersion = Plugin.PluginInterface.GetDalamudVersion().Version;

        return sourceUrls
            .Select(NormalizeUrl)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(IsRiskyRepository)
            .Select(url => BuildPlan(url, installed, currentApi, dalamudVersion))
            .Where(plan => plan.Moves.Count > 0 || plan.BlockedPlugins.Count > 0)
            .ToArray();
    }

    public async Task<RepositoryRemediationResult> RemediateAsync(
        IEnumerable<string> sourceUrls,
        CancellationToken cancellationToken = default)
    {
        var plans = BuildPlans(sourceUrls);
        var moved = 0;
        var failed = 0;
        var blocked = plans.Sum(x => x.BlockedPlugins.Count);
        var disabled = 0;

        foreach (var plan in plans)
        {
            foreach (var move in plan.Moves)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (move.PermissionConcerns.Count > 0)
                {
                    blocked++;
                    continue;
                }

                var targetSource = FindOrCreateSource(move.Target);
                if (!targetSource.Enabled)
                {
                    targetSource.Enabled = true;
                    configuration.Save();
                    catalog.LoadCached(configuration.Repositories);
                }
                var result = await installer.MigrateRepositoryAsync(
                        move.Target,
                        targetSource,
                        configuration.PreferTestingBuilds,
                        cancellationToken)
                    .ConfigureAwait(false);

                if (!result.Success || !InstalledFrom(move.InternalName, move.Target))
                {
                    failed++;
                    Plugin.Log.Warning(
                        "Repository remediation could not verify {Plugin} moved from {OldRepository} to {NewRepository}: {Message}",
                        move.InternalName,
                        move.FromUrl,
                        move.Target.SourceUrl,
                        result.Message);
                    continue;
                }

                moved++;
            }

            if (repositories.GetInstalledPluginUsageByRepository()
                .TryGetValue(NormalizeUrl(plan.SourceUrl), out var usage) && usage.InstalledCount > 0)
                continue;

            var oldSource = FindConfiguredSource(plan.SourceUrl);
            var state = repositories.GetState(plan.SourceUrl);
            if (!state.Present)
                continue;

            RepositoryBridgeResult disableResult;
            if (oldSource?.DalamudManagedByOmega == true)
                disableResult = await repositories.SetManagedEnabledAsync(plan.SourceUrl, false, cancellationToken).ConfigureAwait(false);
            else
                disableResult = await repositories.SetEnabledForReviewedMigrationAsync(plan.SourceUrl, false, cancellationToken).ConfigureAwait(false);

            if (!disableResult.Success)
            {
                failed++;
                continue;
            }

            disabled++;
            if (oldSource is not null)
            {
                oldSource.Enabled = false;
                oldSource.IntegrateWithDalamud = false;
            }

            var normalized = NormalizeUrl(plan.SourceUrl);
            var pending = configuration.RepositoryRemediationCleanup.FirstOrDefault(x =>
                NormalizeUrl(x.SourceUrl).Equals(normalized, StringComparison.OrdinalIgnoreCase));
            if (pending is null)
            {
                configuration.RepositoryRemediationCleanup.Add(new RepositoryRemediationState
                {
                    SourceUrl = normalized,
                    DisabledAtUtc = DateTimeOffset.UtcNow,
                    OmegaManaged = oldSource?.DalamudManagedByOmega == true,
                });
            }
            else
            {
                pending.DisabledAtUtc = DateTimeOffset.UtcNow;
                pending.OmegaManaged = oldSource?.DalamudManagedByOmega == true;
            }
            configuration.Save();
            catalog.LoadCached(configuration.Repositories);
        }

        var message = moved == 0 && failed == 0 && blocked == 0
            ? "No installed plugins could be moved to a preferred source."
            : $"Moved {moved} plugin{(moved == 1 ? string.Empty : "s")} to preferred sources" +
              (disabled > 0 ? $" and disabled {disabled} old repositor{(disabled == 1 ? "y" : "ies")}" : string.Empty) +
              (blocked > 0 ? $". {blocked} need your permission settings reviewed" : string.Empty) +
              (failed > 0 ? $". {failed} could not be moved" : string.Empty) + ".";
        return new RepositoryRemediationResult(moved, failed, blocked, disabled, message);
    }

    private RepositoryRemediationPlan BuildPlan(
        string sourceUrl,
        IReadOnlyList<IExposedPlugin> installed,
        int currentApi,
        Version dalamudVersion)
    {
        var normalized = NormalizeUrl(sourceUrl);
        var sourceName = configuration.Repositories.FirstOrDefault(x => SameUrl(x.Url, normalized))?.Name
            ?? catalog.Variants.FirstOrDefault(x => SameUrl(x.SourceUrl, normalized))?.SourceName
            ?? "Repository";
        var moves = new List<RepositoryRemediationPluginPlan>();
        var blocked = new List<string>();

        foreach (var local in installed.Where(x => SameUrl(x.Manifest.InstalledFromUrl, normalized)))
        {
            if (local.IsDev || local.Version is null)
            {
                blocked.Add(local.Name);
                continue;
            }

            var target = catalog.Variants
                .Where(x => x.InternalName.Equals(local.InternalName, StringComparison.OrdinalIgnoreCase))
                .Where(x => !SameUrl(x.SourceUrl, normalized))
                .Where(x => RepositoryProviderRules.IsStableProvider(x.SourceName, x.SourceUrl, x.SourceIsOfficial))
                .Where(x => !IsRiskyVariant(x))
                .Where(x => x.MinimumDalamudVersion is null || x.MinimumDalamudVersion <= dalamudVersion)
                .Where(x => x.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out _))
                .Select(x => new { Plugin = x, Version = EffectiveTargetVersion(x) })
                .Where(x => x.Version >= local.Version)
                .OrderBy(x => RepositoryProviderRules.SecurityBaselinePriority(
                    x.Plugin.SourceName, x.Plugin.SourceUrl, x.Plugin.SourceIsOfficial))
                .ThenByDescending(x => x.Version)
                .ThenBy(x => x.Plugin.SourceName, StringComparer.OrdinalIgnoreCase)
                .Select(x => x.Plugin)
                .FirstOrDefault();

            if (target is null)
            {
                blocked.Add(local.Name);
                continue;
            }

            var concerns = MarketplacePermissionRules.FindBlockedCapabilities(target, configuration);
            moves.Add(new RepositoryRemediationPluginPlan(
                local.InternalName,
                local.Name,
                normalized,
                target,
                EffectiveTargetVersion(target) == local.Version,
                concerns));
        }

        return new RepositoryRemediationPlan(normalized, sourceName, moves, blocked);
    }

    private async Task CleanupPreviousRunAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(CleanupDelay, cancellationToken).ConfigureAwait(false);
            if (configuration.RepositoryRemediationCleanup.Count == 0)
                return;

            var changed = false;
            foreach (var pending in configuration.RepositoryRemediationCleanup.ToArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var normalized = NormalizeUrl(pending.SourceUrl);
                var usage = repositories.GetInstalledPluginUsageByRepository();
                if (usage.TryGetValue(normalized, out var inUse) && inUse.InstalledCount > 0)
                    continue;

                var state = repositories.GetState(normalized);
                if (!state.Present)
                {
                    configuration.RepositoryRemediationCleanup.Remove(pending);
                    changed = true;
                    continue;
                }
                if (state.Enabled)
                    continue;

                if (!pending.OmegaManaged)
                {
                    // The user created this row. Leaving it disabled is intentional; only the user
                    // gets to decide whether their own repository configuration should be deleted.
                    configuration.RepositoryRemediationCleanup.Remove(pending);
                    changed = true;
                    continue;
                }

                var removed = await repositories.RemoveIfUnusedAsync(normalized, cancellationToken).ConfigureAwait(false);
                if (!removed.Success)
                    continue;

                configuration.RepositoryRemediationCleanup.Remove(pending);
                var source = FindConfiguredSource(normalized);
                if (source is not null)
                {
                    source.IntegrateWithDalamud = false;
                    source.DalamudManagedByOmega = false;
                }
                changed = true;
            }

            if (changed)
                configuration.Save();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not finish deferred risky-repository cleanup; the disabled repository was retained.");
        }
    }

    private RepositorySource FindOrCreateSource(MarketplacePlugin target)
    {
        var existing = FindConfiguredSource(target.SourceUrl);
        if (existing is not null)
            return existing;

        var source = new RepositorySource
        {
            Name = string.IsNullOrWhiteSpace(target.SourceName) ? "Repository" : target.SourceName,
            Url = target.SourceUrl,
            Enabled = true,
            IsOfficial = target.SourceIsOfficial,
            IsExperimental = !target.SourceIsOfficial,
            IntegrateWithDalamud = !target.SourceIsOfficial,
        };
        configuration.Repositories.Add(source);
        configuration.Save();
        return source;
    }

    private RepositorySource? FindConfiguredSource(string sourceUrl)
    {
        var normalized = NormalizeUrl(sourceUrl);
        return configuration.Repositories.FirstOrDefault(x =>
            NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsRiskyRepository(string sourceUrl)
        => catalog.Variants.Any(x => SameUrl(x.SourceUrl, sourceUrl) && IsRiskyVariant(x));

    private static bool IsRiskyVariant(MarketplacePlugin plugin)
        => plugin.SecurityFindings.Any(x => x.RuleId.Equals(DivergenceRule, StringComparison.OrdinalIgnoreCase));

    private Version EffectiveTargetVersion(MarketplacePlugin plugin)
    {
        if (plugin.HasCurrentApiBuild(
                Plugin.PluginInterface.Manifest.DalamudApiLevel,
                configuration.PreferTestingBuilds,
                out var testing) && testing)
            return plugin.TestingAssemblyVersion ?? plugin.AssemblyVersion;
        return plugin.AssemblyVersion;
    }

    private static bool InstalledFrom(string internalName, MarketplacePlugin target)
        => Plugin.PluginInterface.InstalledPlugins.Any(x =>
            x.InternalName.Equals(internalName, StringComparison.OrdinalIgnoreCase) &&
            PluginUpdateRules.IsSamePublishingSource(
                x.Manifest.InstalledFromUrl,
                target.SourceUrl,
                target.SourceIsOfficial));

    private static bool SameUrl(string? left, string? right)
        => NormalizeUrl(left).Equals(NormalizeUrl(right), StringComparison.OrdinalIgnoreCase);

    private static string NormalizeUrl(string? value)
        => (value ?? string.Empty).Trim().TrimEnd('/');

    public void Dispose()
    {
        cts.Cancel();
        cts.Dispose();
    }
}
