namespace Dalagab.Omega;

/// <summary>
/// Executes an already-resolved immutable package plan. Resolution remains pure and separate;
/// this coordinator only prepares sources, revalidates the frozen snapshot, executes leaf-first,
/// records local dependency ownership, and performs conservative rollback of newly auto-installed
/// dependencies when a later step fails.
/// </summary>
internal sealed class PluginInstallTransactionCoordinator
{
    private readonly MarketplaceCatalogService catalog;
    private readonly PluginInstallCoordinator lifecycle;
    private readonly PluginLibraryLedger ledger;

    public PluginInstallTransactionCoordinator(
        MarketplaceCatalogService catalog,
        PluginInstallCoordinator lifecycle,
        PluginLibraryLedger ledger)
    {
        this.catalog = catalog;
        this.lifecycle = lifecycle;
        this.ledger = ledger;
    }

    public async Task<PluginInstallTransactionResult> ExecuteAsync(
        PluginInstallPlan plan,
        Func<MarketplacePlugin, RepositorySource?> resolveSource,
        bool allowTesting,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(resolveSource);

        if (!plan.IsValid || plan.Conflicts.Count > 0)
            return Fail(PluginInstallTransactionOutcome.InvalidPlan, "The dependency plan is not valid and was not executed.");

        if (!plan.MatchesRevisions(catalog.CatalogRevision, catalog.DependencyGraphRevision))
            return Fail(PluginInstallTransactionOutcome.StalePlan, "Dependency data changed. Resolve the transaction again before installing anything.");

        if (!TryRevalidateSelectedVariants(plan, allowTesting, out var validationMessage))
            return Fail(PluginInstallTransactionOutcome.StalePlan, validationMessage);

        var preexisting = SnapshotInstalled();
        if (!TryRevalidateInstalledState(plan, preexisting, out validationMessage))
            return Fail(PluginInstallTransactionOutcome.StalePlan, validationMessage);

        // Prepare every source before the first plugin lifecycle mutation. This may add/enable
        // reviewed repositories, but it never installs or updates a plugin.
        foreach (var operation in plan.Operations.Where(x => x.Mutates)
                     .OrderBy(x => x.ExecutionOrder))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var selected = catalog.HydrateVariant(operation.SelectedVariant);
            var source = resolveSource(selected);
            var error = await lifecycle.PrepareRepositoryAsync(selected, source, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(error))
            {
                return Fail(
                    PluginInstallTransactionOutcome.SourcePreparationFailed,
                    $"Could not prepare {selected.SourceName} for {selected.Name}: {error}");
            }
        }

        // Repository preparation can take time. Revalidate the immutable plan once more immediately
        // before mutation so a newly-published Definitions/dependency graph cannot be executed stale.
        if (!plan.MatchesRevisions(catalog.CatalogRevision, catalog.DependencyGraphRevision) ||
            !TryRevalidateSelectedVariants(plan, allowTesting, out validationMessage))
        {
            return Fail(PluginInstallTransactionOutcome.StalePlan,
                string.IsNullOrWhiteSpace(validationMessage)
                    ? "Dependency data changed while repositories were being prepared. Resolve again."
                    : validationMessage);
        }

        var beforeExecution = SnapshotInstalled();
        if (!SameInstalledSnapshot(preexisting, beforeExecution) ||
            !TryRevalidateInstalledState(plan, beforeExecution, out validationMessage))
        {
            return Fail(PluginInstallTransactionOutcome.StalePlan,
                string.IsNullOrWhiteSpace(validationMessage)
                    ? "Installed plugin state changed while the transaction was being prepared. Resolve again."
                    : validationMessage);
        }

        var steps = new List<PluginInstallTransactionStepResult>();
        var newlyInstalledDependencies = new List<PluginInstallOperation>();
        var roots = plan.RootRequests.Select(x => x.InternalName)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var primaryRoot = roots.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).FirstOrDefault() ?? string.Empty;

        try
        {
            foreach (var operation in plan.Operations.OrderBy(x => x.ExecutionOrder))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!operation.Mutates)
                {
                    steps.Add(new PluginInstallTransactionStepResult(
                        operation.InternalName, operation.Action, true,
                        $"Kept {operation.InternalName} v{operation.TargetVersion}."));
                    TrackOwnership(operation, preexisting, primaryRoot, wasInstalledNow: false);
                    continue;
                }

                var selected = catalog.HydrateVariant(operation.SelectedVariant);
                var source = resolveSource(selected);
                var reserveDependencyOwnership = operation.Action == PluginInstallAction.Install &&
                                                 operation.Reason != PluginInstallReason.Requested &&
                                                 !preexisting.ContainsKey(operation.InternalName);
                // Reserve dependency ownership before Dalamud mutates its installed-plugin list.
                // ActivePluginsChanged/UI observation can otherwise see the new plugin first and
                // conservatively classify it as a manual external install.
                if (reserveDependencyOwnership)
                {
                    ledger.MarkDependencyInstalled(operation.InternalName, primaryRoot);
                    newlyInstalledDependencies.Add(operation);
                }

                var step = await ExecuteOperationAsync(operation, selected, source, allowTesting, cancellationToken)
                    .ConfigureAwait(false);
                steps.Add(step);
                if (!step.Success)
                {
                    var rollback = await RollbackAsync(
                        newlyInstalledDependencies,
                        preexisting.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase),
                        cancellationToken).ConfigureAwait(false);
                    return new PluginInstallTransactionResult(
                        PluginInstallTransactionOutcome.OperationFailed,
                        $"Dependency transaction stopped at {operation.InternalName}. {step.Message}",
                        steps,
                        rollback,
                        FindDependencyOwnedOrphans());
                }

                var wasInstalledNow = operation.Action == PluginInstallAction.Install &&
                                      !preexisting.ContainsKey(operation.InternalName);
                if (wasInstalledNow && operation.Reason != PluginInstallReason.Requested && !reserveDependencyOwnership)
                    newlyInstalledDependencies.Add(operation);
                TrackOwnership(operation, preexisting, primaryRoot, wasInstalledNow);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            var rollback = await RollbackAsync(
                newlyInstalledDependencies,
                preexisting.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase),
                CancellationToken.None).ConfigureAwait(false);
            return new PluginInstallTransactionResult(
                PluginInstallTransactionOutcome.Cancelled,
                "Dependency transaction was cancelled.",
                steps,
                rollback,
                FindDependencyOwnedOrphans());
        }

        var dependencyNames = plan.Operations
            .Where(x => x.Reason != PluginInstallReason.Requested)
            .Select(x => x.InternalName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        foreach (var root in roots)
            ledger.ReconcileRootDependencies(root, dependencyNames);

        var changes = plan.ChangeCount;
        return new PluginInstallTransactionResult(
            PluginInstallTransactionOutcome.Succeeded,
            changes == 1
                ? "Completed 1 package change."
                : $"Completed {changes} package changes.",
            steps,
            [],
            FindDependencyOwnedOrphans());
    }

    public IReadOnlyList<string> FindDependencyOwnedOrphans()
    {
        var installed = SnapshotInstalled();
        return ledger.GetDependencyOwnedOrphans(installed.Keys)
            .Where(name => !HasInstalledRequiredDependent(name, installed))
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public async Task<PluginDependencyAutoremoveResult> RemoveUnusedDependenciesAsync(
        IEnumerable<string> internalNames,
        CancellationToken cancellationToken = default)
    {
        var requested = internalNames
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var removed = 0;
        var skipped = new List<string>();
        var messages = new List<string>();

        foreach (var internalName in requested)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ownership = ledger.GetOwnership(internalName);
            var installed = SnapshotInstalled();
            if (!ownership.IsOrphan || HasInstalledRequiredDependent(internalName, installed))
            {
                skipped.Add(internalName);
                messages.Add($"Kept {internalName}: it is manual or still required by an installed plugin.");
                continue;
            }

            var result = await lifecycle.UninstallAsync(internalName, cancellationToken).ConfigureAwait(false);
            if (result.Outcome == UninstallOutcome.Uninstalled || result.Outcome == UninstallOutcome.NotInstalled)
            {
                removed++;
                ledger.ForgetAutoDependency(internalName);
                messages.Add(result.Message);
            }
            else
            {
                skipped.Add(internalName);
                messages.Add(result.Message);
            }
        }

        return new PluginDependencyAutoremoveResult(requested.Length, removed, skipped, messages);
    }

    private async Task<PluginInstallTransactionStepResult> ExecuteOperationAsync(
        PluginInstallOperation operation,
        MarketplacePlugin selected,
        RepositorySource? source,
        bool allowTesting,
        CancellationToken cancellationToken)
    {
        switch (operation.Action)
        {
            case PluginInstallAction.Install:
            {
                var result = await lifecycle.InstallAsync(selected, source, allowTesting, cancellationToken).ConfigureAwait(false);
                var ok = result.Outcome is InstallOutcome.Installed or InstallOutcome.AlreadyInstalled;
                return new PluginInstallTransactionStepResult(operation.InternalName, operation.Action, ok, result.Message);
            }
            case PluginInstallAction.Update:
            {
                var result = await lifecycle.UpdateAsync(selected, source, allowTesting, cancellationToken).ConfigureAwait(false);
                return new PluginInstallTransactionStepResult(operation.InternalName, operation.Action, result.Success, result.Message);
            }
            case PluginInstallAction.MigrateSource:
            {
                var result = await lifecycle.MigrateRepositoryAsync(selected, source, allowTesting, cancellationToken).ConfigureAwait(false);
                return new PluginInstallTransactionStepResult(operation.InternalName, operation.Action, result.Success, result.Message);
            }
            default:
                return new PluginInstallTransactionStepResult(
                    operation.InternalName, operation.Action, true,
                    $"Kept {operation.InternalName} v{operation.TargetVersion}.");
        }
    }

    private void TrackOwnership(
        PluginInstallOperation operation,
        IReadOnlyDictionary<string, PluginInstalledState> preexisting,
        string primaryRoot,
        bool wasInstalledNow)
    {
        if (operation.Reason == PluginInstallReason.Requested)
        {
            if (wasInstalledNow)
                ledger.MarkManualInstalled(operation.InternalName);
            else
                ledger.PromoteToManual(operation.InternalName);
            return;
        }

        if (preexisting.ContainsKey(operation.InternalName))
        {
            // Do not change ownership of a pre-existing dependency until the complete transaction
            // succeeds. ReconcileRootDependencies commits those edges atomically at the end, so a
            // failed root update cannot leave a phantom requester behind.
            return;
        }

        ledger.MarkDependencyInstalled(operation.InternalName, primaryRoot);
    }

    private async Task<IReadOnlyList<string>> RollbackAsync(
        IReadOnlyList<PluginInstallOperation> newlyInstalledDependencies,
        IReadOnlySet<string> preexisting,
        CancellationToken cancellationToken)
    {
        var messages = new List<string>();
        var installed = SnapshotInstalled();
        foreach (var operation in newlyInstalledDependencies
                     .OrderByDescending(x => x.ExecutionOrder))
        {
            if (preexisting.Contains(operation.InternalName) ||
                operation.Reason == PluginInstallReason.Requested)
                continue;
            var ownership = ledger.GetOwnership(operation.InternalName);
            if (!ownership.IsDependencyOwned)
                continue;
            if (!installed.ContainsKey(operation.InternalName))
            {
                ledger.ForgetAutoDependency(operation.InternalName);
                messages.Add($"Cleared pending dependency ownership for {operation.InternalName}; no package was installed.");
                continue;
            }
            if (HasInstalledRequiredDependent(operation.InternalName, installed))
            {
                messages.Add($"Kept {operation.InternalName}: an installed plugin still requires it.");
                continue;
            }

            var result = await lifecycle.UninstallAsync(operation.InternalName, cancellationToken).ConfigureAwait(false);
            if (result.Outcome is UninstallOutcome.Uninstalled or UninstallOutcome.NotInstalled)
            {
                ledger.ForgetAutoDependency(operation.InternalName);
                installed.Remove(operation.InternalName);
                messages.Add($"Rolled back {operation.InternalName}. {result.Message}");
            }
            else
            {
                messages.Add($"Could not roll back {operation.InternalName}. {result.Message}");
            }
        }
        return messages;
    }

    private bool HasInstalledRequiredDependent(
        string providerInternalName,
        IReadOnlyDictionary<string, PluginInstalledState> installed,
        IEnumerable<string>? ignoreConsumers = null)
    {
        var ignored = (ignoreConsumers ?? []).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return catalog.GetDependentsForProvider(providerInternalName)
            .Where(x => x.Relationship == PluginDependencyRelationship.Required)
            .Any(x =>
            {
                if (ignored.Contains(x.ConsumerInternalName) ||
                    !installed.TryGetValue(x.ConsumerInternalName, out var consumer))
                    return false;
                if (string.IsNullOrWhiteSpace(x.ConsumerVersion))
                    return true;
                // Unknown version text is treated conservatively as still required; a well-formed
                // normalized graph normally carries an exact consumer version.
                return !Version.TryParse(x.ConsumerVersion, out var expected) ||
                       expected.CompareTo(consumer.Version) == 0;
            });
    }

    private bool TryRevalidateSelectedVariants(
        PluginInstallPlan plan,
        bool allowTesting,
        out string message)
    {
        var currentApi = Plugin.PluginInterface.Manifest.DalamudApiLevel;
        var currentDalamud = Plugin.PluginInterface.GetDalamudVersion().Version;
        foreach (var operation in plan.Operations.Where(x => x.Mutates || x.SelectedVariantId > 0))
        {
            var candidates = catalog.GetVariants(operation.InternalName);
            var selected = candidates.FirstOrDefault(x =>
                operation.SelectedVariantId > 0
                    ? x.CatalogVariantId == operation.SelectedVariantId
                    : SameUrl(x.SourceUrl, operation.SelectedVariant.SourceUrl) &&
                      x.AssemblyVersionText.Equals(operation.SelectedVariant.AssemblyVersionText, StringComparison.OrdinalIgnoreCase));
            if (selected is null)
            {
                message = $"The selected catalog variant for {operation.InternalName} no longer exists. Resolve again.";
                return false;
            }
            if (selected.MinimumDalamudVersion is not null && selected.MinimumDalamudVersion > currentDalamud ||
                !selected.HasCurrentApiBuild(currentApi, allowTesting, out var useTesting))
            {
                message = $"{operation.InternalName} is no longer compatible with the active Dalamud/API selection.";
                return false;
            }
            var target = useTesting ? selected.TestingAssemblyVersion ?? selected.AssemblyVersion : selected.AssemblyVersion;
            if (target.CompareTo(operation.TargetVersion) != 0)
            {
                message = $"The selected version for {operation.InternalName} changed from v{operation.TargetVersion} to v{target}. Resolve again.";
                return false;
            }
            if (!PluginVersionConstraint.TryParse(operation.EffectiveVersionConstraint, out var constraint, out _) ||
                !constraint.Allows(target))
            {
                message = $"{operation.InternalName} no longer satisfies the frozen dependency constraint {operation.EffectiveVersionConstraint}.";
                return false;
            }
        }
        message = string.Empty;
        return true;
    }

    private static bool TryRevalidateInstalledState(
        PluginInstallPlan plan,
        IReadOnlyDictionary<string, PluginInstalledState> installed,
        out string message)
    {
        foreach (var operation in plan.Operations)
        {
            installed.TryGetValue(operation.InternalName, out var current);
            switch (operation.Action)
            {
                case PluginInstallAction.Install when current is not null:
                    message = $"{operation.InternalName} became installed after the plan was created. Resolve again.";
                    return false;
                case PluginInstallAction.Update:
                case PluginInstallAction.MigrateSource:
                    if (current is null || operation.InstalledVersion is null || current.Version.CompareTo(operation.InstalledVersion) != 0)
                    {
                        message = $"Installed state for {operation.InternalName} changed after the plan was created. Resolve again.";
                        return false;
                    }
                    break;
                case PluginInstallAction.Keep when current is null:
                    message = $"Required provider {operation.InternalName} is no longer installed. Resolve again.";
                    return false;
            }
        }
        message = string.Empty;
        return true;
    }

    private static Dictionary<string, PluginInstalledState> SnapshotInstalled()
        => Plugin.PluginInterface.InstalledPlugins
            .Where(x => x is not null &&
                        !string.IsNullOrWhiteSpace(x.InternalName) &&
                        !x.Manifest.ScheduledForDeletion &&
                        x.Version is not null)
            .GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                x => x.Key,
                x =>
                {
                    var item = x.OrderByDescending(p => p.IsLoaded).First();
                    return new PluginInstalledState(
                        item.InternalName,
                        item.Version!,
                        item.Manifest.InstalledFromUrl ?? string.Empty,
                        item.IsDev);
                },
                StringComparer.OrdinalIgnoreCase);

    private static bool SameInstalledSnapshot(
        IReadOnlyDictionary<string, PluginInstalledState> left,
        IReadOnlyDictionary<string, PluginInstalledState> right)
    {
        if (left.Count != right.Count)
            return false;
        foreach (var pair in left)
        {
            if (!right.TryGetValue(pair.Key, out var other) ||
                pair.Value.Version.CompareTo(other.Version) != 0 ||
                !SameUrl(pair.Value.SourceUrl, other.SourceUrl))
                return false;
        }
        return true;
    }

    private static bool SameUrl(string? left, string? right)
        => (left ?? string.Empty).Trim().TrimEnd('/').Equals(
            (right ?? string.Empty).Trim().TrimEnd('/'),
            StringComparison.OrdinalIgnoreCase);

    private static PluginInstallTransactionResult Fail(PluginInstallTransactionOutcome outcome, string message)
        => new(outcome, message, [], [], []);
}
