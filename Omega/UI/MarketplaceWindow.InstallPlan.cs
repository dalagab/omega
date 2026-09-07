using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private const string InstallPlanPopupId = "Install dependency plan###DalagabOmegaInstallPlan";

    private void ContinueInstallSelection(
        MarketplacePlugin selected,
        int currentApi,
        Version currentDalamudVersion)
    {
        pendingInstallPlanFromUpdate = false;
        var plan = ResolveInstallPlan(selected, currentApi, currentDalamudVersion);
        if (!plan.HasDependencyClosure && plan.Conflicts.Count == 0)
        {
            pendingInstallPlan = null;
            pendingInstallPlanRootSourceUrl = string.Empty;
            pendingInstallExplicitDependencies.Clear();
            pendingInstallTransactionReviewSources.Clear();
            OpenInstallRepositoryRiskReview(selected);
            return;
        }

        pendingInstallPlan = plan;
        pendingInstallPlanRootSourceUrl = selected.SourceUrl;
        pendingInstallTransactionReviewSources.Clear();
        installPopupOpen = false;
        installPlanPopupOpen = true;
        requestInstallPlanPopup = true;
        ImGui.CloseCurrentPopup();
    }

    private bool TryOpenDependencyUpdatePlan(
        MarketplacePlugin selected,
        int currentApi,
        Version currentDalamudVersion)
    {
        var plan = ResolveInstallPlan(selected, currentApi, currentDalamudVersion);
        if (!plan.HasDependencyClosure && plan.Conflicts.Count == 0)
            return false;

        pendingInstall = selected;
        pendingInstallPlan = plan;
        pendingInstallPlanRootSourceUrl = selected.SourceUrl;
        pendingInstallPlanFromUpdate = true;
        pendingInstallExplicitDependencies.Clear();
        pendingInstallTransactionReviewSources.Clear();
        updateMigrationPopupOpen = false;
        installPlanPopupOpen = true;
        requestInstallPlanPopup = true;
        ImGui.CloseCurrentPopup();
        return true;
    }

    private PluginInstallPlan ResolveInstallPlan(
        MarketplacePlugin root,
        int currentApi,
        Version currentDalamudVersion)
    {
        var identity = ResolveCatalogIdentity(root);
        var installed = Plugin.PluginInterface.InstalledPlugins
            .Where(x => !string.IsNullOrWhiteSpace(x.InternalName) && x.Version is not null)
            .GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group =>
                {
                    var item = group.OrderByDescending(x => x.IsLoaded).First();
                    return new PluginInstalledState(
                        item.InternalName,
                        item.Version!,
                        item.Manifest.InstalledFromUrl ?? string.Empty,
                        item.IsDev);
                },
                StringComparer.OrdinalIgnoreCase);

        var context = new PluginDependencyResolutionContext
        {
            RootVariant = root,
            RootCatalogPluginId = identity.PluginId,
            RootCatalogVariantId = identity.VariantId,
            CurrentApiLevel = currentApi,
            CurrentDalamudVersion = currentDalamudVersion,
            PreferTestingBuilds = configuration.PreferTestingBuilds,
            CatalogRevision = catalog.CatalogRevision,
            DependencyGraphRevision = catalog.DependencyGraphRevision,
            InstalledPlugins = installed,
            PreferredSourceUrls = selectedVariantSource,
            ExplicitDependencyInternalNames = pendingInstallExplicitDependencies,
            GetVariants = internalName => catalog.GetMainVariants(internalName, currentApi),
            GetDependenciesForVariant = catalog.GetDependenciesForVariant,
            GetDependenciesForPlugin = catalog.GetDependenciesForPlugin,
        };
        return new PluginDependencyResolver().Resolve(context);
    }

    private (long PluginId, long VariantId) ResolveCatalogIdentity(MarketplacePlugin plugin)
    {
        if (plugin.CatalogPluginId > 0 && plugin.CatalogVariantId > 0)
            return (plugin.CatalogPluginId, plugin.CatalogVariantId);

        var source = NormalizeUrl(plugin.SourceUrl);
        var sameVersion = catalog.GetPresentationVariants(plugin.InternalName)
            .Where(x => x.CatalogPluginId > 0 && x.CatalogVariantId > 0 &&
                        x.AssemblyVersionText.Equals(plugin.AssemblyVersionText, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var exact = sameVersion.FirstOrDefault(x =>
            source.Length > 0
                ? NormalizeUrl(x.SourceUrl).Equals(source, StringComparison.OrdinalIgnoreCase)
                : plugin.SourceIsOfficial && x.SourceIsOfficial);
        if (exact is not null)
            return (exact.CatalogPluginId, exact.CatalogVariantId);

        // A live overlay may expose only stable plugin identity. Keep that identity, but never
        // pretend a different repository variant is the selected consumer package. With no exact
        // variant id the resolver falls back to same-version plugin-level dependency rows.
        var stable = sameVersion.FirstOrDefault();
        return stable is null
            ? (plugin.CatalogPluginId, plugin.CatalogVariantId)
            : (stable.CatalogPluginId, 0);
    }

    private void DrawInstallPlanModal(int currentApi, Version currentDalamudVersion)
    {
        if (!installPlanPopupOpen || pendingInstall is null || pendingInstallPlan is null)
            return;

        var keepOpen = installPlanPopupOpen;
        ImGui.SetNextWindowSize(UiModalSize(760f, 660f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal(
                InstallPlanPopupId,
                ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoCollapse | ImGuiWindowFlags.NoResize))
        {
            installPlanPopupOpen = keepOpen;
            return;
        }

        var planVerb = pendingInstallPlanFromUpdate ? "Update" : "Install";
        if (DrawOmegaModalHeader($"{planVerb} {pendingInstall.Name}", "install-plan"))
        {
            ReturnFromInstallPlan();
            ImGui.EndPopup();
            return;
        }

        var plan = pendingInstallPlan.MarkStaleIfRevisionsChanged(catalog.CatalogRevision, catalog.DependencyGraphRevision);
        pendingInstallPlan = plan;

        var footerHeight = Ui(86f);
        ImGui.BeginChild("install-plan-body", new Vector2(0f, -footerHeight), false);

        if (plan.IsStale)
        {
            DrawInstallPlanNotice(
                new Vector4(0.95f, 0.64f, 0.20f, 1f),
                "Dependency data changed",
                "Omega will not execute a plan built from an older catalog/dependency revision. Re-resolve before continuing.");
        }

        if (plan.Conflicts.Count > 0)
            DrawInstallPlanConflicts(plan.Conflicts);

        DrawInstallPlanOperations(plan);
        DrawInstallPlanSuggestions(plan, currentApi, currentDalamudVersion);
        DrawInstallPlanRepositories(plan, currentApi);
        DrawInstallPlanSecurity(plan);

        ImGui.EndChild();
        ImGui.Separator();
        ImGui.Spacing();

        DrawInstallPlanFooter(plan, currentApi, currentDalamudVersion);

        installPlanPopupOpen = keepOpen && installPlanPopupOpen;
        ImGui.EndPopup();
    }

    private void DrawInstallPlanOperations(PluginInstallPlan plan)
    {
        ImGui.TextUnformatted("Transaction preview");
        ImGui.TextDisabled("Required dependencies are locked into the plan and ordered before the requested plugin.");
        ImGui.Spacing();

        if (ImGui.BeginTable(
                "install-plan-operations",
                4,
                ImGuiTableFlags.RowBg | ImGuiTableFlags.BordersInnerH | ImGuiTableFlags.SizingStretchProp))
        {
            ImGui.TableSetupColumn("", ImGuiTableColumnFlags.WidthFixed, Ui(26f));
            ImGui.TableSetupColumn("Plugin", ImGuiTableColumnFlags.WidthStretch, 2.2f);
            ImGui.TableSetupColumn("Action", ImGuiTableColumnFlags.WidthStretch, 1.1f);
            ImGui.TableSetupColumn("Reason", ImGuiTableColumnFlags.WidthStretch, 2.2f);

            foreach (var operation in plan.Operations.OrderBy(x => x.ExecutionOrder))
                DrawInstallPlanOperationRow(operation);

            ImGui.EndTable();
        }
    }

    private void DrawInstallPlanOperationRow(PluginInstallOperation operation)
    {
        var (marker, color, action) = operation.Action switch
        {
            PluginInstallAction.Keep => ("✓", new Vector4(0.34f, 0.82f, 0.56f, 1f), "Already installed"),
            PluginInstallAction.Update => ("↑", new Vector4(0.20f, 0.72f, 0.82f, 1f), "Will update"),
            PluginInstallAction.MigrateSource => ("↔", new Vector4(0.95f, 0.64f, 0.20f, 1f), "Will change source"),
            _ => ("↓", new Vector4(0.20f, 0.72f, 0.82f, 1f), "Will install"),
        };

        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        ImGui.TextColored(color, marker);

        ImGui.TableSetColumnIndex(1);
        ImGui.TextUnformatted(operation.SelectedVariant.Name);
        ImGui.TextDisabled(operation.InternalName);

        ImGui.TableSetColumnIndex(2);
        ImGui.TextColored(color, action);
        if (operation.InstalledVersion is not null && operation.Action == PluginInstallAction.Update)
            ImGui.TextDisabled($"{operation.InstalledVersion} → {operation.TargetVersion}");
        else
            ImGui.TextDisabled($"v{operation.TargetVersion}");

        ImGui.TableSetColumnIndex(3);
        var reason = operation.Reason switch
        {
            PluginInstallReason.Requested => "Requested",
            PluginInstallReason.DependencyVersionConstraint => "Dependency version constraint",
            PluginInstallReason.ExplicitRecommendedDependency => "Recommended · selected",
            PluginInstallReason.ExplicitOptionalDependency => "Optional · selected",
            _ => "Required dependency",
        };
        ImGui.TextUnformatted(reason);
        if (operation.RequiredBy.Count > 0)
            ImGui.TextDisabled($"Required by {string.Join(", ", operation.RequiredBy)}");
        if (!operation.EffectiveVersionConstraint.Equals("any", StringComparison.OrdinalIgnoreCase))
            ImGui.TextDisabled(operation.EffectiveVersionConstraint);
    }

    private void DrawInstallPlanConflicts(IReadOnlyList<PluginInstallConflict> conflicts)
    {
        DrawInstallPlanNotice(
            new Vector4(0.96f, 0.30f, 0.24f, 1f),
            conflicts.Count == 1 ? "Dependency conflict" : $"{conflicts.Count} dependency conflicts",
            "Omega cannot safely satisfy the complete required dependency graph, so no plugin mutation will be started.");
        foreach (var conflict in conflicts)
        {
            ImGui.Bullet();
            ImGui.SameLine();
            ImGui.TextWrapped(conflict.Message);
            if (conflict.Consumers.Count > 0)
                ImGui.TextDisabled($"Consumers: {string.Join(", ", conflict.Consumers)}");
        }
        ImGui.Spacing();
    }

    private void DrawInstallPlanSuggestions(
        PluginInstallPlan plan,
        int currentApi,
        Version currentDalamudVersion)
    {
        var requiredNames = plan.Operations
            .Where(x => x.Reason is PluginInstallReason.RequiredDependency or PluginInstallReason.DependencyVersionConstraint)
            .Select(x => x.InternalName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var suggestions = plan.Suggestions
            .Where(x => !requiredNames.Contains(x.ProviderInternalName))
            .Where(x => x.Relationship is PluginDependencyRelationship.Recommended or PluginDependencyRelationship.Optional or PluginDependencyRelationship.Observed)
            .ToArray();
        if (suggestions.Length == 0)
            return;

        ImGui.Spacing();
        ImGui.TextUnformatted("Additional relationships");
        ImGui.TextDisabled("Recommended and optional plugins are never added unless you select them. Observed relationships are informational only.");
        ImGui.Spacing();

        string? toggled = null;
        bool toggledOn = false;
        foreach (var suggestion in suggestions)
        {
            var label = suggestion.Relationship switch
            {
                PluginDependencyRelationship.Recommended => "Recommended",
                PluginDependencyRelationship.Optional => "Optional",
                _ => "Observed",
            };
            var selected = suggestion.Selected;
            var canSelect = suggestion.InstallEligible && (suggestion.Relationship is PluginDependencyRelationship.Recommended or PluginDependencyRelationship.Optional);
            if (!canSelect)
                ImGui.BeginDisabled();
            if (ImGui.Checkbox($"##plan-suggestion-{StableId(suggestion.ProviderInternalName)}-{suggestion.Relationship}", ref selected) && canSelect)
            {
                toggled = suggestion.ProviderInternalName;
                toggledOn = selected;
            }
            if (!canSelect)
                ImGui.EndDisabled();
            ImGui.SameLine(0f, Ui(8f));
            ImGui.TextUnformatted(suggestion.ProviderInternalName);
            ImGui.SameLine(0f, Ui(8f));
            ImGui.TextDisabled(label);
            if (!string.IsNullOrWhiteSpace(suggestion.VersionConstraint))
            {
                ImGui.SameLine(0f, Ui(8f));
                ImGui.TextDisabled(suggestion.VersionConstraint);
            }
            if (suggestion.SuggestedBy.Count > 0 && ImGui.IsItemHovered())
                ImGui.SetTooltip($"Suggested by {string.Join(", ", suggestion.SuggestedBy)}");
        }

        if (toggled is not null)
        {
            if (toggledOn)
                pendingInstallExplicitDependencies.Add(toggled);
            else
                pendingInstallExplicitDependencies.Remove(toggled);
            RebuildPendingInstallPlan(currentApi, currentDalamudVersion);
        }
    }

    private void DrawInstallPlanRepositories(PluginInstallPlan plan, int currentApi)
    {
        var changes = plan.Operations.Where(x => x.Mutates).ToArray();
        if (changes.Length == 0)
            return;

        ImGui.Spacing();
        ImGui.TextUnformatted("Repositories");
        ImGui.TextDisabled("All sources are prepared before the first plugin changes. Review requirements stay independent from dependency resolution.");
        ImGui.Spacing();

        var rendered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var operation in changes)
        {
            var plugin = catalog.HydrateVariant(operation.SelectedVariant);
            var sourceKey = NormalizeUrl(plugin.SourceUrl);
            if (plugin.SourceIsOfficial || sourceKey.Length == 0 || !rendered.Add(sourceKey))
                continue;

            var divergent = IsRepositoryArtifactDivergent(plugin.SourceUrl) || IsPluginPackageArtifactDivergent(plugin);
            var needsDivergence = divergent && !IsRepositoryRiskAcknowledged(plugin.SourceUrl);
            var unrecognized = RequiresUntrustedRepositoryAcknowledgement(plugin);
            var needsUnrecognized = unrecognized && !IsUntrustedRepositoryAcknowledged(plugin);
            var needsReview = needsDivergence || needsUnrecognized;
            var reviewed = !needsReview || pendingInstallTransactionReviewSources.Contains(sourceKey);
            var color = needsDivergence
                ? new Vector4(0.96f, 0.30f, 0.24f, 1f)
                : needsUnrecognized
                    ? new Vector4(0.95f, 0.64f, 0.20f, 1f)
                    : new Vector4(0.34f, 0.82f, 0.56f, 1f);
            var state = needsDivergence
                ? "Package divergence · review required"
                : needsUnrecognized
                    ? "Acknowledgement required"
                    : "Ready";

            ImGui.TextColored(color, "●");
            ImGui.SameLine(0f, Ui(6f));
            ImGui.TextUnformatted(plugin.SourceName);
            ImGui.SameLine(0f, Ui(8f));
            ImGui.TextDisabled($"{plugin.Name} · {state}");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(plugin.SourceUrl);

            if (needsReview)
            {
                ImGui.Indent(Ui(18f));
                var checkedValue = reviewed;
                var label = needsDivergence
                    ? "I reviewed this divergent source and want to use it for this transaction"
                    : "I acknowledge this unrecognized source for this transaction";
                if (ImGui.Checkbox($"{label}##plan-source-{StableId(sourceKey)}", ref checkedValue))
                {
                    if (checkedValue)
                        pendingInstallTransactionReviewSources.Add(sourceKey);
                    else
                        pendingInstallTransactionReviewSources.Remove(sourceKey);
                }
                ImGui.Unindent(Ui(18f));
            }
        }
    }

    private void DrawInstallPlanSecurity(PluginInstallPlan plan)
    {
        var changes = plan.Operations.Where(x => x.Mutates).ToArray();
        if (changes.Length == 0)
            return;

        ImGui.Spacing();
        ImGui.TextUnformatted("Security review");
        ImGui.TextDisabled("Security observations do not decide whether the dependency graph is structurally satisfiable.");
        ImGui.Spacing();
        foreach (var operation in changes)
        {
            var plugin = catalog.HydrateVariant(operation.SelectedVariant);
            var state = plugin.HasCompletedSecurityScan
                ? $"SigmaScope: {plugin.SecurityHighestSeverity} · score {plugin.SecurityRiskScore}"
                : string.IsNullOrWhiteSpace(plugin.SecurityStatus)
                    ? "No published Omega scan for this exact package"
                    : $"SigmaScope: {plugin.SecurityStatus}";
            ImGui.Bullet();
            ImGui.SameLine();
            ImGui.TextUnformatted(plugin.Name);
            ImGui.SameLine(0f, Ui(8f));
            ImGui.TextDisabled(state);
        }
    }

    private void DrawInstallPlanFooter(
        PluginInstallPlan plan,
        int currentApi,
        Version currentDalamudVersion)
    {
        var summary = $"{plan.ChangeCount} change{(plan.ChangeCount == 1 ? string.Empty : "s")}" +
                      $" · {plan.InstallCount} install{(plan.InstallCount == 1 ? string.Empty : "s")}" +
                      $" · {plan.UpdateCount} update{(plan.UpdateCount == 1 ? string.Empty : "s")}";
        if (plan.KeepCount > 0)
            summary += $" · {plan.KeepCount} kept";
        ImGui.TextDisabled(summary);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip($"Plan {plan.PlanId}\nCatalog {plan.CatalogRevision}\nDependencies {plan.DependencyGraphRevision}");

        var buttonY = ImGui.GetCursorPosY() + Ui(6f);
        ImGui.SetCursorPosY(buttonY);
        if (ImGui.Button("Back", Ui(100f, 34f)))
        {
            ReturnFromInstallPlan();
            return;
        }

        var buttonWidth = Ui(190f);
        var buttonX = ImGui.GetCursorPosX() + Math.Max(0f, ImGui.GetContentRegionAvail().X - buttonWidth);
        ImGui.SetCursorPos(new Vector2(buttonX, buttonY));

        if (plan.IsStale)
        {
            if (ImGui.Button("Re-resolve", new Vector2(buttonWidth, Ui(34f))))
                RebuildPendingInstallPlan(currentApi, currentDalamudVersion);
            return;
        }

        if (!plan.IsValid)
        {
            ImGui.BeginDisabled();
            ImGui.Button("Resolve conflicts", new Vector2(buttonWidth, Ui(34f)));
            ImGui.EndDisabled();
            return;
        }

        if (plan.ChangeCount == 0)
        {
            ImGui.BeginDisabled();
            ImGui.Button("Nothing to change", new Vector2(buttonWidth, Ui(34f)));
            ImGui.EndDisabled();
            return;
        }

        var sourceReviewsComplete = InstallPlanSourceReviewsComplete(plan);
        var busy = installTransactionTask is not null || installTask is not null || updateTask is not null;
        if (!sourceReviewsComplete || busy)
            ImGui.BeginDisabled();

        var rootOperation = plan.Operations.LastOrDefault(x => x.Reason == PluginInstallReason.Requested);
        var label = rootOperation?.Action is PluginInstallAction.Update or PluginInstallAction.MigrateSource
            ? $"Apply {plan.ChangeCount} change{(plan.ChangeCount == 1 ? string.Empty : "s")}"
            : $"Install {plan.ChangeCount} plugin{(plan.ChangeCount == 1 ? string.Empty : "s")}";
        if (ImGui.Button(label, new Vector2(buttonWidth, Ui(34f))) && sourceReviewsComplete && !busy)
            StartInstallTransaction(plan);

        if (!sourceReviewsComplete || busy)
            ImGui.EndDisabled();
        if (!sourceReviewsComplete && ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
            ImGui.SetTooltip("Review and acknowledge each orange/red repository before executing the transaction.");
    }

    private bool InstallPlanSourceReviewsComplete(PluginInstallPlan plan)
    {
        foreach (var operation in plan.Operations.Where(x => x.Mutates))
        {
            var plugin = catalog.HydrateVariant(operation.SelectedVariant);
            if (plugin.SourceIsOfficial)
                continue;
            var needsDivergence = (IsRepositoryArtifactDivergent(plugin.SourceUrl) || IsPluginPackageArtifactDivergent(plugin)) &&
                                  !IsRepositoryRiskAcknowledged(plugin.SourceUrl);
            var needsUnrecognized = RequiresUntrustedRepositoryAcknowledgement(plugin) &&
                                    !IsUntrustedRepositoryAcknowledged(plugin);
            if ((needsDivergence || needsUnrecognized) &&
                !pendingInstallTransactionReviewSources.Contains(NormalizeUrl(plugin.SourceUrl)))
                return false;
        }
        return true;
    }

    private void CommitInstallPlanSourceReviews(PluginInstallPlan plan)
    {
        foreach (var operation in plan.Operations.Where(x => x.Mutates))
        {
            var plugin = catalog.HydrateVariant(operation.SelectedVariant);
            var sourceKey = NormalizeUrl(plugin.SourceUrl);
            if (!pendingInstallTransactionReviewSources.Contains(sourceKey))
                continue;
            var notice = FindRepositoryRiskNotice(plugin.SourceUrl);
            if (notice is not null && !IsRepositoryRiskAcknowledged(notice))
                AcknowledgeRepositoryRisk(notice);
            if (RequiresUntrustedRepositoryAcknowledgement(plugin) && !IsUntrustedRepositoryAcknowledged(plugin))
                AcknowledgeUntrustedRepository(plugin);
        }
    }

    private void StartInstallTransaction(PluginInstallPlan plan)
    {
        var current = plan.MarkStaleIfRevisionsChanged(catalog.CatalogRevision, catalog.DependencyGraphRevision);
        pendingInstallPlan = current;
        if (!current.IsValid || current.IsStale || !InstallPlanSourceReviewsComplete(current))
            return;

        CommitInstallPlanSourceReviews(current);
        installTransactionRootInternalName = current.RootRequests.FirstOrDefault()?.InternalName ?? string.Empty;
        operationMessage = current.ChangeCount == 1
            ? "Preparing 1 package change…"
            : $"Preparing {current.ChangeCount} package changes…";
        installTransactionTask = installTransactions.ExecuteAsync(
            current,
            ResolveOrCreateInstallSource,
            configuration.PreferTestingBuilds);

        pendingInstall = null;
        pendingInstallPlan = null;
        pendingInstallPlanRootSourceUrl = string.Empty;
        pendingInstallPlanFromUpdate = false;
        pendingInstallExplicitDependencies.Clear();
        pendingInstallTransactionReviewSources.Clear();
        installPlanPopupOpen = false;
        installPopupOpen = false;
        installRiskPopupOpen = false;
        ImGui.CloseCurrentPopup();
    }

    private void CompleteInstallTransactionTaskIfReady()
    {
        if (installTransactionTask is null || !installTransactionTask.IsCompleted)
            return;
        try
        {
            var result = installTransactionTask.GetAwaiter().GetResult();
            operationMessage = result.Message;
            libraryLedger.ObserveInstalled(Plugin.PluginInterface.InstalledPlugins
                .Where(x => x is not null && !x.Manifest.ScheduledForDeletion)
                .Select(x => x.InternalName));
            pendingOrphanDependencies = result.OrphanedDependencies.ToArray();
            if (pendingOrphanDependencies.Length > 0)
            {
                orphanCleanupPopupOpen = true;
                requestOrphanCleanupPopup = true;
            }
            if (!result.Success && result.RollbackMessages.Count > 0)
                Plugin.Log.Warning("Omega dependency transaction rollback summary: {Summary}", string.Join(" | ", result.RollbackMessages));
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega dependency transaction failed unexpectedly for {Plugin}", installTransactionRootInternalName);
            operationMessage = $"Dependency transaction failed: {ex.GetBaseException().Message}";
        }
        finally
        {
            installTransactionTask = null;
            installTransactionRootInternalName = string.Empty;
            startupAppsSnapshot = null;
        }
    }


    private void DrawInstallPlanNotice(Vector4 color, string title, string message)
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(color.X * 0.20f, color.Y * 0.20f, color.Z * 0.20f, 0.85f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(color.X, color.Y, color.Z, 0.90f));
        ImGui.BeginChild($"install-plan-notice-{StableId(title)}", new Vector2(0f, Ui(76f)), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
        ImGui.TextColored(color, title);
        ImGui.TextWrapped(message);
        ImGui.EndChild();
        ImGui.PopStyleColor(2);
        ImGui.Spacing();
    }

    private void RebuildPendingInstallPlan(int currentApi, Version currentDalamudVersion)
    {
        var root = ResolvePendingInstallPlanRoot(currentApi, currentDalamudVersion);
        if (root is null)
        {
            pendingInstallPlan = pendingInstallPlan is null
                ? null
                : pendingInstallPlan with { IsValid = false, IsStale = true };
            return;
        }
        pendingInstallPlan = ResolveInstallPlan(root, currentApi, currentDalamudVersion);
    }

    private MarketplacePlugin? ResolvePendingInstallPlanRoot(int currentApi, Version currentDalamudVersion)
    {
        if (pendingInstall is null)
            return null;
        return GetInstallCandidates(pendingInstall.InternalName, currentApi, currentDalamudVersion)
            .FirstOrDefault(x => NormalizeUrl(x.SourceUrl)
                .Equals(NormalizeUrl(pendingInstallPlanRootSourceUrl), StringComparison.OrdinalIgnoreCase));
    }

    private bool PendingDependencyPlanAllowsSinglePluginExecution(MarketplacePlugin selected)
    {
        if (pendingInstallPlan is null)
            return true;
        var plan = pendingInstallPlan.MarkStaleIfRevisionsChanged(catalog.CatalogRevision, catalog.DependencyGraphRevision);
        pendingInstallPlan = plan;
        if (plan.IsStale || !plan.IsValid)
            return false;
        var mutations = plan.Operations.Where(x => x.Mutates).ToArray();
        return mutations.Length <= 1 &&
               mutations.All(x => x.InternalName.Equals(selected.InternalName, StringComparison.OrdinalIgnoreCase));
    }

    private void ReturnFromInstallPlan()
    {
        var fromUpdate = pendingInstallPlanFromUpdate;
        installPlanPopupOpen = false;
        pendingInstallPlan = null;
        pendingInstallPlanRootSourceUrl = string.Empty;
        pendingInstallPlanFromUpdate = false;
        pendingInstallExplicitDependencies.Clear();
        pendingInstallTransactionReviewSources.Clear();
        ImGui.CloseCurrentPopup();
        if (fromUpdate)
        {
            pendingInstall = null;
            return;
        }
        if (pendingInstall is not null)
        {
            installPopupOpen = true;
            requestInstallPopup = true;
        }
    }

}
