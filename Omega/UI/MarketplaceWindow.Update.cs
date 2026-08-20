using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void OpenUpdateOrMigration(
        MarketplacePlugin displayedPlugin,
        IExposedPlugin installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (updateTask is not null)
            return;

        var candidate = GetAvailableUpdateCandidate(
            displayedPlugin.InternalName,
            installedPlugin,
            currentApi,
            currentDalamudVersion);
        if (candidate is null)
        {
            operationMessage = $"No newer compatible package is currently available for {displayedPlugin.Name}.";
            return;
        }

        if (!IsRepositoryMigration(installedPlugin, candidate))
        {
            StartSelectedUpdate(candidate);
            return;
        }

        pendingUpdate = candidate;
        pendingUpdatePreviousSourceUrl = installedPlugin.Manifest.InstalledFromUrl ?? string.Empty;
        pendingUpdateSourceAcknowledgementChecked = false;
        updateMigrationPopupOpen = true;
        requestUpdateMigrationPopup = true;
    }

    private void DrawUpdateMigrationModal(int currentApi, Version currentDalamudVersion)
    {
        if (!updateMigrationPopupOpen || pendingUpdate is null)
            return;

        var keepOpen = updateMigrationPopupOpen;
        ImGui.SetNextWindowSize(UiModalSize(650f, 0f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal(
                "Move plugin repository###DalagabOmegaUpdateMigration",
                ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.AlwaysAutoResize))
        {
            updateMigrationPopupOpen = keepOpen;
            return;
        }

        if (DrawOmegaModalHeader("Plugin moved repository", "update-migration"))
        {
            CloseUpdateMigration();
            ImGui.EndPopup();
            return;
        }

        var candidate = pendingUpdate;
        var installedPlugin = Plugin.PluginInterface.InstalledPlugins.FirstOrDefault(x =>
            x.InternalName.Equals(candidate.InternalName, StringComparison.OrdinalIgnoreCase));
        if (installedPlugin is null)
        {
            ImGui.TextWrapped($"{candidate.Name} is no longer installed.");
            if (ImGui.Button("Close", Ui(92f, 30f)))
                CloseUpdateMigration();
            ImGui.EndPopup();
            return;
        }

        var installedVersion = installedPlugin.Version;
        candidate.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out var useTesting);
        var targetVersion = useTesting
            ? candidate.TestingAssemblyVersion ?? candidate.AssemblyVersion
            : candidate.AssemblyVersion;

        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        ImGui.TextColored(new Vector4(0.98f, 0.73f, 0.23f, 1f), FontAwesomeIcon.SyncAlt.ToIconString());
        ImGui.PopFont();
        ImGui.SameLine(0f, 9f);
        ImGui.TextWrapped(
            $"Omega found a newer compatible version of {candidate.Name}, but it is now published from a different repository.");

        ImGui.Spacing();
        if (ImGui.BeginTable("update-migration-sources", 2, ImGuiTableFlags.SizingStretchProp))
        {
            ImGui.TableSetupColumn("Label", ImGuiTableColumnFlags.WidthFixed, 112f);
            ImGui.TableSetupColumn("Value", ImGuiTableColumnFlags.WidthStretch);

            ImGui.TableNextRow();
            ImGui.TableSetColumnIndex(0);
            ImGui.TextDisabled("Installed");
            ImGui.TableSetColumnIndex(1);
            ImGui.TextUnformatted(installedVersion is null ? "Version unknown" : $"v{installedVersion}");

            ImGui.TableNextRow();
            ImGui.TableSetColumnIndex(0);
            ImGui.TextDisabled("Update");
            ImGui.TableSetColumnIndex(1);
            ImGui.TextUnformatted($"v{targetVersion}");

            ImGui.TableNextRow();
            ImGui.TableSetColumnIndex(0);
            ImGui.TextDisabled("From");
            ImGui.TableSetColumnIndex(1);
            DrawInstalledMigrationSource(candidate, pendingUpdatePreviousSourceUrl, currentApi);

            ImGui.TableNextRow();
            ImGui.TableSetColumnIndex(0);
            ImGui.TextDisabled("To");
            ImGui.TableSetColumnIndex(1);
            DrawRepositoryName(SourceLabel(candidate), candidate.SourceUrl, candidate.SourceIsOfficial, currentApi);
            ImGui.SameLine(0f, Ui(8f));
            ImGui.TextDisabled("•");
            ImGui.SameLine(0f, Ui(8f));
            DrawRepositoryTrustLabel(SourceLabel(candidate), candidate.SourceUrl, candidate.SourceIsOfficial);

            ImGui.EndTable();
        }

        var destinationNeedsSourceReview = NeedsInstallRepositoryReview(candidate);
        if (destinationNeedsSourceReview)
        {
            ImGui.Spacing();
            ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.24f, 0.035f, 0.045f, 0.88f));
            ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.82f, 0.16f, 0.20f, 0.94f));
            ImGui.BeginChild("update-migration-source-review", new Vector2(0f, Ui(92f)), true,
                ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
            ImGui.TextColored(new Vector4(0.98f, 0.37f, 0.31f, 1f), "The destination source requires acknowledgement.");
            ImGui.TextWrapped(BuildInstallRepositoryReviewReason(candidate));
            ImGui.Checkbox("I understand and want to migrate to this source", ref pendingUpdateSourceAcknowledgementChecked);
            ImGui.EndChild();
            ImGui.PopStyleColor(2);
        }

        var previousVariant = ResolveMigrationSourceVariant(candidate.InternalName, pendingUpdatePreviousSourceUrl, installedVersion);
        if (previousVariant is not null)
        {
            var comparison = CompareRepositorySecurity(candidate, previousVariant);
            if (comparison.Different)
            {
                ImGui.Spacing();
                ImGui.PushFont(UiBuilder.IconFontFixedWidth);
                ImGui.TextColored(
                    comparison.Worse ? new Vector4(0.94f, 0.28f, 0.26f, 1f) : new Vector4(0.28f, 0.62f, 0.92f, 1f),
                    (comparison.Worse ? FontAwesomeIcon.ExclamationTriangle : FontAwesomeIcon.InfoCircle).ToIconString());
                ImGui.PopFont();
                ImGui.SameLine(0f, 8f);
                ImGui.TextWrapped(BuildMigrationSecurityMessage(candidate, previousVariant, comparison));
            }
        }

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.TextWrapped(
            "Omega will add or enable the new repository when necessary, then ask Dalamud to update the installed plugin in place. " +
            "The old repository is not removed because other installed plugins may still depend on it.");

        ImGui.TextDisabled(DescribeUpdateSourceState(candidate));

        ImGui.Spacing();
        var cancelWidth = Ui(92f);
        var migrateWidth = Ui(150f);
        if (ImGui.Button("Cancel", new Vector2(cancelWidth, 32f)))
        {
            CloseUpdateMigration();
            ImGui.EndPopup();
            return;
        }

        ImGui.SameLine(0f, 10f);
        var canUpdate = updateTask is null &&
                        (!destinationNeedsSourceReview || pendingUpdateSourceAcknowledgementChecked) &&
                        GetAvailableUpdateCandidate(candidate.InternalName, installedPlugin, currentApi, currentDalamudVersion) is not null;
        if (!canUpdate)
            ImGui.BeginDisabled();
        var migrateLabel = destinationNeedsSourceReview ? "Acknowledge & migrate" : "Migrate & update";
        if (ImGui.Button(migrateLabel, new Vector2(destinationNeedsSourceReview ? Ui(178f) : migrateWidth, Ui(32f))))
        {
            if (destinationNeedsSourceReview)
            {
                var notice = FindRepositoryRiskNotice(candidate.SourceUrl);
                if (notice is not null && !IsRepositoryRiskAcknowledged(notice))
                    AcknowledgeRepositoryRisk(notice);
                if (RequiresUntrustedRepositoryAcknowledgement(candidate) && !IsUntrustedRepositoryAcknowledged(candidate))
                    AcknowledgeUntrustedRepository(candidate);
            }
            StartSelectedUpdate(candidate);
        }
        if (!canUpdate)
            ImGui.EndDisabled();

        updateMigrationPopupOpen = keepOpen && updateMigrationPopupOpen;
        ImGui.EndPopup();
    }


    private static string BuildMigrationSecurityMessage(
        MarketplacePlugin destination,
        MarketplacePlugin installedSource,
        RepositorySecurityComparison comparison)
    {
        if (comparison.IntegrityAnomaly)
            return "Definitions integrity warning: the two repositories identify the same plugin package bytes but expose different security reports. Review the destination before migrating.";

        if (comparison.ArtifactDiffers)
        {
            var destinationVisual = ResolveSigmascopeVisual(destination);
            var installedVisual = ResolveSigmascopeVisual(installedSource);
            return $"The destination repository publishes different plugin package bytes from the installed source. " +
                   $"Security summary: destination {destinationVisual.Label.ToLowerInvariant()}, installed source {installedVisual.Label.ToLowerInvariant()}.";
        }

        return comparison.Worse
            ? "The destination repository has a different or less-complete security report than the installed source. Review its Security section before migrating."
            : "The destination repository has a different security report from the installed source. Review it before migrating.";
    }

    private string DescribeUpdateSourceState(MarketplacePlugin candidate)
    {
        if (candidate.SourceIsOfficial)
            return "The destination is built into Dalamud.";

        var source = FindConfiguredSource(candidate.SourceUrl);
        if (source is null)
            return "The destination repository definition is unavailable; refresh Sources before migrating.";

        var state = repositoryBridge.GetState(source.Url);
        if (!state.Available)
            return "Dalamud repository state is currently unavailable.";
        if (!state.Present)
            return "Omega will add the destination repository to Dalamud before updating.";
        if (!state.Enabled)
            return "Omega will enable the destination repository in Dalamud before updating.";
        return "The destination repository is already ready in Dalamud.";
    }

    private MarketplacePlugin? ResolveMigrationSourceVariant(string internalName, string sourceUrl, Version? installedVersion)
    {
        if (string.IsNullOrWhiteSpace(sourceUrl))
            return null;

        var variants = catalog.GetVariants(internalName);
        var exact = variants.FirstOrDefault(x =>
            NormalizeUrl(x.SourceUrl).Equals(NormalizeUrl(sourceUrl), StringComparison.OrdinalIgnoreCase) &&
            (installedVersion is null || x.AssemblyVersion.Equals(installedVersion)));
        return exact ?? variants.FirstOrDefault(x =>
            NormalizeUrl(x.SourceUrl).Equals(NormalizeUrl(sourceUrl), StringComparison.OrdinalIgnoreCase));
    }

    private void DrawInstalledMigrationSource(MarketplacePlugin candidate, string sourceUrl, int currentApi)
    {
        var sourceVariant = ResolveMigrationSourceVariant(candidate.InternalName, sourceUrl, installedVersion: null);
        if (sourceVariant is not null)
        {
            DrawRepositoryName(SourceLabel(sourceVariant), sourceVariant.SourceUrl, sourceVariant.SourceIsOfficial, currentApi);
            ImGui.SameLine(0f, Ui(8f));
            ImGui.TextDisabled("•");
            ImGui.SameLine(0f, Ui(8f));
            DrawRepositoryTrustLabel(SourceLabel(sourceVariant), sourceVariant.SourceUrl, sourceVariant.SourceIsOfficial);
            return;
        }

        var name = Uri.TryCreate(sourceUrl, UriKind.Absolute, out var uri) ? uri.Host : "Installed repository";
        DrawRepositoryName(name, sourceUrl, official: false, currentApi: currentApi);
        ImGui.SameLine(0f, Ui(8f));
        ImGui.TextDisabled("•");
        ImGui.SameLine(0f, Ui(8f));
        ImGui.TextColored(new Vector4(0.34f, 0.64f, 0.98f, 1f), "Unmanaged local");
    }

    private void StartUpdateAll(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (updateAllActive || updateTask is not null || updateAllDefinitionsTask is not null || updates.IsRefreshing)
            return;

        updateAllQueue.Clear();
        updateAllCompleted = 0;
        updateAllFailed = 0;
        updateAllSkippedMigrations = 0;
        updateAllDefinitionsPending = updates.DefinitionsUpdateAvailable;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var displayed in catalog.GetMainProjection(currentApi).Plugins.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
        {
            if (!seen.Add(displayed.InternalName) || !installed.TryGetValue(displayed.InternalName, out var installedPlugin))
                continue;
            var candidate = GetAvailableUpdateCandidate(displayed.InternalName, installedPlugin, currentApi, currentDalamudVersion);
            if (candidate is null)
                continue;
            if (IsRepositoryMigration(installedPlugin, candidate))
            {
                updateAllSkippedMigrations++;
                continue;
            }
            updateAllQueue.Enqueue(candidate);
        }

        updateAllTotal = updateAllQueue.Count + (updateAllDefinitionsPending ? 1 : 0);
        if (updateAllTotal == 0)
        {
            operationMessage = updateAllSkippedMigrations > 0
                ? $"{updateAllSkippedMigrations} update{(updateAllSkippedMigrations == 1 ? string.Empty : "s")} require repository review below."
                : "Everything is already current.";
            return;
        }

        updateAllActive = true;
        operationMessage = $"Updating 0/{updateAllTotal}…";
        StartNextUpdateAllStep();
    }

    private void StartNextUpdateAllStep()
    {
        if (!updateAllActive || updateTask is not null || updateAllDefinitionsTask is not null)
            return;

        if (updateAllQueue.Count > 0)
        {
            var plugin = updateAllQueue.Dequeue();
            updatingInternalName = plugin.InternalName;
            operationMessage = $"Updating {Math.Min(updateAllCompleted + 1, updateAllTotal)}/{updateAllTotal}: {plugin.Name}…";
            updateTask = installer.UpdateAsync(
                plugin,
                FindConfiguredSource(plugin.SourceUrl),
                configuration.PreferTestingBuilds);
            return;
        }

        if (updateAllDefinitionsPending)
        {
            updateAllDefinitionsPending = false;
            operationMessage = $"Updating {Math.Min(updateAllCompleted + 1, updateAllTotal)}/{updateAllTotal}: Omega Definitions…";
            updateAllDefinitionsTask = updates.ApplyDefinitionsUpdateAsync();
            return;
        }

        FinishUpdateAll();
    }

    private void CompleteUpdateAllDefinitionsTaskIfReady()
    {
        if (updateAllDefinitionsTask is null || !updateAllDefinitionsTask.IsCompleted)
            return;

        try
        {
            updateAllDefinitionsTask.GetAwaiter().GetResult();
            updateAllCompleted++;
            if (!string.IsNullOrWhiteSpace(updates.LastOnlineError) || updates.DefinitionsUpdateAvailable)
                updateAllFailed++;
        }
        catch (Exception ex)
        {
            updateAllCompleted++;
            updateAllFailed++;
            Plugin.Log.Warning(ex, "Omega Update all could not apply Definitions");
        }
        finally
        {
            updateAllDefinitionsTask = null;
            sidebarCatalogRevision = -1;
            filterCatalogRevision = -1;
        }

        StartNextUpdateAllStep();
    }

    private void FinishUpdateAll()
    {
        var succeeded = Math.Max(0, updateAllCompleted - updateAllFailed);
        var summary = $"Update all finished: {succeeded}/{updateAllTotal} succeeded";
        if (updateAllFailed > 0)
            summary += $", {updateAllFailed} failed";
        if (updateAllSkippedMigrations > 0)
            summary += $". {updateAllSkippedMigrations} repository migration{(updateAllSkippedMigrations == 1 ? string.Empty : "s")} remain in the list for review";
        operationMessage = summary + ".";
        updateAllActive = false;
        updateAllDefinitionsPending = false;
        updateAllQueue.Clear();
        updateAllTotal = 0;
    }

    private void StartSelectedUpdate(MarketplacePlugin plugin)
    {
        if (updateTask is not null)
            return;

        var installedPlugin = Plugin.PluginInterface.InstalledPlugins.FirstOrDefault(x =>
            x.InternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase));
        var migration = installedPlugin is not null && IsRepositoryMigration(installedPlugin, plugin);

        updatingInternalName = plugin.InternalName;
        updatingInstalledVersionText = installedPlugin?.Version?.ToString() ?? string.Empty;
        plugin.HasCurrentApiBuild(Plugin.PluginInterface.Manifest.DalamudApiLevel, configuration.PreferTestingBuilds, out var useTestingTarget);
        updatingTargetVersionText = (useTestingTarget ? plugin.TestingAssemblyVersion ?? plugin.AssemblyVersion : plugin.AssemblyVersion).ToString();
        operationMessage = migration
            ? $"Migrating {plugin.Name} to {plugin.SourceName} and updating it..."
            : $"Updating {plugin.Name}...";
        updateTask = installer.UpdateAsync(
            plugin,
            FindConfiguredSource(plugin.SourceUrl),
            configuration.PreferTestingBuilds);

        pendingUpdate = null;
        pendingUpdatePreviousSourceUrl = string.Empty;
        if (updateMigrationPopupOpen)
        {
            updateMigrationPopupOpen = false;
            ImGui.CloseCurrentPopup();
        }
    }

    private void CompleteUpdateTaskIfReady()
    {
        if (updateTask is null || !updateTask.IsCompleted)
            return;

        try
        {
            var result = updateTask.GetAwaiter().GetResult();
            operationMessage = result.Message;
            if (!string.IsNullOrWhiteSpace(updatingInternalName))
            {
                if (result.Success)
                    ClearUpdateFailure(updatingInternalName);
                else if (result.HasFailureDetail)
                    SetUpdateFailure(updatingInternalName, result);
            }
            if (result.Success && !string.IsNullOrWhiteSpace(updatingInternalName) && !string.IsNullOrWhiteSpace(result.NewSourceUrl))
                selectedVariantSource[updatingInternalName] = result.NewSourceUrl;
            if (updateAllActive)
            {
                updateAllCompleted++;
                if (!result.Success)
                    updateAllFailed++;
            }
        }
        catch (Exception ex)
        {
            var detail = ex.GetBaseException().Message;
            operationMessage = $"Update failed: {detail}";
            if (!string.IsNullOrWhiteSpace(updatingInternalName))
            {
                SetUpdateFailure(updatingInternalName, new UpdateResult(
                    UpdateOutcome.Failed,
                    $"Update failed for {updatingInternalName}. The installed plugin was not intentionally replaced by Omega.",
                    FailureKind: UpdateFailureKind.Lifecycle,
                    FailureCode: ex.GetBaseException().GetType().Name,
                    FailureDetail: detail));
            }
            if (updateAllActive)
            {
                updateAllCompleted++;
                updateAllFailed++;
            }
        }
        finally
        {
            updateTask = null;
            updatingInternalName = string.Empty;
            updatingInstalledVersionText = string.Empty;
            updatingTargetVersionText = string.Empty;
            sidebarCatalogRevision = -1;
            filterCatalogRevision = -1;
        }

        if (updateAllActive)
            StartNextUpdateAllStep();
    }

    private void DrawProductUpdateFailure(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (!updateFailures.TryGetValue(plugin.InternalName, out var failure))
            return;

        var availableTarget = installedPlugin is null
            ? null
            : GetAvailableUpdateVersion(plugin.InternalName, installedPlugin, currentApi, currentDalamudVersion);
        if (installedPlugin is null || !IsUpdateFailureApplicable(failure, availableTarget))
        {
            ClearUpdateFailure(plugin.InternalName);
            return;
        }

        ImGui.Dummy(Ui(1f, 10f));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, Ui(7f));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 1f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.18f, 0.055f, 0.035f, 0.72f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.86f, 0.27f, 0.17f, 0.78f));
        ImGui.BeginChild(
            $"product-update-failure-{StableId(plugin.InternalName)}",
            new Vector2(0f, Ui(142f)),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        ImGui.TextColored(new Vector4(0.98f, 0.48f, 0.24f, 1f), FontAwesomeIcon.ExclamationTriangle.ToIconString());
        ImGui.PopFont();
        ImGui.SameLine(0f, Ui(8f));
        ImGui.TextUnformatted("Update needs attention");
        ImGui.TextWrapped(failure.Message);
        var code = string.IsNullOrWhiteSpace(failure.FailureCode) ? "Dalamud update failure" : $"Dalamud: {failure.FailureCode}";
        var target = availableTarget;
        var installedVersion = installedPlugin?.Version?.ToString() ?? "unknown";
        var targetVersion = target?.ToString() ?? "unknown";
        ImGui.TextDisabled($"Installed v{installedVersion}  •  target v{targetVersion}  •  {code}  •  {SourceLabel(plugin)}");
        if (ImGui.IsItemHovered())
            SetReadableTooltip(BuildUpdateFailureTooltip(plugin, failure));

        ImGui.Spacing();
        if (IsSafeUpdateFailureRepositoryUrl(plugin.SourceUrl) && ImGui.SmallButton($"Open repository##update-failure-open-{StableId(plugin.InternalName)}"))
            OpenProductWebsite(plugin, plugin.SourceUrl);
        if (IsSafeUpdateFailureRepositoryUrl(plugin.SourceUrl))
            ImGui.SameLine(0f, Ui(8f));
        if (ImGui.SmallButton($"Dismiss##update-failure-dismiss-{StableId(plugin.InternalName)}"))
        {
            ClearUpdateFailure(plugin.InternalName);
            operationMessage = $"Dismissed the saved update diagnostic for {plugin.Name}.";
        }
        if (ImGui.IsWindowHovered())
            SetReadableTooltip(BuildUpdateFailureTooltip(plugin, failure));

        ImGui.EndChild();
        ImGui.PopStyleColor(2);
        ImGui.PopStyleVar(2);
    }

    private static string BuildUpdateFailureTooltip(MarketplacePlugin plugin, UpdateResult failure)
    {
        var lines = new List<string>();
        if (failure.FailureRecordedAtUtc is { } recorded)
            lines.Add($"Recorded: {recorded.ToLocalTime():g}");
        if (!string.IsNullOrWhiteSpace(failure.FailureInstalledVersion) || !string.IsNullOrWhiteSpace(failure.FailureTargetVersion))
            lines.Add($"Failed update: v{(string.IsNullOrWhiteSpace(failure.FailureInstalledVersion) ? "?" : failure.FailureInstalledVersion)} → v{(string.IsNullOrWhiteSpace(failure.FailureTargetVersion) ? "?" : failure.FailureTargetVersion)}");
        if (!string.IsNullOrWhiteSpace(failure.FailureDetail))
            lines.Add(failure.FailureDetail);
        if (!string.IsNullOrWhiteSpace(failure.FailureCode))
            lines.Add($"Dalamud status: {failure.FailureCode}");
        if (!string.IsNullOrWhiteSpace(plugin.SourceUrl))
            lines.Add($"Repository: {plugin.SourceUrl}");
        lines.Add("The existing installed version remains the safe baseline. Retry the update; if a download failure keeps repeating, the repository/update endpoint likely needs attention.");
        return string.Join("\n", lines);
    }

    private void RestorePersistedUpdateFailures()
    {
        if (configuration.UpdateFailures is null || configuration.UpdateFailures.Count == 0)
            return;

        foreach (var pair in configuration.UpdateFailures)
        {
            var stored = pair.Value;
            if (stored is null || string.IsNullOrWhiteSpace(pair.Key) || string.IsNullOrWhiteSpace(stored.Message))
                continue;
            if (!Enum.TryParse<UpdateFailureKind>(stored.FailureKind, ignoreCase: true, out var kind))
                kind = UpdateFailureKind.Lifecycle;
            updateFailures[pair.Key] = new UpdateResult(
                UpdateOutcome.Failed,
                stored.Message,
                stored.PreviousSourceUrl,
                stored.NewSourceUrl,
                FailureKind: kind,
                FailureCode: stored.FailureCode,
                FailureDetail: stored.FailureDetail,
                FailureRecordedAtUtc: stored.RecordedAtUtc == default ? null : stored.RecordedAtUtc,
                FailureInstalledVersion: stored.InstalledVersion,
                FailureTargetVersion: stored.TargetVersion);
        }
    }

    private void SetUpdateFailure(string internalName, UpdateResult failure)
    {
        if (string.IsNullOrWhiteSpace(internalName))
            return;
        var recorded = failure with
        {
            FailureRecordedAtUtc = failure.FailureRecordedAtUtc ?? DateTimeOffset.UtcNow,
            FailureInstalledVersion = string.IsNullOrWhiteSpace(failure.FailureInstalledVersion) ? updatingInstalledVersionText : failure.FailureInstalledVersion,
            FailureTargetVersion = string.IsNullOrWhiteSpace(failure.FailureTargetVersion) ? updatingTargetVersionText : failure.FailureTargetVersion,
        };
        updateFailures[internalName] = recorded;
        configuration.UpdateFailures ??= new Dictionary<string, PersistedUpdateFailure>(StringComparer.OrdinalIgnoreCase);
        configuration.UpdateFailures[internalName] = new PersistedUpdateFailure
        {
            Message = recorded.Message,
            PreviousSourceUrl = recorded.PreviousSourceUrl,
            NewSourceUrl = recorded.NewSourceUrl,
            FailureKind = recorded.FailureKind.ToString(),
            FailureCode = recorded.FailureCode,
            FailureDetail = recorded.FailureDetail,
            InstalledVersion = recorded.FailureInstalledVersion,
            TargetVersion = recorded.FailureTargetVersion,
            RecordedAtUtc = recorded.FailureRecordedAtUtc ?? DateTimeOffset.UtcNow,
        };
        configuration.Save();
    }

    private void ClearUpdateFailure(string internalName)
    {
        if (string.IsNullOrWhiteSpace(internalName))
            return;
        var changed = updateFailures.Remove(internalName);
        if (configuration.UpdateFailures is not null)
            changed |= configuration.UpdateFailures.Remove(internalName);
        if (changed)
            configuration.Save();
    }

    private static bool IsUpdateFailureApplicable(UpdateResult failure, Version? availableTarget)
    {
        if (availableTarget is null)
            return false;
        return string.IsNullOrWhiteSpace(failure.FailureTargetVersion) ||
               failure.FailureTargetVersion.Equals(availableTarget.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSafeUpdateFailureRepositoryUrl(string value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
           (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase));

    private void CloseUpdateMigration()
    {
        pendingUpdate = null;
        pendingUpdatePreviousSourceUrl = string.Empty;
        pendingUpdateSourceAcknowledgementChecked = false;
        updateMigrationPopupOpen = false;
        ImGui.CloseCurrentPopup();
    }
}
