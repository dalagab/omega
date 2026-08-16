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
        updateMigrationPopupOpen = true;
        requestUpdateMigrationPopup = true;
    }

    private void DrawUpdateMigrationModal(int currentApi, Version currentDalamudVersion)
    {
        if (!updateMigrationPopupOpen || pendingUpdate is null)
            return;

        var keepOpen = updateMigrationPopupOpen;
        ImGui.SetNextWindowSize(new Vector2(650f, 0f), ImGuiCond.Appearing);
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
            if (ImGui.Button("Close", new Vector2(92f, 30f)))
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

            ImGui.EndTable();
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
        const float cancelWidth = 92f;
        const float migrateWidth = 150f;
        if (ImGui.Button("Cancel", new Vector2(cancelWidth, 32f)))
        {
            CloseUpdateMigration();
            ImGui.EndPopup();
            return;
        }

        ImGui.SameLine(0f, 10f);
        var canUpdate = updateTask is null &&
                        GetAvailableUpdateCandidate(candidate.InternalName, installedPlugin, currentApi, currentDalamudVersion) is not null;
        if (!canUpdate)
            ImGui.BeginDisabled();
        if (ImGui.Button("Migrate & update", new Vector2(migrateWidth, 32f)))
            StartSelectedUpdate(candidate);
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
            var destinationVisual = ResolvePluginSecurityVisual(destination);
            var installedVisual = ResolvePluginSecurityVisual(installedSource);
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
            return;
        }

        var name = Uri.TryCreate(sourceUrl, UriKind.Absolute, out var uri) ? uri.Host : "Installed repository";
        DrawRepositoryName(name, sourceUrl, official: false, currentApi: currentApi);
    }

    private void StartSelectedUpdate(MarketplacePlugin plugin)
    {
        if (updateTask is not null)
            return;

        var installedPlugin = Plugin.PluginInterface.InstalledPlugins.FirstOrDefault(x =>
            x.InternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase));
        var migration = installedPlugin is not null && IsRepositoryMigration(installedPlugin, plugin);

        updatingInternalName = plugin.InternalName;
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
            if (result.Success && !string.IsNullOrWhiteSpace(updatingInternalName) && !string.IsNullOrWhiteSpace(result.NewSourceUrl))
                selectedVariantSource[updatingInternalName] = result.NewSourceUrl;
        }
        catch (Exception ex)
        {
            operationMessage = $"Update failed: {ex.GetBaseException().Message}";
        }
        finally
        {
            updateTask = null;
            updatingInternalName = string.Empty;
            sidebarCatalogRevision = -1;
            filterCatalogRevision = -1;
        }
    }

    private void CloseUpdateMigration()
    {
        pendingUpdate = null;
        pendingUpdatePreviousSourceUrl = string.Empty;
        updateMigrationPopupOpen = false;
        ImGui.CloseCurrentPopup();
    }
}
