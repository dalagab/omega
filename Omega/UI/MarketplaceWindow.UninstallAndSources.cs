using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

/// <summary>
/// Owns destructive uninstall confirmation. Plugin lifecycle changes remain delegated to Dalamud.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private void OpenUninstallConfirmation(MarketplacePlugin plugin)
    {
        pendingUninstall = plugin;
        uninstallPopupOpen = true;
        requestUninstallPopup = true;
    }

    private void DrawUninstallModal()
    {
        if (!uninstallPopupOpen || pendingUninstall is null)
            return;

        var keepOpen = uninstallPopupOpen;
        ImGui.SetNextWindowSize(UiModalSize(520f, 0f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal("Uninstall plugin###DalagabOmegaUninstall", ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.AlwaysAutoResize))
        {
            uninstallPopupOpen = keepOpen;
            return;
        }

        if (DrawOmegaModalHeader("Uninstall plugin", "uninstall"))
        {
            CloseUninstallConfirmation();
            ImGui.EndPopup();
            return;
        }

        var plugin = pendingUninstall;
        ImGui.TextUnformatted($"Uninstall {plugin.Name}?");
        ImGui.Spacing();
        ImGui.TextWrapped("Dalamud will uninstall this plugin.");
        ImGui.TextDisabled("Plugin configuration/data is not deleted by this action.");

        var requiredDependents = GetInstalledRequiredDependents(plugin);
        if (requiredDependents.Length > 0)
        {
            ImGui.Spacing();
            ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.24f, 0.035f, 0.045f, 0.88f));
            ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.82f, 0.16f, 0.20f, 0.94f));
            ImGui.BeginChild("uninstall-required-dependents", new Vector2(0f, Ui(Math.Min(156f, 72f + requiredDependents.Length * 22f))), true);
            ImGui.TextColored(new Vector4(0.98f, 0.37f, 0.31f, 1f),
                requiredDependents.Length == 1
                    ? "This plugin is required by an installed plugin."
                    : $"This plugin is required by {requiredDependents.Length} installed plugins.");
            foreach (var dependent in requiredDependents.Take(4))
                ImGui.TextWrapped($"• {dependent}");
            if (requiredDependents.Length > 4)
                ImGui.TextDisabled($"…and {requiredDependents.Length - 4} more");
            ImGui.EndChild();
            ImGui.PopStyleColor(2);
            ImGui.TextDisabled("Omega will not silently break required dependents. Remove or change those plugins first.");
            if (ImGui.Button("View dependent", Ui(150f, 32f)))
            {
                var target = catalog.GetVariants(requiredDependents[0]).FirstOrDefault();
                if (target is not null)
                {
                    CloseUninstallConfirmation();
                    OpenPluginDetails(target);
                    ImGui.EndPopup();
                    return;
                }
            }
        }

        var namedMemberships = GetPluginDirectControlState(plugin.InternalName).Memberships
            .Where(x => !x.Collection.IsDefault)
            .OrderBy(x => CollectionDisplayName(x.Collection), StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (namedMemberships.Length > 0)
        {
            ImGui.Spacing();
            ImGui.TextWrapped(namedMemberships.Length == 1
                ? $"{plugin.Name} is also in this named collection:"
                : $"{plugin.Name} is also in these named collections:");
            foreach (var membership in namedMemberships)
                ImGui.TextDisabled($"• {CollectionDisplayName(membership.Collection)}");
            ImGui.TextDisabled("You can remove these memberships before uninstalling.");

            var canRemoveMemberships = collectionOperationTask is null;
            if (!canRemoveMemberships)
                ImGui.BeginDisabled();
            if (ImGui.Button(
                    namedMemberships.Length == 1 ? "Remove from collection" : "Remove from collections",
                    Ui(190f, 34f)))
            {
                StartRemovePendingUninstallFromCollections(plugin, namedMemberships);
            }
            if (!canRemoveMemberships)
                ImGui.EndDisabled();
            if (!canRemoveMemberships && ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
                ImGui.SetTooltip("Another Dalamud collection change is still being applied.");
        }

        ImGui.Spacing();

        var canUninstall = uninstallTask is null &&
                           installTransactionTask is null &&
                           collectionOperationTask is null &&
                           requiredDependents.Length == 0 &&
                           !plugin.InternalName.Equals(Plugin.PluginInterface.InternalName, StringComparison.OrdinalIgnoreCase);
        if (!canUninstall)
            ImGui.BeginDisabled();
        if (ImGui.Button("Uninstall", Ui(140f, 36f)))
            StartSelectedUninstall(plugin);
        if (!canUninstall)
            ImGui.EndDisabled();

        ImGui.SameLine();
        if (ImGui.Button("Cancel", Ui(110f, 36f)))
            CloseUninstallConfirmation();

        uninstallPopupOpen = keepOpen && uninstallPopupOpen;
        ImGui.EndPopup();
    }

    private void StartRemovePendingUninstallFromCollections(
        MarketplacePlugin plugin,
        IReadOnlyList<PluginCollectionMembershipState> memberships)
    {
        if (collectionOperationTask is not null)
        {
            operationMessage = "Dalamud is already changing a collection.";
            return;
        }

        var namedMemberships = memberships
            .Where(x => !x.Collection.IsDefault)
            .ToArray();
        if (namedMemberships.Length == 0)
            return;

        operationMessage = namedMemberships.Length == 1
            ? $"Removing {plugin.Name} from {CollectionDisplayName(namedMemberships[0].Collection)}…"
            : $"Removing {plugin.Name} from {namedMemberships.Length} named collections…";
        collectionOperationTask = Task.Run(() => RemovePendingUninstallFromCollectionsAsync(plugin, namedMemberships));
    }

    private async Task<DalamudCollectionOperationResult> RemovePendingUninstallFromCollectionsAsync(
        MarketplacePlugin plugin,
        IReadOnlyList<PluginCollectionMembershipState> memberships)
    {
        foreach (var membership in memberships)
        {
            var result = await profileBridge.RemovePluginFromCollectionAsync(
                membership.Collection.Id,
                membership.Entry.WorkingPluginId).ConfigureAwait(false);
            if (!result.Success)
            {
                return new(
                    false,
                    $"Could not remove {plugin.Name} from {CollectionDisplayName(membership.Collection)}. {result.Message}");
            }
        }

        return new(
            true,
            memberships.Count == 1
                ? $"Removed {plugin.Name} from {CollectionDisplayName(memberships[0].Collection)}."
                : $"Removed {plugin.Name} from {memberships.Count} named collections.");
    }

    private void StartSelectedUninstall(MarketplacePlugin plugin)
    {
        uninstallingInternalName = plugin.InternalName;
        operationMessage = $"Uninstalling {plugin.Name} through Dalamud...";
        uninstallTask = installer.UninstallAsync(plugin.InternalName);
        pendingUninstall = null;
        uninstallPopupOpen = false;
        ImGui.CloseCurrentPopup();
    }

    private void CloseUninstallConfirmation()
    {
        pendingUninstall = null;
        uninstallPopupOpen = false;
        ImGui.CloseCurrentPopup();
    }

    private void CompleteUninstallTaskIfReady()
    {
        if (uninstallTask is null || !uninstallTask.IsCompleted)
            return;

        try
        {
            var result = uninstallTask.GetAwaiter().GetResult();
            operationMessage = result.Message;
            if (result.Outcome is UninstallOutcome.Uninstalled or UninstallOutcome.NotInstalled)
            {
                if (!string.IsNullOrWhiteSpace(uninstallingInternalName))
                {
                    libraryLedger.MarkRootRemoved(uninstallingInternalName);
                    libraryLedger.ForgetRemoved(uninstallingInternalName);
                }
                pendingOrphanDependencies = installTransactions.FindDependencyOwnedOrphans().ToArray();
                if (pendingOrphanDependencies.Length > 0)
                {
                    orphanCleanupPopupOpen = true;
                    requestOrphanCleanupPopup = true;
                }
            }
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega uninstall task failed unexpectedly for {Plugin}", uninstallingInternalName);
            operationMessage = $"Uninstall failed: {ex.GetBaseException().Message}";
        }
        finally
        {
            startupAppsSnapshot = null;
            uninstallTask = null;
            uninstallingInternalName = string.Empty;
        }
    }

    private string[] GetInstalledRequiredDependents(MarketplacePlugin provider)
    {
        var installed = Plugin.PluginInterface.InstalledPlugins
            .Where(x => x is not null && !x.Manifest.ScheduledForDeletion && !string.IsNullOrWhiteSpace(x.InternalName))
            .GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);
        var identity = provider.CatalogPluginId;
        var edges = identity > 0
            ? catalog.GetDependentsForProvider(identity)
            : catalog.GetDependentsForProvider(provider.InternalName);
        return edges
            .Where(x => x.Relationship == PluginDependencyRelationship.Required)
            .Where(x => installed.TryGetValue(x.ConsumerInternalName, out var consumer) &&
                        (string.IsNullOrWhiteSpace(x.ConsumerVersion) ||
                         consumer.Version is null ||
                         Version.TryParse(x.ConsumerVersion, out var expected) && expected.CompareTo(consumer.Version) == 0))
            .Select(x => x.ConsumerInternalName)
            .Where(x => !string.IsNullOrWhiteSpace(x) && !x.Equals(provider.InternalName, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private void DrawOrphanCleanupModal()
    {
        if (!orphanCleanupPopupOpen || pendingOrphanDependencies.Length == 0)
            return;
        var keepOpen = orphanCleanupPopupOpen;
        ImGui.SetNextWindowSize(UiModalSize(560f, 0f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal("Unused dependencies###DalagabOmegaOrphanCleanup", ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.AlwaysAutoResize))
        {
            orphanCleanupPopupOpen = keepOpen;
            return;
        }

        if (DrawOmegaModalHeader("Unused dependencies", "orphan-cleanup"))
        {
            orphanCleanupPopupOpen = false;
            pendingOrphanDependencies = [];
            ImGui.CloseCurrentPopup();
            ImGui.EndPopup();
            return;
        }

        ImGui.TextWrapped("These plugins were installed by Omega only as dependencies and are no longer required by an installed root plugin.");
        ImGui.TextDisabled("Nothing is removed automatically.");
        ImGui.Spacing();
        foreach (var dependency in pendingOrphanDependencies)
        {
            ImGui.Bullet();
            ImGui.SameLine();
            ImGui.TextUnformatted(dependency);
            ImGui.SameLine(0f, Ui(8f));
            ImGui.TextDisabled("No longer required");
        }
        ImGui.Spacing();
        var busy = orphanRemovalTask is not null;
        if (busy)
            ImGui.BeginDisabled();
        if (ImGui.Button("Remove unused dependencies", Ui(220f, 36f)) && !busy)
        {
            orphanRemovalTask = installTransactions.RemoveUnusedDependenciesAsync(pendingOrphanDependencies);
            operationMessage = "Removing unused dependency-owned plugins…";
        }
        if (busy)
            ImGui.EndDisabled();
        ImGui.SameLine();
        if (ImGui.Button("Keep", Ui(100f, 36f)))
        {
            orphanCleanupPopupOpen = false;
            pendingOrphanDependencies = [];
            ImGui.CloseCurrentPopup();
        }

        orphanCleanupPopupOpen = keepOpen && orphanCleanupPopupOpen;
        ImGui.EndPopup();
    }

    private void CompleteOrphanRemovalTaskIfReady()
    {
        if (orphanRemovalTask is null || !orphanRemovalTask.IsCompleted)
            return;
        try
        {
            var result = orphanRemovalTask.GetAwaiter().GetResult();
            operationMessage = result.Skipped.Count == 0
                ? $"Removed {result.Removed} unused dependenc{(result.Removed == 1 ? "y" : "ies")}."
                : $"Removed {result.Removed}; kept {result.Skipped.Count} because they became required or were no longer dependency-owned.";
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega unused-dependency removal failed.");
            operationMessage = $"Could not remove unused dependencies: {ex.GetBaseException().Message}";
        }
        finally
        {
            orphanRemovalTask = null;
            pendingOrphanDependencies = installTransactions.FindDependencyOwnedOrphans().ToArray();
            if (pendingOrphanDependencies.Length == 0)
            {
                orphanCleanupPopupOpen = false;
                ImGui.CloseCurrentPopup();
            }
            startupAppsSnapshot = null;
        }
    }


}
