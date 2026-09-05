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
                           collectionOperationTask is null &&
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
            operationMessage = uninstallTask.GetAwaiter().GetResult().Message;
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega uninstall task failed unexpectedly for {Plugin}", uninstallingInternalName);
            operationMessage = $"Uninstall failed: {ex.GetBaseException().Message}";
        }
        finally
        {
            uninstallTask = null;
            uninstallingInternalName = string.Empty;
        }
    }

}
