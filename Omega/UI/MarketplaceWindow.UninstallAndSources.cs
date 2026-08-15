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
        ImGui.SetNextWindowSize(new Vector2(520f, 0f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal("Uninstall plugin###DalagabOmegaUninstall", ref keepOpen, ImGuiWindowFlags.AlwaysAutoResize))
        {
            uninstallPopupOpen = keepOpen;
            return;
        }

        var plugin = pendingUninstall;
        ImGui.TextUnformatted($"Uninstall {plugin.Name}?");
        ImGui.Spacing();
        ImGui.TextWrapped("Omega will ask Dalamud to unload the plugin when needed, schedule its installed files for deletion, and remove it from Dalamud's active installed-plugin list.");
        ImGui.TextDisabled("Plugin configuration/data is not deleted by this action.");
        ImGui.Spacing();

        var canUninstall = uninstallTask is null &&
                           !plugin.InternalName.Equals(Plugin.PluginInterface.InternalName, StringComparison.OrdinalIgnoreCase);
        if (!canUninstall)
            ImGui.BeginDisabled();
        if (ImGui.Button("Uninstall", new Vector2(140f, 36f)))
            StartSelectedUninstall(plugin);
        if (!canUninstall)
            ImGui.EndDisabled();

        ImGui.SameLine();
        if (ImGui.Button("Cancel", new Vector2(110f, 36f)))
            CloseUninstallConfirmation();

        uninstallPopupOpen = keepOpen && uninstallPopupOpen;
        ImGui.EndPopup();
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
