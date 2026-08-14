using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

/// <summary>
/// Owns destructive uninstall confirmation and the per-plugin source provenance popup.
/// Both flows remain explicit: uninstall delegates to Dalamud, while source URLs are copied only
/// after the user chooses the exact known repository.
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

    private void DrawKnownSourcesPopup()
    {
        if (!sourcePopupOpen || sourcePopupPlugin is null)
            return;

        var keepOpen = sourcePopupOpen;
        ImGui.SetNextWindowSize(new Vector2(680f, 0f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal("Known sources###DalagabOmegaKnownSources", ref keepOpen, ImGuiWindowFlags.AlwaysAutoResize))
        {
            sourcePopupOpen = keepOpen;
            return;
        }

        var plugin = sourcePopupPlugin;
        var sources = catalog.GetVariants(plugin.InternalName)
            .Where(x => !string.IsNullOrWhiteSpace(x.SourceUrl))
            .GroupBy(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderByDescending(x => x.SourceIsOfficial).ThenByDescending(x => x.AssemblyVersion).First())
            .OrderByDescending(x => x.SourceIsOfficial)
            .ThenBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        ImGui.TextUnformatted($"Known sources for {plugin.Name}");
        ImGui.TextDisabled($"Omega currently knows {sources.Length} repository source{(sources.Length == 1 ? string.Empty : "s")} for this plugin.");
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        foreach (var source in sources)
        {
            ImGui.PushID($"known-source-{StableId(source.SourceUrl)}");
            ImGui.TextUnformatted(source.SourceName);
            ImGui.SameLine();
            ImGui.TextDisabled(source.SourceIsOfficial ? "Official" : "Community");
            ImGui.TextWrapped(source.SourceUrl);
            ImGui.TextDisabled($"Version {source.AssemblyVersionText}  •  API {source.HighestKnownApiLevel}");
            if (ImGui.Button("Copy source", new Vector2(120f, 30f)))
            {
                ImGui.SetClipboardText(source.SourceUrl);
                operationMessage = $"Copied source for {source.SourceName}.";
            }
            ImGui.PopID();
            ImGui.Spacing();
        }

        if (sources.Length == 0)
            ImGui.TextDisabled("No repository URL is currently known for this plugin.");

        ImGui.Separator();
        if (ImGui.Button("Close", new Vector2(100f, 32f)))
        {
            sourcePopupPlugin = null;
            sourcePopupOpen = false;
            ImGui.CloseCurrentPopup();
        }

        sourcePopupOpen = keepOpen && sourcePopupOpen;
        ImGui.EndPopup();
    }
}
