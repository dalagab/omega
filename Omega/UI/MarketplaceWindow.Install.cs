using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void DrawDetailsPrimaryAction(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (installedPlugin is not null)
        {
            ImGui.TextDisabled($"Installed {installedPlugin.Version?.ToString() ?? "version pending"}  •  {(installedPlugin.IsLoaded ? "loaded" : "not loaded")}");
            return;
        }

        var candidates = GetInstallCandidates(plugin.InternalName, currentApi, currentDalamudVersion);
        if (candidates.Count == 0)
        {
            ImGui.TextDisabled($"No compatible API {currentApi} package is available from an enabled repository.");
            return;
        }

        if (installTask is not null && installingInternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase))
        {
            ImGui.TextDisabled("Installing…");
            return;
        }

        var label = candidates.Count > 1 ? $"Install  •  {candidates.Count} repositories" : "Install";
        var width = Math.Min(260f, Math.Max(130f, ImGui.CalcTextSize(label).X + 36f));
        if (DrawPillButton(label, $"details-install-{plugin.InternalName}", new Vector2(width, 36f), true))
            OpenInstallChooser(plugin);
    }

    /// <summary>
    /// Repository chooser shown for every install. The user picks the exact feed variant; Omega
    /// then asks Dalamud to service that repository and perform the installation.
    /// </summary>
    private void DrawInstallModal(int currentApi, Version currentDalamudVersion)
    {
        if (!installPopupOpen || pendingInstall is null)
            return;

        var keepOpen = installPopupOpen;
        ImGui.SetNextWindowSize(new Vector2(600f, 0f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal("Choose repository###DalagabOmegaInstall", ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.AlwaysAutoResize))
        {
            installPopupOpen = keepOpen;
            return;
        }

        if (DrawOmegaModalHeader("Choose repository", "install"))
        {
            CloseInstallChooser();
            ImGui.EndPopup();
            return;
        }

        var plugin = pendingInstall;
        var candidates = GetInstallCandidates(plugin.InternalName, currentApi, currentDalamudVersion);
        EnsurePendingInstallSource(candidates);

        ImGui.Text($"Install {plugin.Name}");
        ImGui.TextDisabled("Choose which repository to use for this installation.");
        ImGui.Separator();

        if (candidates.Count == 0)
        {
            ImGui.TextWrapped($"No enabled repository currently advertises a compatible API {currentApi} package.");
        }
        else
        {
            foreach (var candidate in candidates)
                DrawInstallSourceChoice(candidate, currentApi);
        }

        ImGui.Separator();
        ImGui.TextWrapped("Dalamud will perform the installation and continue servicing updates from the selected repository.");

        var selected = candidates.FirstOrDefault(x =>
            NormalizeUrl(x.SourceUrl).Equals(NormalizeUrl(pendingInstallSourceUrl), StringComparison.OrdinalIgnoreCase));
        var canInstall = selected is not null && installTask is null;
        if (!canInstall)
            ImGui.BeginDisabled();
        if (ImGui.Button("Install"))
            StartSelectedInstall(selected!);
        if (!canInstall)
            ImGui.EndDisabled();

        ImGui.SameLine();
        if (ImGui.Button("Cancel"))
            CloseInstallChooser();

        installPopupOpen = keepOpen && installPopupOpen;
        ImGui.EndPopup();
    }

    private void DrawInstallSourceChoice(MarketplacePlugin candidate, int currentApi)
    {
        var selected = NormalizeUrl(candidate.SourceUrl)
            .Equals(NormalizeUrl(pendingInstallSourceUrl), StringComparison.OrdinalIgnoreCase);
        var version = candidate.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out var testing)
            ? testing ? candidate.TestingAssemblyVersionText ?? candidate.AssemblyVersionText : candidate.AssemblyVersionText
            : candidate.AssemblyVersionText;
        var api = testing ? candidate.TestingDalamudApiLevel ?? candidate.DalamudApiLevel : candidate.DalamudApiLevel;
        var sourceState = DescribeInstallSourceState(candidate);

        ImGui.PushID($"install-source-{StableId(candidate.SourceUrl)}");
        if (ImGui.Selectable($"{candidate.SourceName}##choice", selected))
            pendingInstallSourceUrl = candidate.SourceUrl;
        ImGui.TextDisabled($"{(candidate.SourceIsOfficial ? "Official" : "Community")}  •  Version {version}  •  API {api}");
        ImGui.TextDisabled(sourceState);
        ImGui.TextWrapped(candidate.SourceUrl);
        ImGui.Spacing();
        ImGui.PopID();
    }

    private string DescribeInstallSourceState(MarketplacePlugin candidate)
    {
        if (candidate.SourceIsOfficial)
            return "Official Dalamud repository";

        var source = FindConfiguredSource(candidate.SourceUrl);
        if (source is null)
            return "Source definition unavailable";

        var state = repositoryBridge.GetState(source.Url);
        if (!state.Available)
            return "Repository service unavailable";
        if (!state.Present)
            return "Will be added automatically for installation";
        if (!state.Enabled && source.DalamudManagedByOmega)
            return "Will be enabled automatically for installation";
        if (!state.Enabled)
            return "Currently disabled; Install will enable it";
        return "Ready";
    }

    private void EnsurePendingInstallSource(IReadOnlyList<MarketplacePlugin> candidates)
    {
        if (candidates.Any(x => NormalizeUrl(x.SourceUrl)
                .Equals(NormalizeUrl(pendingInstallSourceUrl), StringComparison.OrdinalIgnoreCase)))
            return;
        pendingInstallSourceUrl = candidates.FirstOrDefault()?.SourceUrl ?? string.Empty;
    }

    private void StartSelectedInstall(MarketplacePlugin plugin)
    {
        installingInternalName = plugin.InternalName;
        operationMessage = $"Installing {plugin.Name} from {plugin.SourceName}...";
        installTask = installer.InstallAsync(
            plugin,
            FindConfiguredSource(plugin.SourceUrl),
            configuration.PreferTestingBuilds);
        pendingInstall = null;
        pendingInstallSourceUrl = string.Empty;
        installPopupOpen = false;
        ImGui.CloseCurrentPopup();
    }

    private void CloseInstallChooser()
    {
        pendingInstall = null;
        pendingInstallSourceUrl = string.Empty;
        installPopupOpen = false;
        ImGui.CloseCurrentPopup();
    }

}
