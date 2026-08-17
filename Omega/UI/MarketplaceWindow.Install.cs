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
    /// Repository chooser shown for every install. Repository priority is already encoded in the
    /// candidate ordering, so the chooser stays focused on one task: select a source and install.
    /// Clicking a source only changes selection; the explicit Install action performs the lifecycle.
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
        var selected = candidates.FirstOrDefault(x =>
            NormalizeUrl(x.SourceUrl).Equals(NormalizeUrl(pendingInstallSourceUrl), StringComparison.OrdinalIgnoreCase));

        var headingY = ImGui.GetCursorPosY();
        ImGui.Text($"Install {plugin.Name}");

        const float installButtonWidth = 88f;
        const float installButtonHeight = 30f;
        var actionX = ImGui.GetCursorPosX() + Math.Max(0f, ImGui.GetContentRegionAvail().X - installButtonWidth);
        ImGui.SetCursorPos(new Vector2(actionX, headingY));
        var canInstall = selected is not null && installTask is null;
        if (!canInstall)
            ImGui.BeginDisabled();
        if (ImGui.Button("Install", new Vector2(installButtonWidth, installButtonHeight)))
            StartSelectedInstall(selected!);
        if (!canInstall)
            ImGui.EndDisabled();

        ImGui.SetCursorPosY(headingY + installButtonHeight + 4f);
        ImGui.TextDisabled("Choose which repository to use for this installation.");
        ImGui.Separator();

        if (DrawRequiredProviderInstallWarning(plugin))
        {
            installPopupOpen = false;
            ImGui.EndPopup();
            return;
        }

        if (candidates.Count == 0)
        {
            ImGui.TextWrapped($"No enabled repository currently advertises a compatible API {currentApi} package.");
        }
        else
        {
            foreach (var candidate in candidates)
                DrawInstallSourceChoice(candidate, currentApi, currentDalamudVersion);
        }

        ImGui.Separator();
        ImGui.TextWrapped("Dalamud will perform the installation and continue servicing updates from the selected repository.");

        installPopupOpen = keepOpen && installPopupOpen;
        ImGui.EndPopup();
    }

    private bool DrawRequiredProviderInstallWarning(MarketplacePlugin plugin)
    {
        var installedNames = Plugin.PluginInterface.InstalledPlugins
            .Where(x => !string.IsNullOrWhiteSpace(x.InternalName))
            .Select(x => x.InternalName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var missing = plugin.SecurityDependencies
            .Where(IsHighConfidenceRequiredProvider)
            .Where(x => string.IsNullOrWhiteSpace(x.TargetInternalName) || !installedNames.Contains(x.TargetInternalName))
            .GroupBy(x => string.IsNullOrWhiteSpace(x.TargetInternalName) ? x.Name : x.TargetInternalName, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .Take(4)
            .ToArray();
        if (missing.Length == 0)
            return false;

        var height = 86f + (missing.Length * 28f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.24f, 0.035f, 0.045f, 0.90f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.82f, 0.16f, 0.20f, 0.94f));
        ImGui.BeginChild("install-required-provider-warning", new Vector2(0f, height), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
        ImGui.SetCursorPosY(12f);
        DrawPluginFontAwesomeRiskIcon(
            FontAwesomeIcon.ExclamationTriangle,
            new Vector4(0.98f, 0.28f, 0.31f, 1f),
            "High-confidence required IPC provider is not installed",
            24f);
        ImGui.SameLine(0f, 10f);
        ImGui.BeginGroup();
        ImGui.TextUnformatted(missing.Length == 1 ? "Required provider not installed" : "Required providers not installed");
        ImGui.PushTextWrapPos(ImGui.GetWindowContentRegionMax().X - 12f);
        ImGui.TextDisabled("Static analysis indicates that core plugin functionality depends on the IPC provider below. Omega will not install it automatically.");
        ImGui.PopTextWrapPos();
        ImGui.EndGroup();

        foreach (var dependency in missing)
        {
            var providerName = string.IsNullOrWhiteSpace(dependency.TargetInternalName) ? dependency.Name : dependency.TargetInternalName;
            ImGui.SetCursorPosX(14f);
            ImGui.TextColored(new Vector4(0.98f, 0.46f, 0.42f, 1f), $"• {providerName}");
            var target = string.IsNullOrWhiteSpace(dependency.TargetInternalName)
                ? null
                : catalog.GetVariants(dependency.TargetInternalName).FirstOrDefault();
            if (target is not null)
            {
                ImGui.SameLine();
                if (ImGui.SmallButton($"View provider##required-provider-{StableId(dependency.TargetInternalName)}"))
                {
                    pendingInstall = null;
                    pendingInstallSourceUrl = string.Empty;
                    installPopupOpen = false;
                    ImGui.CloseCurrentPopup();
                    OpenPluginDetails(target);
                    ImGui.EndChild();
                    ImGui.PopStyleColor(2);
                    return true;
                }
            }
            if (ImGui.IsItemHovered() && !string.IsNullOrWhiteSpace(dependency.RelationshipReason))
                ImGui.SetTooltip($"{dependency.RelationshipConfidence} confidence\n{dependency.RelationshipReason}");
        }

        ImGui.EndChild();
        ImGui.PopStyleColor(2);
        ImGui.Spacing();
        return false;
    }

    private void DrawInstallSourceChoice(MarketplacePlugin candidate, int currentApi, Version currentDalamudVersion)
    {
        var selected = NormalizeUrl(candidate.SourceUrl)
            .Equals(NormalizeUrl(pendingInstallSourceUrl), StringComparison.OrdinalIgnoreCase);
        var version = candidate.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out var testing)
            ? testing ? candidate.TestingAssemblyVersionText ?? candidate.AssemblyVersionText : candidate.AssemblyVersionText
            : candidate.AssemblyVersionText;
        var api = testing ? candidate.TestingDalamudApiLevel ?? candidate.DalamudApiLevel : candidate.DalamudApiLevel;
        var sourceState = DescribeInstallSourceState(candidate);
        var alreadyPresent = IsInstallRepositoryPresent(candidate);
        var baseline = GetInstallCandidates(candidate.InternalName, currentApi, currentDalamudVersion).FirstOrDefault() ?? candidate;
        var sourceComparison = CompareRepositorySecurity(candidate, baseline);

        ImGui.PushID($"install-source-{StableId(candidate.SourceUrl)}");
        var rowStart = ImGui.GetCursorPos();
        var rowWidth = ImGui.GetContentRegionAvail().X;
        if (ImGui.Selectable(
                "##choice",
                selected,
                ImGuiSelectableFlags.DontClosePopups,
                new Vector2(rowWidth, MarketplaceLayoutRules.InstallSourceRowHeight)))
        {
            pendingInstallSourceUrl = candidate.SourceUrl;
        }
        var rowEnd = ImGui.GetCursorPos();

        ImGui.SetCursorPos(rowStart + new Vector2(10f, 8f));
        if (sourceComparison.Worse)
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.94f, 0.28f, 0.26f, 1f));
        DrawRepositoryName(Shorten(candidate.SourceName, 46), candidate.SourceUrl, candidate.SourceIsOfficial, currentApi);
        if (sourceComparison.Worse)
            ImGui.PopStyleColor();
        DrawRepositorySecurityDifferenceIndicator(sourceComparison);

        if (alreadyPresent)
            DrawInstallRepositoryPresentMarker(rowStart, rowWidth, candidate.SourceIsOfficial);

        ImGui.SetCursorPos(rowStart + new Vector2(10f, 33f));
        ImGui.TextDisabled($"Version {version}  •  API {api}");
        ImGui.SetCursorPos(rowStart + new Vector2(10f, 55f));
        if (sourceComparison.Worse)
            ImGui.TextColored(new Vector4(0.94f, 0.28f, 0.26f, 1f), sourceState);
        else
            ImGui.TextDisabled(sourceState);
        ImGui.SetCursorPos(rowStart + new Vector2(10f, 76f));
        ImGui.TextDisabled(Shorten(candidate.SourceUrl, 88));
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(candidate.SourceUrl);

        ImGui.SetCursorPos(rowEnd);
        ImGui.Spacing();
        ImGui.PopID();
    }

    private static void DrawInstallRepositoryPresentMarker(Vector2 rowStart, float rowWidth, bool official)
    {
        ImGui.SetCursorPos(rowStart + new Vector2(Math.Max(10f, rowWidth - 30f), 10f));
        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        ImGui.TextColored(new Vector4(0.28f, 0.80f, 0.48f, 1f), FontAwesomeIcon.Check.ToIconString());
        ImGui.PopFont();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(official ? "Built into Dalamud" : "Repository already added to Dalamud");
    }

    private bool IsInstallRepositoryPresent(MarketplacePlugin candidate)
    {
        if (candidate.SourceIsOfficial)
            return true;

        var source = FindConfiguredSource(candidate.SourceUrl);
        if (source is null)
            return false;

        var state = repositoryBridge.GetState(source.Url);
        return state.Available && state.Present;
    }

    private string DescribeInstallSourceState(MarketplacePlugin candidate)
    {
        if (candidate.SourceIsOfficial)
            return "Built into Dalamud";

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
