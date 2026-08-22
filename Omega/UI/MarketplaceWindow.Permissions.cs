using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private const string InstallPermissionPopupId = "Check plugin permissions###DalagabOmegaInstallPermission";
    private bool installPermissionPopupOpen;
    private bool requestInstallPermissionPopup;
    private string pendingInstallPermissionSourceUrl = string.Empty;
    private bool pendingInstallPermissionAcknowledgementChecked;

    private void TryStartSelectedInstall(MarketplacePlugin plugin)
    {
        var concerns = MarketplacePermissionRules.FindBlockedCapabilities(plugin, configuration);
        if (concerns.Count == 0)
        {
            StartSelectedInstall(plugin);
            return;
        }

        pendingInstallPermissionSourceUrl = plugin.SourceUrl;
        pendingInstallPermissionAcknowledgementChecked = false;
        installPopupOpen = false;
        installPermissionPopupOpen = true;
        requestInstallPermissionPopup = true;
        ImGui.CloseCurrentPopup();
    }

    private void DrawInstallPermissionModal(int currentApi, Version currentDalamudVersion)
    {
        if (!installPermissionPopupOpen || pendingInstall is null)
            return;

        var keepOpen = installPermissionPopupOpen;
        ImGui.SetNextWindowSize(UiModalSize(590f, 0f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal(
                InstallPermissionPopupId,
                ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoCollapse | ImGuiWindowFlags.AlwaysAutoResize))
        {
            installPermissionPopupOpen = keepOpen;
            return;
        }

        if (DrawOmegaModalHeader("Check before installing", "install-permissions"))
        {
            ReturnFromInstallPermissionReview();
            ImGui.EndPopup();
            return;
        }

        var plugin = pendingInstall;
        var selected = GetInstallCandidates(plugin.InternalName, currentApi, currentDalamudVersion)
            .FirstOrDefault(x => NormalizeUrl(x.SourceUrl)
                .Equals(NormalizeUrl(pendingInstallPermissionSourceUrl), StringComparison.OrdinalIgnoreCase));
        if (selected is null)
        {
            ImGui.TextWrapped("This plugin package is no longer available. Go back and choose a repository again.");
            if (ImGui.Button("Back", Ui(100f, 34f)))
                ReturnFromInstallPermissionReview();
            installPermissionPopupOpen = keepOpen && installPermissionPopupOpen;
            ImGui.EndPopup();
            return;
        }

        var concerns = MarketplacePermissionRules.FindBlockedCapabilities(selected, configuration);
        if (concerns.Count == 0)
        {
            // A setting may have changed while the dialog was open. Do not keep a stale warning up.
            StartSelectedInstall(selected);
            installPermissionPopupOpen = false;
            ImGui.EndPopup();
            return;
        }

        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.24f, 0.12f, 0.025f, 0.90f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.88f, 0.50f, 0.12f, 0.92f));
        var panelHeight = Ui(76f + (concerns.Count * 54f));
        ImGui.BeginChild("install-permission-summary", new Vector2(0f, panelHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
        ImGui.TextWrapped($"{selected.Name} can do things you asked Omega to warn you about.");
        ImGui.Spacing();
        foreach (var concern in concerns)
        {
            ImGui.PushFont(UiBuilder.IconFontFixedWidth);
            ImGui.TextUnformatted(FontAwesomeIcon.ExclamationTriangle.ToIconString());
            ImGui.PopFont();
            ImGui.SameLine(0f, Ui(8f));
            ImGui.BeginGroup();
            ImGui.TextUnformatted(concern.Label);
            ImGui.TextDisabled(concern.Explanation);
            ImGui.EndGroup();
        }
        ImGui.EndChild();
        ImGui.PopStyleColor(2);

        ImGui.Spacing();
        ImGui.TextWrapped("Omega is stopping here because of your install preferences. This does not mean the plugin is malicious.");
        ImGui.TextDisabled("Omega can warn before install, but it cannot remove these abilities after Dalamud loads a plugin.");
        ImGui.Spacing();
        ImGui.Checkbox($"Install {selected.Name} anyway", ref pendingInstallPermissionAcknowledgementChecked);

        ImGui.Spacing();
        if (ImGui.Button("Back", Ui(100f, 34f)))
        {
            ReturnFromInstallPermissionReview();
            ImGui.EndPopup();
            return;
        }

        ImGui.SameLine();
        if (!pendingInstallPermissionAcknowledgementChecked)
            ImGui.BeginDisabled();
        if (ImGui.Button("Install anyway", Ui(145f, 34f)) && pendingInstallPermissionAcknowledgementChecked)
        {
            installPermissionPopupOpen = false;
            pendingInstallPermissionAcknowledgementChecked = false;
            ImGui.CloseCurrentPopup();
            StartSelectedInstall(selected);
            ImGui.EndPopup();
            return;
        }
        if (!pendingInstallPermissionAcknowledgementChecked)
            ImGui.EndDisabled();

        installPermissionPopupOpen = keepOpen && installPermissionPopupOpen;
        ImGui.EndPopup();
    }

    private void ReturnFromInstallPermissionReview()
    {
        installPermissionPopupOpen = false;
        pendingInstallPermissionAcknowledgementChecked = false;
        pendingInstallPermissionSourceUrl = string.Empty;
        ImGui.CloseCurrentPopup();
        if (pendingInstall is not null)
        {
            installPopupOpen = true;
            requestInstallPopup = true;
        }
    }
}
