using System.Diagnostics;
using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;

namespace Dalagab.Omega;

/// <summary>
/// Centralizes Omega's public project/community destinations so About and Settings
/// do not drift to different branch URLs over time.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private const string OmegaClientGitHubUrl = "https://github.com/dalagab/omega/tree/omega";
    private const string SigmaScopeGitHubUrl = "https://github.com/dalagab/omega/tree/sigmascope";
    private const string DeltaScopeGitHubUrl = "https://github.com/dalagab/omega/tree/deltascope";
    private const string RiftGitHubUrl = "https://github.com/dalagab/omega/tree/rift";
    private const string OmegaDiscordUrl = "https://discord.gg/rMBHbJTjp";
    private const string OmegaResetPopupId = "Reset Omega local data###DalagabOmegaResetLocalData";

    private void DrawAboutCommunityShortcuts(float alignX)
    {
        ImGui.SetCursorPosX(alignX);
        if (DrawApplicationIconButton(FontAwesomeIcon.CodeBranch, "about-github", "Open Omega on GitHub", false))
            OpenExternalCommunityUrl("Omega on GitHub", OmegaClientGitHubUrl);

        ImGui.SameLine(0f, Ui(4f));
        if (DrawApplicationIconButton(FontAwesomeIcon.Comments, "about-discord", "Join the Omega Discord", false))
            OpenExternalCommunityUrl("the Omega Discord", OmegaDiscordUrl);
    }

    private void DrawSettingsCommunityTab()
    {
        ImGui.TextDisabled("Project branches");
        ImGui.Spacing();
        DrawCommunityLinkRow(
            FontAwesomeIcon.Star,
            "Omega",
            "Dalamud marketplace client",
            "omega",
            OmegaClientGitHubUrl,
            "omega");
        DrawCommunityLinkRow(
            FontAwesomeIcon.Search,
            "SigmaScope",
            "Production static security analysis and evidence pipeline",
            "sigmascope",
            SigmaScopeGitHubUrl,
            "sigmascope");
        DrawCommunityLinkRow(
            FontAwesomeIcon.List,
            "DeltaScope",
            "Local, read-only investigation and SRL authoring workbench",
            "deltascope",
            DeltaScopeGitHubUrl,
            "deltascope");
        DrawCommunityLinkRow(
            FontAwesomeIcon.Flask,
            "Interdimensional Rift",
            "Isolated runtime observation and sandbox research",
            "rift",
            RiftGitHubUrl,
            "rift");

        ImGui.Spacing();
        ImGui.TextDisabled("Talk to us");
        ImGui.Spacing();
        DrawCommunityLinkRow(
            FontAwesomeIcon.Comments,
            "Omega Discord",
            "Help, discussion, feedback and project community",
            "discord.gg/rMBHbJTjp",
            OmegaDiscordUrl,
            "discord");

        DrawLocalDataResetSettings();
    }

    private void DrawLocalDataResetSettings()
    {
        ImGui.Dummy(Ui(1f, 12f));
        ImGui.Separator();
        ImGui.Dummy(Ui(1f, 10f));
        ImGui.TextUnformatted("Local data");
        ImGui.TextWrapped("Return Omega to the same local state as a new installation. Installed plugins, their configuration, and repositories registered in Dalamud are not removed.");
        ImGui.Spacing();

        var resetRequested = OmegaDataResetService.IsRequested(Plugin.PluginInterface.ConfigDirectory.FullName);
        if (resetRequested)
        {
            ImGui.TextColored(new Vector4(0.95f, 0.64f, 0.20f, 1f), "Reset queued — reload Omega to complete it.");
            return;
        }

        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.44f, 0.08f, 0.10f, 0.94f));
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.58f, 0.10f, 0.13f, 1f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive, new Vector4(0.34f, 0.06f, 0.08f, 1f));
        if (ImGui.Button("Delete all Omega local data…", Ui(220f, 32f)))
            ImGui.OpenPopup(OmegaResetPopupId);
        ImGui.PopStyleColor(3);

        DrawLocalDataResetConfirmation();
    }

    private void DrawLocalDataResetConfirmation()
    {
        var keepOpen = true;
        ImGui.SetNextWindowSize(UiModalSize(520f, 0f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal(
                OmegaResetPopupId,
                ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoCollapse | ImGuiWindowFlags.AlwaysAutoResize))
        {
            return;
        }

        if (DrawOmegaModalHeader("Reset Omega", "reset-local-data"))
        {
            ImGui.CloseCurrentPopup();
            ImGui.EndPopup();
            return;
        }

        ImGui.TextWrapped("This deletes Omega's settings, EULA/tutorial state, acknowledgements, marketplace database, image cache, and local history on the next Omega reload.");
        ImGui.Spacing();
        ImGui.TextDisabled("It does not uninstall plugins, delete plugin configuration, or remove repositories from Dalamud.");
        ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.95f, 0.64f, 0.20f, 1f), "After confirming, reload Omega from Dalamud to complete the reset.");
        ImGui.Spacing();

        if (ImGui.Button("Cancel", Ui(100f, 34f)))
        {
            ImGui.CloseCurrentPopup();
            ImGui.EndPopup();
            return;
        }

        ImGui.SameLine();
        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.48f, 0.07f, 0.09f, 0.96f));
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.62f, 0.09f, 0.12f, 1f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive, new Vector4(0.38f, 0.05f, 0.07f, 1f));
        if (ImGui.Button("Delete on reload", Ui(150f, 34f)))
        {
            try
            {
                OmegaDataResetService.Request(Plugin.PluginInterface.ConfigDirectory.FullName);
                operationMessage = "Omega local-data reset queued. Reload Omega from Dalamud to return to a fresh install.";
                settingsOpen = false;
                ImGui.CloseCurrentPopup();
            }
            catch (Exception ex)
            {
                Plugin.Log.Warning(ex, "Omega could not queue its local-data reset.");
                operationMessage = $"Could not queue the Omega reset: {ex.GetBaseException().Message}";
            }
        }
        ImGui.PopStyleColor(3);

        ImGui.EndPopup();
    }

    private void DrawCommunityLinkRow(
        FontAwesomeIcon icon,
        string title,
        string description,
        string location,
        string url,
        string id)
    {
        var rowHeight = Ui(64f);
        var tableFlags = ImGuiTableFlags.SizingStretchProp | ImGuiTableFlags.BordersInnerH;
        if (!ImGui.BeginTable($"omega-community-link-{id}", 3, tableFlags, new Vector2(0f, rowHeight)))
            return;

        ImGui.TableSetupColumn("icon", ImGuiTableColumnFlags.WidthFixed, Ui(36f));
        ImGui.TableSetupColumn("details", ImGuiTableColumnFlags.WidthStretch);
        ImGui.TableSetupColumn("action", ImGuiTableColumnFlags.WidthFixed, Ui(92f));
        ImGui.TableNextRow(ImGuiTableRowFlags.None, rowHeight);

        ImGui.TableSetColumnIndex(0);
        ImGui.SetCursorPosY(ImGui.GetCursorPosY() + Ui(13f));
        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        ImGui.TextDisabled(icon.ToIconString());
        ImGui.PopFont();

        ImGui.TableSetColumnIndex(1);
        ImGui.SetCursorPosY(ImGui.GetCursorPosY() + Ui(5f));
        ImGui.TextUnformatted(title);
        ImGui.TextDisabled(description);
        ImGui.TextDisabled(location);

        ImGui.TableSetColumnIndex(2);
        ImGui.SetCursorPosY(ImGui.GetCursorPosY() + Ui(13f));
        if (ImGui.Button($"Open##community-open-{id}", Ui(78f, 30f)))
            OpenExternalCommunityUrl(title, url);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(url);

        ImGui.EndTable();
    }

    private static void OpenExternalCommunityUrl(string label, string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, $"Omega could not open {label}.");
        }
    }
}
