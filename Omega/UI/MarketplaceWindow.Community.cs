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
    private const string OmegaClientGitHubUrl = "https://github.com/dalagab/omega/tree/main";
    private const string SigmaScopeGitHubUrl = "https://github.com/dalagab/omega/tree/sigmascope";
    private const string DeltaScopeGitHubUrl = "https://github.com/dalagab/omega/tree/deltascope";
    private const string RiftGitHubUrl = "https://github.com/dalagab/omega/tree/rift";
    private const string OmegaDiscordUrl = "https://discord.gg/rMBHbJTjp";

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
            "main",
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
