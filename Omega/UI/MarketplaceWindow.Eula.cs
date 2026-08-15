using System.Diagnostics;
using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private const string EulaPopupId = "Omega End User License Agreement###DalagabOmegaEula";
    private const string ProjectGitHubUrl = "https://github.com/dalagab/omega";
    private const int EulaAcceptanceDelaySeconds = 15;

    private static string[] LoadEulaLines(string path, out bool available)
    {
        try
        {
            available = File.Exists(path);
            return available
                ? File.ReadAllLines(path)
                : ["# Omega End User License Agreement", "", "The EULA document could not be loaded. Close Omega and verify the installation package."];
        }
        catch (Exception ex)
        {
            available = false;
            Plugin.Log.Warning(ex, "Omega could not read its EULA document from {Path}.", path);
            return ["# Omega End User License Agreement", "", "The EULA document could not be loaded. Close Omega and verify the installation package."];
        }
    }

    private void DrawRequiredEulaGate()
    {
        if (!eulaRequiredOpen)
        {
            eulaRequiredOpen = true;
            eulaOpenedAtUtc = DateTimeOffset.UtcNow;
            requestEulaPopup = true;
        }

        OpenRequestedPopups();
        DrawEulaModal(requiredAcceptance: true);
    }

    private void DrawSettingsEulaShortcut()
    {
        if (ImGui.Button("View EULA / Risk Disclosure"))
            OpenEulaFromSettings();
        ImGui.SameLine();
        ImGui.TextDisabled(configuration.EulaAcceptedAtUtc is { } acceptedAt
            ? $"Accepted {acceptedAt.ToLocalTime():yyyy-MM-dd HH:mm}"
            : "Not yet accepted");
    }

    private void OpenEulaFromSettings()
    {
        settingsOpen = false;
        eulaReviewOpen = true;
        requestEulaPopup = true;
        ImGui.CloseCurrentPopup();
    }

    private void DrawEulaReviewModal()
    {
        if (!eulaReviewOpen)
            return;
        DrawEulaModal(requiredAcceptance: false);
    }

    private void DrawEulaModal(bool requiredAcceptance)
    {
        var keepOpen = true;
        ImGui.SetNextWindowSize(new Vector2(860f, 680f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal(EulaPopupId, ref keepOpen, ImGuiWindowFlags.NoCollapse | ImGuiWindowFlags.NoTitleBar))
        {
            if (!keepOpen && !requiredAcceptance)
                eulaReviewOpen = false;
            return;
        }

        if (DrawOmegaModalHeader("End User License Agreement", "eula", allowClose: !requiredAcceptance))
        {
            eulaReviewOpen = false;
            ImGui.CloseCurrentPopup();
            ImGui.EndPopup();
            return;
        }

        ImGui.TextWrapped("Plugins are executable third-party software. They may access game data and your computer, and their use may put your FFXIV account at risk.");
        ImGui.Spacing();
        if (ImGui.Button("Open Omega project on GitHub"))
            OpenProjectGitHub();
        ImGui.SameLine();
        ImGui.TextDisabled(ProjectGitHubUrl);
        ImGui.Separator();

        var footerHeight = requiredAcceptance ? 78f : 58f;
        ImGui.BeginChild("omega-eula-document", new Vector2(0f, -footerHeight), true, ImGuiWindowFlags.AlwaysVerticalScrollbar);
        DrawEulaDocument();
        ImGui.EndChild();

        ImGui.Separator();
        if (requiredAcceptance)
            DrawEulaAcceptanceActions();
        else
            DrawEulaReviewActions();

        ImGui.EndPopup();
    }

    private void DrawEulaDocument()
    {
        foreach (var rawLine in eulaLines)
        {
            var line = rawLine.TrimEnd();
            if (line.Length == 0)
            {
                ImGui.Spacing();
                continue;
            }

            if (line.StartsWith("# ", StringComparison.Ordinal))
            {
                ImGui.TextWrapped(StripMarkdown(line[2..]));
                ImGui.Separator();
                continue;
            }

            if (line.StartsWith("## ", StringComparison.Ordinal))
            {
                ImGui.Spacing();
                ImGui.TextWrapped(StripMarkdown(line[3..]));
                continue;
            }

            if (line.StartsWith("- ", StringComparison.Ordinal))
            {
                ImGui.TextWrapped($"• {StripMarkdown(line[2..])}");
                continue;
            }

            ImGui.TextWrapped(StripMarkdown(line));
        }
    }

    private void DrawEulaAcceptanceActions()
    {
        var openedAt = eulaOpenedAtUtc ?? DateTimeOffset.UtcNow;
        var elapsed = DateTimeOffset.UtcNow - openedAt;
        var remaining = Math.Max(0, (int)Math.Ceiling(EulaAcceptanceDelaySeconds - elapsed.TotalSeconds));
        var canAccept = eulaDocumentAvailable && remaining <= 0;
        var acceptLabel = !eulaDocumentAvailable ? "EULA unavailable" : canAccept ? "Accept" : $"Accept ({remaining})";

        if (!canAccept)
            ImGui.BeginDisabled();
        if (ImGui.Button(acceptLabel, new Vector2(150f, 34f)) && canAccept)
            AcceptEula();
        if (!canAccept)
            ImGui.EndDisabled();

        ImGui.SameLine();
        if (ImGui.Button("Decline / Close Omega", new Vector2(190f, 34f)))
            DeclineEula();

        ImGui.SameLine();
        ImGui.TextDisabled("Acceptance is recorded once and is not reset by routine Omega or catalog updates.");
    }

    private void DrawEulaReviewActions()
    {
        if (configuration.EulaAcceptedAtUtc is { } acceptedAt)
            ImGui.TextDisabled($"Accepted {acceptedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}");
        else
            ImGui.TextDisabled("No acceptance timestamp is stored.");
    }

    private void AcceptEula()
    {
        configuration.EulaAccepted = true;
        configuration.EulaAcceptedAtUtc = DateTimeOffset.UtcNow;
        configuration.Save();
        eulaRequiredOpen = false;
        eulaOpenedAtUtc = null;
        ImGui.CloseCurrentPopup();
    }

    private void DeclineEula()
    {
        eulaRequiredOpen = false;
        eulaOpenedAtUtc = null;
        IsOpen = false;
        ImGui.CloseCurrentPopup();
    }

    private static void OpenProjectGitHub()
    {
        try
        {
            Process.Start(new ProcessStartInfo(ProjectGitHubUrl) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not open its GitHub project page.");
        }
    }

    private static string StripMarkdown(string value)
        => value.Replace("**", string.Empty, StringComparison.Ordinal)
            .Replace("`", string.Empty, StringComparison.Ordinal)
            .Trim();
}
