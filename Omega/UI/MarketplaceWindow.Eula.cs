using System.Diagnostics;
using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private const string EulaPopupId = "Omega End User License Agreement###DalagabOmegaEula";
    private const string ProjectGitHubUrl = "https://github.com/dalagab/omega";
    private const int EulaAcceptanceDelaySeconds = 15;

    private bool eulaScrolledToEnd;

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
            eulaScrolledToEnd = false;
            requestEulaPopup = true;
        }

        OpenRequestedPopups();
        DrawEulaModal(requiredAcceptance: true);
    }

    private void DrawSettingsEulaShortcut()
    {
        if (ImGui.Button("View EULA"))
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
        ImGui.SetNextWindowSize(UiModalSize(900f, 720f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal(EulaPopupId, ref keepOpen, ImGuiWindowFlags.NoCollapse | ImGuiWindowFlags.NoTitleBar))
        {
            if (!keepOpen && !requiredAcceptance)
                eulaReviewOpen = false;
            return;
        }

        if (DrawOmegaModalHeader("End User License Agreement", "eula", allowClose: !requiredAcceptance, showMark: false))
        {
            eulaReviewOpen = false;
            ImGui.CloseCurrentPopup();
            ImGui.EndPopup();
            return;
        }

        DrawEulaRiskSummary();
        ImGui.Spacing();
        ImGui.Separator();

        var footerHeight = Ui(requiredAcceptance ? 112f : 58f);
        ImGui.BeginChild("omega-eula-document", new Vector2(0f, -footerHeight), true, ImGuiWindowFlags.AlwaysVerticalScrollbar);
        DrawEulaDocument();
        if (requiredAcceptance)
        {
            var scrollMax = ImGui.GetScrollMaxY();
            // Fail closed on the first layout frame, where ImGui may not have a previous content
            // height yet. The bundled agreement is intentionally scrollable, so only a real
            // positive scroll range can satisfy the first-use reading gate.
            if (scrollMax > Ui(1f) && ImGui.GetScrollY() >= scrollMax - Ui(8f))
                eulaScrolledToEnd = true;
        }
        ImGui.EndChild();

        ImGui.Separator();
        if (requiredAcceptance)
            DrawEulaAcceptanceActions();
        else
            DrawEulaReviewActions();

        ImGui.EndPopup();
    }

    private static void DrawEulaRiskSummary()
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.11f, 0.075f, 0.025f, 0.76f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.72f, 0.47f, 0.12f, 0.76f));
        ImGui.BeginChild("omega-eula-risk-summary", Ui(0f, 96f), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
        ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.98f, 0.78f, 0.32f, 1f));
        ImGui.TextUnformatted("Third-party plugins are executable software");
        ImGui.PopStyleColor();
        ImGui.TextWrapped("Plugins can access game data and resources available to your Windows account, and their use can put your FINAL FANTASY XIV account at risk. Omega helps you review a plugin; it cannot make third-party code inherently safe.");
        ImGui.EndChild();
        ImGui.PopStyleColor(2);
    }

    private void DrawEulaDocument()
    {
        var emphasizedIndex = 0;
        foreach (var rawLine in eulaLines)
        {
            var line = rawLine.TrimEnd();
            var trimmed = line.Trim();
            if (trimmed.Length == 0)
            {
                ImGui.Dummy(Ui(1f, 6f));
                continue;
            }

            if (trimmed.StartsWith("# ", StringComparison.Ordinal))
            {
                ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.35f, 0.86f, 0.75f, 1f));
                ImGui.TextWrapped(StripMarkdown(trimmed[2..]));
                ImGui.PopStyleColor();
                ImGui.Dummy(Ui(1f, 4f));
                ImGui.Separator();
                ImGui.Dummy(Ui(1f, 6f));
                continue;
            }

            if (trimmed.StartsWith("## ", StringComparison.Ordinal))
            {
                DrawEulaSectionHeading(StripMarkdown(trimmed[3..]));
                continue;
            }

            if (IsWholeLineEmphasis(trimmed, out var emphasized))
            {
                DrawEulaEmphasis(emphasized, emphasizedIndex++);
                continue;
            }

            if (trimmed.StartsWith("- ", StringComparison.Ordinal))
            {
                DrawEulaBullet(StripMarkdown(trimmed[2..]));
                continue;
            }

            if (TrySplitNumberedEulaLine(trimmed, out var number, out var numberedText))
            {
                DrawEulaNumbered(number, StripMarkdown(numberedText));
                continue;
            }

            if (trimmed.Equals(ProjectGitHubUrl, StringComparison.OrdinalIgnoreCase))
            {
                // The project destination is exposed once, consistently, in the footer icon row.
                continue;
            }

            ImGui.PushTextWrapPos(ImGui.GetCursorPosX() + Math.Max(Ui(320f), ImGui.GetContentRegionAvail().X - Ui(8f)));
            ImGui.TextWrapped(StripMarkdown(trimmed));
            ImGui.PopTextWrapPos();
            ImGui.Dummy(Ui(1f, 3f));
        }
    }

    private static void DrawEulaSectionHeading(string title)
    {
        ImGui.Dummy(Ui(1f, 10f));
        var start = ImGui.GetCursorScreenPos();
        var markerMax = start + Ui(3f, 22f);
        ImGui.GetWindowDrawList().AddRectFilled(
            start,
            markerMax,
            ImGui.ColorConvertFloat4ToU32(new Vector4(0.08f, 0.58f, 0.59f, 0.92f)),
            Ui(2f));
        var cursor = ImGui.GetCursorPos();
        ImGui.SetCursorPosX(cursor.X + Ui(12f));
        ImGui.TextUnformatted(title);
        ImGui.SetCursorPosX(cursor.X);
        ImGui.Dummy(Ui(1f, 5f));
    }

    private static void DrawEulaEmphasis(string text, int index)
    {
        ImGui.PushID(index);
        ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.98f, 0.74f, 0.30f, 1f));
        ImGui.TextWrapped(text);
        ImGui.PopStyleColor();
        ImGui.Dummy(Ui(1f, 5f));
        ImGui.PopID();
    }

    private static void DrawEulaBullet(string text)
    {
        var startX = ImGui.GetCursorPosX();
        ImGui.Bullet();
        ImGui.SameLine(0f, Ui(7f));
        ImGui.PushTextWrapPos(startX + Math.Max(Ui(300f), ImGui.GetContentRegionAvail().X));
        ImGui.TextWrapped(text);
        ImGui.PopTextWrapPos();
        ImGui.Dummy(Ui(1f, 2f));
    }

    private static void DrawEulaNumbered(string number, string text)
    {
        var startX = ImGui.GetCursorPosX();
        ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.35f, 0.86f, 0.75f, 1f));
        ImGui.TextUnformatted($"{number}.");
        ImGui.PopStyleColor();
        ImGui.SameLine(0f, Ui(8f));
        ImGui.PushTextWrapPos(startX + Math.Max(Ui(300f), ImGui.GetContentRegionAvail().X));
        ImGui.TextWrapped(text);
        ImGui.PopTextWrapPos();
        ImGui.Dummy(Ui(1f, 3f));
    }

    private void DrawEulaAcceptanceActions()
    {
        var openedAt = eulaOpenedAtUtc ?? DateTimeOffset.UtcNow;
        var elapsed = DateTimeOffset.UtcNow - openedAt;
        var remaining = Math.Max(0, (int)Math.Ceiling(EulaAcceptanceDelaySeconds - elapsed.TotalSeconds));
        var canAccept = eulaDocumentAvailable && eulaScrolledToEnd && remaining <= 0;

        if (!eulaDocumentAvailable)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.96f, 0.30f, 0.24f, 1f));
            ImGui.TextWrapped("The EULA document is unavailable. Omega fails closed and cannot record acceptance.");
            ImGui.PopStyleColor();
        }
        else if (!eulaScrolledToEnd)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.95f, 0.64f, 0.20f, 1f));
            ImGui.TextUnformatted("Read the agreement and scroll to the end to continue.");
            ImGui.PopStyleColor();
        }
        else if (remaining > 0)
        {
            ImGui.TextDisabled($"You reached the end. Accept becomes available in {remaining} second{(remaining == 1 ? string.Empty : "s")}.");
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.34f, 0.82f, 0.56f, 1f));
            ImGui.TextUnformatted("You reached the end of the agreement. You can now accept or decline.");
            ImGui.PopStyleColor();
        }

        ImGui.Spacing();
        var acceptLabel = !eulaDocumentAvailable
            ? "EULA unavailable"
            : !eulaScrolledToEnd
                ? "Scroll to end"
                : remaining > 0
                    ? $"Accept ({remaining})"
                    : "Accept";

        var actionY = ImGui.GetCursorPosY();
        DrawEulaFooterLinks();

        var declineWidth = Ui(198f);
        var acceptWidth = Ui(150f);
        var gap = Ui(10f);
        var actionWidth = declineWidth + gap + acceptWidth;
        var actionX = Math.Max(ImGui.GetCursorPosX(), ImGui.GetWindowContentRegionMax().X - actionWidth);
        ImGui.SetCursorPos(new Vector2(actionX, actionY));
        if (ImGui.Button("Decline / Disable Omega", new Vector2(declineWidth, Ui(34f))))
            DeclineEula();

        ImGui.SameLine(0f, gap);
        if (!canAccept)
            ImGui.BeginDisabled();
        if (ImGui.Button(acceptLabel, new Vector2(acceptWidth, Ui(34f))) && canAccept)
            AcceptEula();
        if (!canAccept)
            ImGui.EndDisabled();
    }

    private void DrawEulaReviewActions()
    {
        var actionY = ImGui.GetCursorPosY();
        DrawEulaFooterLinks();
        var status = configuration.EulaAcceptedAtUtc is { } acceptedAt
            ? $"Accepted {acceptedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}"
            : "No acceptance timestamp is stored.";
        var width = ImGui.CalcTextSize(status).X;
        ImGui.SetCursorPos(new Vector2(
            Math.Max(ImGui.GetCursorPosX(), ImGui.GetWindowContentRegionMax().X - width),
            actionY + Ui(6f)));
        ImGui.TextDisabled(status);
    }

    private void DrawEulaFooterLinks()
    {
        if (DrawApplicationIconButton(
                Dalamud.Interface.FontAwesomeIcon.CodeBranch,
                "eula-github",
                "Open Omega on GitHub",
                false))
        {
            OpenProjectGitHub();
        }

        ImGui.SameLine(0f, Ui(5f));
        if (DrawApplicationIconButton(
                Dalamud.Interface.FontAwesomeIcon.Comments,
                "eula-discord",
                "Join the Omega Discord",
                false))
        {
            OpenExternalCommunityUrl("the Omega Discord", OmegaDiscordUrl);
        }
    }

    private void AcceptEula()
    {
        configuration.EulaAccepted = true;
        configuration.EulaAcceptedAtUtc = DateTimeOffset.UtcNow;
        configuration.Save();
        eulaRequiredOpen = false;
        eulaOpenedAtUtc = null;
        eulaScrolledToEnd = false;

        if (!configuration.TutorialCompleted)
            StartTutorial();
        else
            ImGui.CloseCurrentPopup();
    }

    private void DeclineEula()
    {
        eulaRequiredOpen = false;
        eulaOpenedAtUtc = null;
        eulaScrolledToEnd = false;
        IsOpen = false;
        ImGui.CloseCurrentPopup();
        disableOmegaAfterEulaDecline();
    }

    private static bool IsWholeLineEmphasis(string value, out string text)
    {
        text = string.Empty;
        if (value.Length < 4 || !value.StartsWith("**", StringComparison.Ordinal) || !value.EndsWith("**", StringComparison.Ordinal))
            return false;
        text = StripMarkdown(value);
        return !string.IsNullOrWhiteSpace(text);
    }

    private static bool TrySplitNumberedEulaLine(string value, out string number, out string text)
    {
        number = string.Empty;
        text = string.Empty;
        var dot = value.IndexOf('.');
        if (dot <= 0 || dot > 2)
            return false;
        var prefix = value[..dot];
        if (!prefix.All(char.IsDigit) || dot + 1 >= value.Length || !char.IsWhiteSpace(value[dot + 1]))
            return false;
        number = prefix;
        text = value[(dot + 1)..].TrimStart();
        return true;
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
