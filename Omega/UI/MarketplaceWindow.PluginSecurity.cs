using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private readonly record struct PluginSecurityVisual(
        FontAwesomeIcon Icon,
        Vector4 IconColor,
        Vector4 BadgeColor,
        string Label,
        string Tooltip);

    private static PluginSecurityVisual ResolvePluginSecurityVisual(MarketplacePlugin plugin)
    {
        if (string.IsNullOrWhiteSpace(plugin.SecurityStatus))
        {
            return new PluginSecurityVisual(
                FontAwesomeIcon.Question,
                new Vector4(0.46f, 0.48f, 0.52f, 1f),
                new Vector4(0.24f, 0.25f, 0.27f, 0.94f),
                "Not yet scanned",
                "Not yet scanned: no completed Omega static security scan is available for this repository package.");
        }

        if (!plugin.HasCompletedSecurityScan)
        {
            var tooltip = "Scan incomplete: Omega does not have a completed static security result for this repository package.";
            if (!string.IsNullOrWhiteSpace(plugin.SecurityError))
                tooltip += $" {plugin.SecurityError}";
            return new PluginSecurityVisual(
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.94f, 0.43f, 0.10f, 1f),
                new Vector4(0.46f, 0.25f, 0.08f, 0.96f),
                "Scan incomplete",
                tooltip);
        }

        return ResolveCompletedSecurityVisual(plugin.SecurityHighestSeverity);
    }

    private static PluginSecurityVisual ResolveCompletedSecurityVisual(string severity)
    {
        var normalized = (severity ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            "critical" => new PluginSecurityVisual(
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.92f, 0.12f, 0.15f, 1f),
                new Vector4(0.55f, 0.08f, 0.10f, 0.96f),
                "Critical",
                "Critical: the completed static scan contains at least one critical finding."),
            "high" => new PluginSecurityVisual(
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.90f, 0.28f, 0.12f, 1f),
                new Vector4(0.48f, 0.16f, 0.08f, 0.96f),
                "High",
                "High: the completed static scan contains at least one high-severity finding."),
            "caution" or "medium" => new PluginSecurityVisual(
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.94f, 0.58f, 0.12f, 1f),
                new Vector4(0.43f, 0.31f, 0.07f, 0.96f),
                "Medium",
                "Medium: the completed static scan contains at least one caution-level finding."),
            "informational" or "low" => new PluginSecurityVisual(
                FontAwesomeIcon.InfoCircle,
                new Vector4(0.18f, 0.54f, 0.86f, 1f),
                new Vector4(0.08f, 0.30f, 0.40f, 0.96f),
                "Low",
                "Low: the completed static scan contains informational findings only."),
            "none" or "" => new PluginSecurityVisual(
                FontAwesomeIcon.InfoCircle,
                new Vector4(0.20f, 0.72f, 0.42f, 1f),
                new Vector4(0.10f, 0.34f, 0.22f, 0.96f),
                "No findings",
                "No findings were observed by the completed static scan."),
            _ => new PluginSecurityVisual(
                FontAwesomeIcon.InfoCircle,
                new Vector4(0.20f, 0.72f, 0.42f, 1f),
                new Vector4(0.10f, 0.34f, 0.22f, 0.96f),
                "Scanned",
                "A completed Omega static security scan is available for this repository package."),
        };
    }

    private static void DrawPluginSecurityScanIndicator(MarketplacePlugin plugin, float size)
    {
        var visual = ResolvePluginSecurityVisual(plugin);
        DrawPluginFontAwesomeRiskIcon(visual.Icon, visual.IconColor, visual.Tooltip, size);
    }

    private void DrawProductSecuritySummary(MarketplacePlugin plugin)
    {
        // The product hero and every marketplace card intentionally consume the same exact-variant
        // security visual. This prevents Spotlight from aggregating another repository's scan and
        // then showing a different state after the user opens the product page.
        var visual = ResolvePluginSecurityVisual(plugin);
        DrawPluginFontAwesomeRiskIcon(visual.Icon, visual.IconColor, visual.Tooltip, 20f);
        ImGui.SameLine(0f, 8f);
        DrawDiscoverTextBadge(visual.Label, visual.BadgeColor);
    }

    private void DrawProductSecurity(MarketplacePlugin plugin)
    {
        if (!plugin.HasCompletedSecurityScan)
            return;

        DrawProductSectionHeading("Security details");

        ImGui.Indent(14f);
        DrawSecuritySeverityBadge(plugin.SecurityHighestSeverity);
        if (plugin.SecurityScannedAtUtc is { } scanned)
        {
            ImGui.SameLine(0f, 10f);
            ImGui.TextDisabled($"Scanned {scanned.ToLocalTime():g}");
        }
        ImGui.TextDisabled(SecurityCountSummary(plugin));

        if (plugin.SecurityCapabilities.Count > 0)
        {
            ImGui.Dummy(new Vector2(1f, 10f));
            ImGui.TextUnformatted("Observed capabilities");
            ImGui.TextDisabled("What the scanner found the package capable of accessing or invoking.");
            ImGui.Spacing();
            DrawSecurityBulletList(plugin.SecurityCapabilities.Take(12));
        }

        if (plugin.SecurityAutomationCapabilities.Count > 0)
        {
            ImGui.Dummy(new Vector2(1f, 12f));
            ImGui.TextUnformatted("Automation");
            ImGui.TextDisabled(AutomationLevelLabel(plugin.SecurityAutomationLevel));
            ImGui.Spacing();
            foreach (var capability in plugin.SecurityAutomationCapabilities.Take(10))
            {
                var qualifiers = new List<string>();
                if (!string.IsNullOrWhiteSpace(capability.Confidence))
                    qualifiers.Add($"confidence {capability.Confidence}");
                if (capability.Reachable)
                    qualifiers.Add("reachable from plugin entry/callback code");
                if (capability.Indirect)
                    qualifiers.Add("via IPC");
                var suffix = qualifiers.Count == 0 ? string.Empty : $" — {string.Join(", ", qualifiers)}";
                DrawSecurityBullet($"{capability.Label}{suffix}");
            }
        }

        if (plugin.SecurityFindings.Count > 0)
        {
            ImGui.Dummy(new Vector2(1f, 12f));
            if (ImGui.TreeNode($"Detailed findings ({plugin.SecurityFindings.Count})##security-findings-{plugin.InternalName}"))
            {
                foreach (var finding in plugin.SecurityFindings.Take(20))
                    DrawSecurityFinding(finding);
                ImGui.TreePop();
            }
        }

        ImGui.Dummy(new Vector2(1f, 12f));
        ImGui.Separator();
        ImGui.Spacing();
        if (plugin.SecuritySourceAvailable)
        {
            ImGui.TextDisabled("Public source was also inspected.");
            if (!plugin.SecuritySourceToBinaryVerified)
                ImGui.TextDisabled("The published package was not verified to match that source.");
        }
        else
        {
            ImGui.TextDisabled("No public source was available for this scan.");
        }
        DrawSecurityDisclaimer();
        ImGui.Unindent(14f);
    }

    private static void DrawSecurityBulletList(IEnumerable<string> values)
    {
        foreach (var value in values.Where(x => !string.IsNullOrWhiteSpace(x)))
            DrawSecurityBullet(value);
    }

    private static void DrawSecurityBullet(string value)
    {
        var x = ImGui.GetCursorPosX();
        ImGui.TextDisabled("•");
        ImGui.SameLine(0f, 8f);
        ImGui.PushTextWrapPos(ImGui.GetCursorPosX() + Math.Max(280f, Math.Min(900f, ImGui.GetContentRegionAvail().X)));
        ImGui.TextWrapped(value);
        ImGui.PopTextWrapPos();
        ImGui.SetCursorPosX(x);
    }

    private static void DrawSecurityFinding(MarketplaceSecurityFinding finding)
    {
        ImGui.Spacing();
        ImGui.TextUnformatted($"[{finding.Severity.ToUpperInvariant()}] {finding.Title}");
        if (!string.IsNullOrWhiteSpace(finding.Description))
            ImGui.TextWrapped(finding.Description);
        if (finding.Evidence.Count == 0)
            return;
        ImGui.Indent(14f);
        foreach (var evidence in finding.Evidence.Take(4))
            ImGui.TextDisabled(evidence);
        ImGui.Unindent(14f);
    }

    private static void DrawSecuritySeverityBadge(string severity)
    {
        var visual = ResolveCompletedSecurityVisual(severity);
        DrawDiscoverTextBadge(visual.Label, visual.BadgeColor);
    }

    private static string SecurityCountSummary(MarketplacePlugin plugin)
        => $"Findings: {plugin.SecurityCriticalCount} critical  •  {plugin.SecurityHighCount} high  •  {plugin.SecurityCautionCount} medium  •  {plugin.SecurityInformationalCount} low";

    private static string AutomationLevelLabel(string level)
        => (level ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "observational" => "Observational only",
            "ui-automation" => "Game UI/menu automation",
            "character-automation" => "Character control",
            "full-gameplay-automation" => "Full gameplay automation",
            _ => "None detected",
        };

    private static void DrawSecurityDisclaimer()
    {
        ImGui.Spacing();
        ImGui.TextDisabled("Static analysis reports observed capabilities and indicators. No findings is not proof that a plugin is safe.");
    }
}
