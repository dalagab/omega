using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void DrawProductSecuritySummary(MarketplacePlugin plugin)
    {
        if (string.IsNullOrWhiteSpace(plugin.SecurityStatus))
        {
            DrawDiscoverTextBadge("Not yet scanned", new Vector4(0.24f, 0.25f, 0.27f, 0.94f));
            return;
        }

        if (!plugin.HasCompletedSecurityScan)
        {
            DrawDiscoverTextBadge("Scan incomplete", new Vector4(0.46f, 0.25f, 0.08f, 0.96f));
            if (ImGui.IsItemHovered() && !string.IsNullOrWhiteSpace(plugin.SecurityError))
                ImGui.SetTooltip(plugin.SecurityError);
            return;
        }

        // Keep the hero summary intentionally terse. Scan time, counts and provenance belong
        // in the detailed security section below where they have enough room to read well.
        DrawSecuritySeverityBadge(plugin.SecurityHighestSeverity);
    }

    private void DrawProductSecurity(MarketplacePlugin plugin)
    {
        if (!plugin.HasCompletedSecurityScan)
            return;

        DrawProductSectionHeading(
            "Security details",
            "Static analysis summary, capabilities and evidence");

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
        var normalized = (severity ?? string.Empty).Trim().ToLowerInvariant();
        var color = normalized switch
        {
            "critical" => new Vector4(0.55f, 0.08f, 0.10f, 0.96f),
            "high" => new Vector4(0.48f, 0.16f, 0.08f, 0.96f),
            "caution" => new Vector4(0.43f, 0.31f, 0.07f, 0.96f),
            "informational" => new Vector4(0.08f, 0.30f, 0.40f, 0.96f),
            _ => new Vector4(0.10f, 0.34f, 0.22f, 0.96f),
        };
        var label = normalized switch
        {
            "critical" => "Critical",
            "high" => "High",
            "caution" => "Medium",
            "informational" => "Low",
            "none" or "" => "No findings",
            _ => "Scanned",
        };
        DrawDiscoverTextBadge(label, color);
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
