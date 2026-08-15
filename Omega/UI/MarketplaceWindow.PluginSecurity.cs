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

        DrawSecuritySeverityBadge(plugin.SecurityHighestSeverity);
        ImGui.SameLine(0f, 10f);
        ImGui.TextDisabled(SecurityCountSummary(plugin));
        if (plugin.SecurityScannedAtUtc is { } scanned)
            ImGui.TextDisabled($"Scanned {scanned.ToLocalTime():g}");
    }

    private void DrawProductSecurity(MarketplacePlugin plugin)
    {
        if (!plugin.HasCompletedSecurityScan)
            return;

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();
        ImGui.TextUnformatted("Security details");

        if (plugin.SecurityCapabilities.Count > 0)
        {
            ImGui.Spacing();
            ImGui.TextDisabled("Observed capabilities");
            ImGui.TextWrapped(string.Join("  •  ", plugin.SecurityCapabilities.Take(12)));
        }

        if (plugin.SecurityFindings.Count > 0 &&
            ImGui.TreeNode($"Why these findings were reported ({plugin.SecurityFindings.Count})##security-findings-{plugin.InternalName}"))
        {
            foreach (var finding in plugin.SecurityFindings.Take(20))
                DrawSecurityFinding(finding);
            ImGui.TreePop();
        }

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
            "none" or "" => "No findings observed",
            _ => $"Highest: {normalized}",
        };
        DrawDiscoverTextBadge(label, color);
    }

    private static string SecurityCountSummary(MarketplacePlugin plugin)
        => $"Critical {plugin.SecurityCriticalCount}  •  High {plugin.SecurityHighCount}  •  Caution {plugin.SecurityCautionCount}  •  Info {plugin.SecurityInformationalCount}";

    private static void DrawSecurityDisclaimer()
    {
        ImGui.Spacing();
        ImGui.TextDisabled("Static analysis reports observed capabilities and indicators. No findings is not proof that a plugin is safe.");
    }
}
