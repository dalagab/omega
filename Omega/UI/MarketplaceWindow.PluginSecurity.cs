using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void DrawProductSecurity(MarketplacePlugin plugin)
    {
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();
        ImGui.TextUnformatted("Security");
        ImGui.Spacing();

        if (string.IsNullOrWhiteSpace(plugin.SecurityStatus))
        {
            DrawDiscoverTextBadge("Not yet scanned", new Vector4(0.24f, 0.25f, 0.27f, 0.94f));
            ImGui.SameLine(0f, 10f);
            ImGui.TextDisabled("This exact catalog artifact has not been processed by Omega's static scanner yet.");
            DrawSecurityDisclaimer();
            return;
        }

        if (!plugin.HasCompletedSecurityScan)
        {
            DrawDiscoverTextBadge("Scan incomplete", new Vector4(0.46f, 0.25f, 0.08f, 0.96f));
            if (!string.IsNullOrWhiteSpace(plugin.SecurityError))
            {
                ImGui.Spacing();
                ImGui.TextWrapped(plugin.SecurityError);
            }
            DrawSecurityDisclaimer();
            return;
        }

        DrawSecuritySeverityBadge(plugin.SecurityHighestSeverity);
        ImGui.SameLine(0f, 10f);
        ImGui.TextDisabled(SecurityCountSummary(plugin));

        if (plugin.SecurityScannedAtUtc is { } scanned)
            ImGui.TextDisabled($"Scanned {scanned.ToLocalTime():g}  •  Scanner {plugin.SecurityScannerVersion}");
        if (!string.IsNullOrWhiteSpace(plugin.SecurityArtifactSha256))
            ImGui.TextDisabled($"Artifact SHA-256: {ShortHash(plugin.SecurityArtifactSha256)}");

        if (plugin.SecurityCapabilities.Count > 0)
        {
            ImGui.Spacing();
            ImGui.TextUnformatted("Observed capabilities");
            foreach (var capability in plugin.SecurityCapabilities.Take(12))
            {
                ImGui.Bullet();
                ImGui.SameLine();
                ImGui.TextUnformatted(capability);
            }
        }

        if (plugin.SecurityFindings.Count > 0 && ImGui.TreeNode($"View findings ({plugin.SecurityFindings.Count})##security-findings-{plugin.InternalName}"))
        {
            foreach (var finding in plugin.SecurityFindings.Take(20))
                DrawSecurityFinding(finding);
            ImGui.TreePop();
        }

        ImGui.Spacing();
        if (plugin.SecuritySourceAvailable)
        {
            var commit = string.IsNullOrWhiteSpace(plugin.SecuritySourceCommit) ? "unknown commit" : ShortHash(plugin.SecuritySourceCommit);
            ImGui.TextDisabled($"Public source inspected separately: {commit}");
            if (!plugin.SecuritySourceToBinaryVerified)
                ImGui.TextDisabled("Source-to-binary correspondence has not been verified.");
        }
        else
        {
            ImGui.TextDisabled("No corresponding public GitHub source was inspected for this scan.");
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

    private static string ShortHash(string value)
        => value.Length <= 12 ? value : value[..12];

    private static void DrawSecurityDisclaimer()
    {
        ImGui.Spacing();
        ImGui.TextDisabled("Static analysis reports observed capabilities and indicators. No findings is not proof that a plugin is safe.");
    }
}
