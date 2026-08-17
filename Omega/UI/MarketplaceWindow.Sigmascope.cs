using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private readonly record struct SigmascopeVisual(
        FontAwesomeIcon Icon,
        Vector4 IconColor,
        Vector4 BadgeColor,
        string Label,
        string Tooltip);

    private static SigmascopeVisual ResolveSigmascopeVisual(MarketplacePlugin plugin)
    {
        if (string.IsNullOrWhiteSpace(plugin.SecurityStatus))
        {
            return new SigmascopeVisual(
                FontAwesomeIcon.Question,
                new Vector4(0.46f, 0.48f, 0.52f, 1f),
                new Vector4(0.24f, 0.25f, 0.27f, 0.94f),
                "Not yet indexed",
                "Not yet indexed: no completed Sigmascope analysis is available for this repository package.");
        }

        if (!plugin.HasCompletedSecurityScan)
        {
            var tooltip = "Sigmascope analysis is incomplete for this repository package.";
            if (!string.IsNullOrWhiteSpace(plugin.SecurityError))
                tooltip += $" {plugin.SecurityError}";
            return new SigmascopeVisual(
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.94f, 0.43f, 0.10f, 1f),
                new Vector4(0.46f, 0.25f, 0.08f, 0.96f),
                "Analysis incomplete",
                tooltip);
        }

        var staticSeverity = plugin.SecurityHighestSeverity;
        var advisoryRank = plugin.HasKnownAtRiskDependency
            ? Math.Max(SecuritySeverityRank(plugin.SecurityKnownAdvisoryHighestSeverity), SecuritySeverityRank("caution"))
            : 0;
        var effectiveSeverity = advisoryRank > SecuritySeverityRank(staticSeverity)
            ? (SecuritySeverityRank(plugin.SecurityKnownAdvisoryHighestSeverity) > 0 ? plugin.SecurityKnownAdvisoryHighestSeverity : "caution")
            : staticSeverity;
        var visual = ResolveCompletedSigmascopeVisual(effectiveSeverity);
        if (!plugin.HasKnownAtRiskDependency)
            return visual;

        var advisorySeverity = string.IsNullOrWhiteSpace(plugin.SecurityKnownAdvisoryHighestSeverity)
            ? "unknown"
            : plugin.SecurityKnownAdvisoryHighestSeverity;
        var advisoryLabel = plugin.SecurityKnownAdvisoryCount == 1 ? "advisory" : "advisories";
        return visual with
        {
            Tooltip = $"Sigmascope finding level: {visual.Label}. OSV reports {plugin.SecurityKnownAdvisoryCount} known {advisoryLabel} affecting dependency versions used by this plugin package (highest: {advisorySeverity}). Sigmascope static finding level: {ResolveCompletedSigmascopeVisual(staticSeverity).Label}."
        };
    }

    private static int EffectiveSecuritySeverityRank(MarketplacePlugin plugin)
        => Math.Max(
            SecuritySeverityRank(plugin.SecurityHighestSeverity),
            plugin.HasKnownAtRiskDependency
                ? Math.Max(SecuritySeverityRank(plugin.SecurityKnownAdvisoryHighestSeverity), SecuritySeverityRank("caution"))
                : 0);

    /// <summary>
    /// Orders the normalized security severities used by Library posture sorting.
    /// Keep aliases aligned with ResolveCompletedSigmascopeVisual so the summary and badge cannot disagree.
    /// </summary>
    private static int SecuritySeverityRank(string? severity)
        => (severity ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "critical" => 4,
            "high" => 3,
            "caution" or "medium" => 2,
            "informational" or "low" => 1,
            _ => 0,
        };

    private static SigmascopeVisual ResolveCompletedSigmascopeVisual(string severity)
    {
        var normalized = (severity ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            "critical" => new SigmascopeVisual(
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.92f, 0.12f, 0.15f, 1f),
                new Vector4(0.55f, 0.08f, 0.10f, 0.96f),
                "Critical",
                "Critical: the completed Sigmascope analysis contains at least one critical finding."),
            "high" => new SigmascopeVisual(
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.90f, 0.28f, 0.12f, 1f),
                new Vector4(0.48f, 0.16f, 0.08f, 0.96f),
                "High",
                "High: the completed Sigmascope analysis contains at least one high-severity finding."),
            "caution" or "medium" => new SigmascopeVisual(
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.94f, 0.58f, 0.12f, 1f),
                new Vector4(0.43f, 0.31f, 0.07f, 0.96f),
                "Medium",
                "Medium: the completed Sigmascope analysis contains at least one caution-level finding."),
            "informational" or "low" => new SigmascopeVisual(
                FontAwesomeIcon.InfoCircle,
                new Vector4(0.18f, 0.54f, 0.86f, 1f),
                new Vector4(0.08f, 0.30f, 0.40f, 0.96f),
                "Low",
                "Low: the completed Sigmascope analysis contains informational findings only."),
            "none" or "" => new SigmascopeVisual(
                FontAwesomeIcon.InfoCircle,
                new Vector4(0.20f, 0.72f, 0.42f, 1f),
                new Vector4(0.10f, 0.34f, 0.22f, 0.96f),
                "No findings",
                "No findings were observed by the completed Sigmascope analysis."),
            _ => new SigmascopeVisual(
                FontAwesomeIcon.InfoCircle,
                new Vector4(0.20f, 0.72f, 0.42f, 1f),
                new Vector4(0.10f, 0.34f, 0.22f, 0.96f),
                "Indexed",
                "A completed Sigmascope analysis is available for this repository package."),
        };
    }

    private static void DrawPluginSigmascopeIndicator(MarketplacePlugin plugin, float size)
    {
        var visual = ResolveSigmascopeVisual(plugin);
        DrawPluginFontAwesomeRiskIcon(visual.Icon, visual.IconColor, visual.Tooltip, size);
    }

    private void DrawProductSigmascopeSummary(MarketplacePlugin plugin)
    {
        // The product hero and every marketplace card intentionally consume the same exact-variant
        // Sigmascope visual. This prevents Spotlight from aggregating another repository's analysis and
        // then showing a different state after the user opens the product page.
        var visual = ResolveSigmascopeVisual(plugin);
        DrawPluginFontAwesomeRiskIcon(visual.Icon, visual.IconColor, visual.Tooltip, 20f);
        ImGui.SameLine(0f, 8f);
        DrawDiscoverTextBadge(visual.Label, visual.BadgeColor);
        if (plugin.HasKnownAtRiskDependency)
        {
            ImGui.SameLine(0f, 8f);
            DrawKnownRiskBadge(plugin);
        }
        ImGui.SameLine(0f, 8f);
        DrawPublicSourceAvailabilityBadge(plugin);
    }

    private static void DrawPublicSourceAvailabilityBadge(MarketplacePlugin plugin)
    {
        if (plugin.SecuritySourceAvailable)
        {
            DrawDiscoverTextBadge("Source: public source inspected", new Vector4(0.10f, 0.30f, 0.36f, 0.96f));
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(plugin.SecuritySourceToBinaryVerified
                    ? "Public source was inspected and the published package was verified against that source."
                    : "Public source was inspected, but the published package was not verified to match that source.");
            return;
        }

        DrawDiscoverTextBadge("Source: public source unavailable.", new Vector4(0.25f, 0.25f, 0.27f, 0.94f));
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("No public source was available to Sigmascope for this repository package analysis.");
    }

    private static void DrawKnownRiskBadge(MarketplacePlugin plugin)
    {
        DrawDiscoverTextBadge("Known risk", new Vector4(0.58f, 0.08f, 0.11f, 0.96f));
        if (ImGui.IsItemHovered())
        {
            var noun = plugin.SecurityKnownAdvisoryCount == 1 ? "advisory" : "advisories";
            ImGui.SetTooltip($"OSV reports {plugin.SecurityKnownAdvisoryCount} known {noun} affecting dependency versions used by this plugin package. Highest advisory severity: {plugin.SecurityKnownAdvisoryHighestSeverity}.");
        }
    }

    private void DrawProductSigmascope(MarketplacePlugin plugin)
    {
        if (!plugin.HasCompletedSecurityScan)
            return;

        DrawProductSectionHeading(SigmascopeInfo.Name);
        ImGui.TextDisabled(SigmascopeInfo.Description);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(SigmascopeInfo.Lore);

        ImGui.Indent(14f);
        DrawSecuritySeverityBadge(plugin.SecurityHighestSeverity);
        if (plugin.HasKnownAtRiskDependency)
        {
            ImGui.SameLine(0f, 8f);
            DrawKnownRiskBadge(plugin);
        }
        if (plugin.SecurityScannedAtUtc is { } scanned)
        {
            ImGui.SameLine(0f, 10f);
            ImGui.TextDisabled($"Analyzed {scanned.ToLocalTime():g}");
        }
        ImGui.TextDisabled(SecurityCountSummary(plugin));
        if (plugin.HasKnownAtRiskDependency)
        {
            var noun = plugin.SecurityKnownAdvisoryCount == 1 ? "dependency advisory" : "dependency advisories";
            ImGui.TextWrapped($"Known at-risk dependency: OSV reports {plugin.SecurityKnownAdvisoryCount} {noun} affecting component versions used by this package. This contributes to Omega's internal risk score even when that score is not shown numerically.");
        }

        if (plugin.SecurityCapabilities.Count > 0)
        {
            ImGui.Dummy(new Vector2(Ui(1f), Ui(10f)));
            ImGui.TextUnformatted("Observed capabilities");
            ImGui.TextDisabled("What Sigmascope found the package capable of accessing or invoking.");
            ImGui.Spacing();
            DrawSecurityBulletList(plugin.SecurityCapabilities.Take(12));
        }

        if (plugin.SecurityAutomationCapabilities.Count > 0)
        {
            ImGui.Dummy(new Vector2(Ui(1f), Ui(12f)));
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
            ImGui.Dummy(new Vector2(Ui(1f), Ui(12f)));
            if (ImGui.TreeNode($"Detailed findings ({plugin.SecurityFindings.Count})##security-findings-{plugin.InternalName}"))
            {
                foreach (var finding in plugin.SecurityFindings.Take(20))
                    DrawSecurityFinding(finding);
                ImGui.TreePop();
            }
        }

        ImGui.Dummy(new Vector2(Ui(1f), Ui(12f)));
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
            ImGui.TextDisabled("No public source was available to Sigmascope for this analysis.");
        }
        DrawSigmascopeDisclaimer();
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
        ImGui.PushTextWrapPos(ImGui.GetCursorPosX() + Math.Max(Ui(280f), Math.Min(Ui(900f), ImGui.GetContentRegionAvail().X)));
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
        var visual = ResolveCompletedSigmascopeVisual(severity);
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

    private static void DrawSigmascopeDisclaimerPanel()
    {
        const string warning = "Static analysis reports observed capabilities and indicators. No findings is not proof that a plugin is safe.";
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.24f, 0.035f, 0.045f, 0.88f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.82f, 0.16f, 0.20f, 0.92f));
        ImGui.BeginChild("omega-security-disclaimer-panel", new Vector2(0f, Ui(66f)), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
        ImGui.SetCursorPosY(Ui(18f));
        DrawPluginFontAwesomeRiskIcon(
            FontAwesomeIcon.ExclamationTriangle,
            new Vector4(0.98f, 0.28f, 0.31f, 1f),
            warning,
            24f);
        ImGui.SameLine(0f, 10f);
        ImGui.SetCursorPosY(Ui(16f));
        ImGui.PushTextWrapPos(ImGui.GetWindowContentRegionMax().X - 12f);
        ImGui.TextWrapped(warning);
        ImGui.PopTextWrapPos();
        ImGui.EndChild();
        ImGui.PopStyleColor(2);
    }

    private static void DrawSigmascopeDisclaimer()
    {
        ImGui.Spacing();
        ImGui.TextDisabled("Static analysis reports observed capabilities and indicators. No findings is not proof that a plugin is safe.");
    }
}
