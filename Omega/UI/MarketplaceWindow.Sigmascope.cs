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
                "Waiting for analysis",
                "No published analysis for this plugin version and source.");
        }

        if (!plugin.HasCompletedSecurityScan)
        {
            var status = (plugin.SecurityStatus ?? string.Empty).Trim().ToLowerInvariant();
            var failed = status is "failed" or "error";
            var pending = status is "pending" or "queued" or "selected";
            var running = status is "running" or "in-progress" or "in_progress" or "analyzing";
            var label = failed ? "Analysis failed" : running ? "Analysis in progress" : pending ? "Queued for analysis" : "Analysis incomplete";
            var tooltip = failed
                ? "Analysis failed for this plugin version."
                : running
                    ? "Analysis in progress."
                    : pending
                        ? "Queued for analysis."
                        : "Analysis incomplete.";
            if (!string.IsNullOrWhiteSpace(plugin.SecurityError))
                tooltip += $" {plugin.SecurityError}";
            return new SigmascopeVisual(
                FontAwesomeIcon.ExclamationTriangle,
                failed ? new Vector4(0.92f, 0.18f, 0.16f, 1f) : new Vector4(0.94f, 0.43f, 0.10f, 1f),
                failed ? new Vector4(0.50f, 0.10f, 0.10f, 0.96f) : new Vector4(0.46f, 0.25f, 0.08f, 0.96f),
                label,
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
                "At least one critical finding."),
            "high" => new SigmascopeVisual(
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.90f, 0.28f, 0.12f, 1f),
                new Vector4(0.48f, 0.16f, 0.08f, 0.96f),
                "High",
                "At least one high finding."),
            "caution" or "medium" => new SigmascopeVisual(
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.94f, 0.58f, 0.12f, 1f),
                new Vector4(0.43f, 0.31f, 0.07f, 0.96f),
                "Medium",
                "At least one medium finding."),
            "informational" or "low" => new SigmascopeVisual(
                FontAwesomeIcon.InfoCircle,
                new Vector4(0.18f, 0.54f, 0.86f, 1f),
                new Vector4(0.08f, 0.30f, 0.40f, 0.96f),
                "Low",
                "Low-severity findings only."),
            "none" or "" => new SigmascopeVisual(
                FontAwesomeIcon.InfoCircle,
                new Vector4(0.20f, 0.72f, 0.42f, 1f),
                new Vector4(0.10f, 0.34f, 0.22f, 0.96f),
                "No findings",
                "No findings in the published analysis."),
            _ => new SigmascopeVisual(
                FontAwesomeIcon.InfoCircle,
                new Vector4(0.20f, 0.72f, 0.42f, 1f),
                new Vector4(0.10f, 0.34f, 0.22f, 0.96f),
                "Indexed",
                "Published analysis available."),
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
        if (!plugin.HasCompletedSecurityScan)
        {
            DrawDiscoverTextBadge("Review: pending", new Vector4(0.25f, 0.25f, 0.27f, 0.94f));
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("Review coverage pending.");
            return;
        }

        var confidence = plugin.SecuritySourceAttributionConfidence;
        var coverage = ReviewCoverageLabel(plugin);
        var color = confidence >= 70
            ? new Vector4(0.10f, 0.30f, 0.36f, 0.96f)
            : new Vector4(0.25f, 0.25f, 0.27f, 0.94f);
        DrawDiscoverTextBadge($"Review: {coverage}", color);
        if (!ImGui.IsItemHovered())
            return;

        if (confidence <= 0)
        {
            ImGui.SetTooltip("Source attribution unresolved for this version.");
            return;
        }

        var basis = plugin.SecuritySourceAttributionBasis.Count > 0
            ? $" Basis: {string.Join(", ", plugin.SecuritySourceAttributionBasis)}."
            : string.Empty;
        ImGui.SetTooltip($"Source attribution: {confidence}.{basis}");
    }

    private static string ReviewCoverageLabel(MarketplacePlugin plugin)
    {
        if (plugin.SecuritySourceAttributionConfidence <= 0 || string.IsNullOrWhiteSpace(plugin.SecurityReviewCoverageLabel))
            return "Plugin package only";
        return plugin.SecurityReviewCoverageLabel.Trim().Equals("Artifact only", StringComparison.OrdinalIgnoreCase)
            ? "Plugin package only"
            : plugin.SecurityReviewCoverageLabel.Trim();
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
        DrawProductSectionHeading(SigmascopeInfo.Name);
        ImGui.Spacing();
        DrawSigmascopeDisclaimerPanel();

        ImGui.Indent(14f);
        var lifecycle = ResolveSigmascopeVisual(plugin);
        DrawPluginFontAwesomeRiskIcon(lifecycle.Icon, lifecycle.IconColor, lifecycle.Tooltip, Ui(20f));
        ImGui.SameLine(0f, Ui(8f));
        DrawDiscoverTextBadge(lifecycle.Label, lifecycle.BadgeColor);
        if (!plugin.HasCompletedSecurityScan)
        {
            ImGui.Spacing();
            ImGui.TextWrapped(BuildSigmascopeLifecycleExplanation(plugin));
            ImGui.Unindent(14f);
            return;
        }

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
            ImGui.TextWrapped($"OSV: {plugin.SecurityKnownAdvisoryCount} known {noun}; highest {plugin.SecurityKnownAdvisoryHighestSeverity}.");
        }

        if (plugin.SecurityCapabilities.Count > 0)
        {
            ImGui.Dummy(new Vector2(Ui(1f), Ui(10f)));
            ImGui.TextUnformatted("Observed capabilities");
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
        ImGui.TextDisabled($"Review coverage: {ReviewCoverageLabel(plugin)}");
        if (plugin.SecuritySourceAttributionConfidence > 0)
        {
            ImGui.TextDisabled($"Source attribution: {plugin.SecuritySourceAttributionConfidence}/100");
            if (plugin.SecuritySourceAttributionConfidence < 100)
                ImGui.TextDisabled("Source/package match: unverified");
        }
        else
        {
            ImGui.TextDisabled("Source attribution: unresolved");
        }

        DrawSigmascopeAnalysisDetails(plugin);
        ImGui.Unindent(14f);
    }


    private void DrawSigmascopeAnalysisDetails(MarketplacePlugin plugin)
    {
        ImGui.Dummy(new Vector2(Ui(1f), Ui(8f)));
        if (!ImGui.TreeNode($"Analysis details##sigmascope-analysis-details-{StableId(plugin.InternalName)}"))
            return;

        ImGui.TextDisabled($"Plugin version analyzed: v{plugin.AssemblyVersionText}");
        if (plugin.SecurityScannedAtUtc is { } scanned)
            ImGui.TextDisabled($"Analysis completed: {scanned.ToLocalTime():g}");
        if (!string.IsNullOrWhiteSpace(plugin.SigmascopeVersion))
            ImGui.TextDisabled($"Sigmascope: {plugin.SigmascopeVersion}");
        if (!string.IsNullOrWhiteSpace(plugin.SourceName))
            ImGui.TextDisabled($"Package repository: {plugin.SourceName}");

        if (!string.IsNullOrWhiteSpace(plugin.SecurityArtifactSha256))
        {
            var digest = plugin.SecurityArtifactSha256.Trim();
            var shortDigest = digest.Length > 16 ? digest[..16] + "…" : digest;
            ImGui.TextDisabled($"Plugin package SHA-256: {shortDigest}");
            if (ImGui.IsItemHovered())
                SetReadableTooltip(digest);
        }

        if (!string.IsNullOrWhiteSpace(plugin.SecuritySourceRepository))
        {
            ImGui.TextDisabled($"Attributed source: {plugin.SecuritySourceRepository}");
            if (!string.IsNullOrWhiteSpace(plugin.SecuritySourceCommit))
            {
                var commit = plugin.SecuritySourceCommit.Trim();
                var shortCommit = commit.Length > 12 ? commit[..12] : commit;
                ImGui.TextDisabled($"Attributed source revision: {shortCommit}");
                if (ImGui.IsItemHovered())
                    SetReadableTooltip(commit);
            }
        }

        if (!string.IsNullOrWhiteSpace(catalog.DefinitionsRevision))
            ImGui.TextDisabled($"Current marketplace Definitions: {catalog.DefinitionsRevision}");
        if (!string.IsNullOrWhiteSpace(catalog.EvidenceRevision))
            ImGui.TextDisabled($"Published evidence snapshot: {catalog.EvidenceRevision}");

        ImGui.TreePop();
    }

    private string BuildSigmascopeLifecycleExplanation(MarketplacePlugin plugin)
    {
        var status = (plugin.SecurityStatus ?? string.Empty).Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(status))
        {
            var otherVersion = catalog.GetVariants(plugin.InternalName)
                .Where(x => x.HasCompletedSecurityScan &&
                            !x.AssemblyVersion.Equals(plugin.AssemblyVersion))
                .OrderByDescending(x => x.AssemblyVersion)
                .FirstOrDefault();
            return otherVersion is null
                ? $"No published analysis for v{plugin.AssemblyVersionText}."
                : $"No analysis for v{plugin.AssemblyVersionText}; v{otherVersion.AssemblyVersionText} has a published result.";
        }
        if (status is "failed" or "error")
            return string.IsNullOrWhiteSpace(plugin.SecurityError)
                ? "Analysis failed."
                : $"Analysis failed: {plugin.SecurityError}";
        if (status is "pending" or "queued" or "selected")
            return "Queued for analysis.";
        if (status is "running" or "in-progress" or "in_progress" or "analyzing")
            return "Analysis in progress.";
        return "Analysis incomplete.";
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
        const string warning = "Findings come from static analysis. No findings is not a safety guarantee.";
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
        ImGui.TextDisabled("Findings come from static analysis. No findings is not a safety guarantee.");
    }
}
