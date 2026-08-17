using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private readonly record struct RepositorySecurityComparison(
        bool Different,
        bool Worse,
        bool IntegrityAnomaly,
        bool ArtifactDiffers,
        string Tooltip);

    /// <summary>
    /// Compares a repository package with Omega's preferred/green package baseline. The baseline is
    /// selected from Dalamud, Puni.sh, NightmareXIV and Combat Reborn before ordinary community
    /// repositories. An identical artifact SHA-256 must produce an identical user-facing security
    /// report; a mismatch in that case is treated as a Definitions integrity anomaly.
    /// </summary>
    private static RepositorySecurityComparison CompareRepositorySecurity(
        MarketplacePlugin candidate,
        MarketplacePlugin baseline)
    {
        if (NormalizeUrl(candidate.SourceUrl)
            .Equals(NormalizeUrl(baseline.SourceUrl), StringComparison.OrdinalIgnoreCase))
            return default;

        // Different plugin versions are expected to have different package bytes. Cross-source
        // provenance comparison is meaningful only for the same advertised version/API package.
        if (!candidate.AssemblyVersion.Equals(baseline.AssemblyVersion) ||
            candidate.DalamudApiLevel != baseline.DalamudApiLevel)
            return default;

        var candidateHash = NormalizeArtifactHash(candidate.SecurityArtifactSha256);
        var baselineHash = NormalizeArtifactHash(baseline.SecurityArtifactSha256);
        var sameKnownArtifact = candidateHash.Length > 0 && baselineHash.Length > 0 &&
                                candidateHash.Equals(baselineHash, StringComparison.OrdinalIgnoreCase);
        var differentKnownArtifact = candidateHash.Length > 0 && baselineHash.Length > 0 && !sameKnownArtifact;

        if (sameKnownArtifact)
        {
            if (candidate.HasCompletedSecurityScan && baseline.HasCompletedSecurityScan &&
                SecurityResultSignature(candidate).Equals(SecurityResultSignature(baseline), StringComparison.Ordinal))
                return default;

            return new RepositorySecurityComparison(
                true,
                true,
                true,
                false,
                $"Definitions integrity anomaly: {SourceLabel(candidate)} and {SourceLabel(baseline)} point to the same plugin package SHA-256 " +
                $"({ShortArtifactHash(candidateHash)}), but their projected security reports differ. Identical package bytes should have one canonical security result.");
        }

        if (differentKnownArtifact)
        {
            var riskSummary = BuildBaselineRiskSummary(candidate, baseline);
            return new RepositorySecurityComparison(
                true,
                true,
                false,
                true,
                $"Package differs from the preferred baseline {SourceLabel(baseline)}: baseline SHA-256 {ShortArtifactHash(baselineHash)}, " +
                $"this source SHA-256 {ShortArtifactHash(candidateHash)}. {riskSummary}");
        }

        if (baseline.HasCompletedSecurityScan && !candidate.HasCompletedSecurityScan)
        {
            return new RepositorySecurityComparison(
                true,
                true,
                false,
                false,
                $"This source cannot be verified against the preferred baseline {SourceLabel(baseline)} yet: the baseline has a completed scan, but {SourceLabel(candidate)} does not.");
        }

        if (candidate.HasCompletedSecurityScan && baseline.HasCompletedSecurityScan &&
            !SecurityResultSignature(candidate).Equals(SecurityResultSignature(baseline), StringComparison.Ordinal))
        {
            return new RepositorySecurityComparison(
                true,
                true,
                false,
                false,
                $"Security report differs from the preferred baseline {SourceLabel(baseline)}, but one or both plugin package hashes are unavailable. " +
                BuildBaselineRiskSummary(candidate, baseline));
        }

        return default;
    }

    private static string NormalizeArtifactHash(string? value)
        => (value ?? string.Empty).Trim().ToLowerInvariant();

    private static string ShortArtifactHash(string hash)
        => hash.Length > 16 ? hash[..16] + "…" : hash;

    private static string SecurityResultSignature(MarketplacePlugin plugin)
        => $"{(plugin.HasCompletedSecurityScan ? "complete" : plugin.SecurityStatus)}|{plugin.SecurityHighestSeverity}|" +
           $"{plugin.SecurityCriticalCount}|{plugin.SecurityHighCount}|{plugin.SecurityCautionCount}|" +
           $"{plugin.SecurityInformationalCount}|{plugin.SecurityKnownAdvisoryCount}|{plugin.SecurityKnownAdvisoryHighestSeverity}|{plugin.SecurityRiskScore}|{plugin.SecurityAutomationLevel}|" +
           $"{string.Join(",", plugin.SecurityCapabilities.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))}|" +
           $"{string.Join(",", plugin.SecurityFindings.Select(x => $"{x.RuleId}:{x.Severity}").OrderBy(x => x, StringComparer.OrdinalIgnoreCase))}";

    private static string BuildBaselineRiskSummary(MarketplacePlugin candidate, MarketplacePlugin baseline)
    {
        var candidateVisual = ResolvePluginSecurityVisual(candidate);
        var baselineVisual = ResolvePluginSecurityVisual(baseline);
        return $"Security: {SourceLabel(candidate)} is {candidateVisual.Label.ToLowerInvariant()} " +
               $"({candidate.SecurityCriticalCount} critical, {candidate.SecurityHighCount} high, {candidate.SecurityCautionCount} medium, {candidate.SecurityKnownAdvisoryCount} known OSV risk(s)) versus " +
               $"baseline {baselineVisual.Label.ToLowerInvariant()} ({baseline.SecurityCriticalCount} critical, {baseline.SecurityHighCount} high, {baseline.SecurityCautionCount} medium, {baseline.SecurityKnownAdvisoryCount} known OSV risk(s)).";
    }

    private static void DrawRepositorySecurityDifferenceIndicator(RepositorySecurityComparison comparison)
    {
        if (!comparison.Different)
            return;

        ImGui.SameLine(0f, 7f);
        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        ImGui.TextColored(
            comparison.Worse ? new Vector4(0.94f, 0.22f, 0.20f, 1f) : new Vector4(0.28f, 0.62f, 0.92f, 1f),
            (comparison.Worse ? FontAwesomeIcon.ExclamationTriangle : FontAwesomeIcon.InfoCircle).ToIconString());
        ImGui.PopFont();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(comparison.Tooltip);
    }
}
