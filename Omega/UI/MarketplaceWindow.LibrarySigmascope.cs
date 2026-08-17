using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Plugin;

namespace Dalagab.Omega;

/// <summary>
/// Library-wide security posture for the plugins installed in the current Dalamud environment.
/// This surface never executes installed plugin code: it joins Dalamud's installed-plugin snapshot
/// to the exact repository/package scan already present in Omega Definitions.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private sealed record InstalledSigmascopeEntry(
        MarketplacePlugin Listing,
        MarketplacePlugin SecurityVariant,
        IExposedPlugin InstalledPlugin);

    private void DrawLibrarySigmascopeEnvironment(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (!catalog.HasLoaded)
        {
            updates.SeedIfEmpty();
            DrawCatalogLoadingState();
            return;
        }

        var projection = catalog.GetMainProjection(currentApi).Plugins;
        var library = BuildLibraryProjection(projection, installed)
            .ToDictionary(x => x.InternalName, StringComparer.OrdinalIgnoreCase);
        var entries = installed.Values
            .Select(installedPlugin =>
            {
                var listing = library.TryGetValue(installedPlugin.InternalName, out var known)
                    ? known
                    : new MarketplacePlugin { InternalName = installedPlugin.InternalName, Name = installedPlugin.Name };
                return new InstalledSigmascopeEntry(
                    listing,
                    ResolveInstalledSigmascopeVariant(listing, installedPlugin),
                    installedPlugin);
            })
            .OrderByDescending(x => x.SecurityVariant.SecurityRiskScore)
            .ThenByDescending(x => EffectiveSecuritySeverityRank(x.SecurityVariant))
            .ThenByDescending(x => x.SecurityVariant.SecurityCriticalCount)
            .ThenByDescending(x => x.SecurityVariant.SecurityHighCount)
            .ThenBy(x => x.Listing.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var completed = entries.Count(x => x.SecurityVariant.HasCompletedSecurityScan);
        var elevated = entries.Count(x => EffectiveSecuritySeverityRank(x.SecurityVariant) >= SecuritySeverityRank("high"));
        var caution = entries.Count(x => x.SecurityVariant.HasCompletedSecurityScan &&
                                         EffectiveSecuritySeverityRank(x.SecurityVariant) == SecuritySeverityRank("caution"));
        var unknown = entries.Length - completed;

        DrawSigmascopeDisclaimerPanel();
        ImGui.Spacing();
        DrawLibrarySigmascopeSummary(entries.Length, completed, elevated, caution, unknown);
        ImGui.Spacing();
        ImGui.TextDisabled("Sigmascope results are matched to the installed repository package where possible. Sigmascope examines evidence without executing plugin code.");
        ImGui.Spacing();

        foreach (var entry in entries)
        {
            DrawLibrarySigmascopeRow(entry, currentApi, currentDalamudVersion);
            ImGui.Spacing();
        }
    }

    private void DrawLibrarySigmascopeSummary(int installed, int scanned, int elevated, int caution, int unknown)
    {
        ImGui.TextUnformatted("Sigmascope · Installed environment");
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(SigmascopeInfo.Lore);
        ImGui.SameLine(0f, Ui(12f));
        ImGui.TextDisabled($"{installed} plugins  •  {scanned} scanned  •  {elevated} high/critical  •  {caution} medium  •  {unknown} pending/unknown");

        var label = updates.IsRefreshing ? "Checking…" : "Check newer security data";
        var width = Math.Max(Ui(164f), ImGui.CalcTextSize(label).X + Ui(24f));
        ImGui.SameLine(Math.Max(ImGui.GetCursorPosX() + 12f, ImGui.GetWindowWidth() - width - 18f));
        if (ImGui.Button(label, new Vector2(width, Ui(30f))) && !updates.IsRefreshing)
            CheckForUpdates();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Check whether newer Omega Definitions/security summaries are available. Installed plugin code is never executed by this view.");
    }

    private void DrawLibrarySigmascopeRow(
        InstalledSigmascopeEntry entry,
        int currentApi,
        Version currentDalamudVersion)
    {
        var rowHeight = Ui(112f);
        var rowWidth = Math.Max(Ui(1f), ImGui.GetContentRegionAvail().X);
        ImGui.BeginChild($"library-security-{StableId(entry.Listing.InternalName)}", new Vector2(rowWidth, rowHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, Ui(52f)));
        if (DrawPluginArtwork(
                entry.Listing,
                entry.InstalledPlugin,
                Ui(52f),
                Ui(52f),
                currentApi,
                currentDalamudVersion,
                showOverlays: false))
        {
            OpenPluginDetails(entry.SecurityVariant);
        }

        ImGui.SameLine(0f, Ui(12f));
        var textStart = ImGui.GetCursorPosX();
        var visual = ResolveSigmascopeVisual(entry.SecurityVariant);
        ImGui.SetCursorPosY(Ui(15f));
        ImGui.BeginGroup();
        ImGui.TextUnformatted(Shorten(entry.Listing.Name, 44));
        ImGui.TextDisabled($"{InstalledVersionText(entry.InstalledPlugin)}  •  {InstalledSigmascopeSourceLabel(entry.SecurityVariant, entry.InstalledPlugin)}");
        ImGui.TextDisabled(BuildEnvironmentSigmascopeIssueLine(entry.SecurityVariant));
        ImGui.TextDisabled(BuildEnvironmentPluginIdentityLine(entry.SecurityVariant));
        ImGui.EndGroup();
        if (ImGui.IsItemClicked(ImGuiMouseButton.Left))
            OpenPluginDetails(entry.SecurityVariant);

        var indicatorWidth = Ui(132f);
        ImGui.SameLine();
        ImGui.SetCursorPos(new Vector2(
            Math.Max(textStart + Ui(260f), MarketplaceLayoutRules.RightAlignedX(ImGui.GetWindowContentRegionMax().X, indicatorWidth)),
            Ui(32f)));
        ImGui.BeginGroup();
        DrawPluginFontAwesomeRiskIcon(visual.Icon, visual.IconColor, visual.Tooltip, Ui(20f));
        ImGui.SameLine(0f, Ui(8f));
        DrawDiscoverTextBadge(visual.Label, visual.BadgeColor);
        ImGui.EndGroup();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(visual.Tooltip);

        ImGui.EndChild();
    }

    private MarketplacePlugin ResolveInstalledSigmascopeVariant(MarketplacePlugin listing, IExposedPlugin installedPlugin)
    {
        var variants = catalog.GetVariants(installedPlugin.InternalName);
        if (variants.Count == 0)
            return listing;

        if (!installedPlugin.IsThirdParty)
        {
            return variants
                       .Where(x => x.SourceIsOfficial)
                       .OrderByDescending(x => x.AssemblyVersion)
                       .FirstOrDefault()
                   ?? ResolveDefaultVariant(listing);
        }

        var installedFrom = installedPlugin.Manifest.InstalledFromUrl;
        if (!string.IsNullOrWhiteSpace(installedFrom))
        {
            var exact = variants.FirstOrDefault(x =>
                NormalizeUrl(x.SourceUrl).Equals(NormalizeUrl(installedFrom), StringComparison.OrdinalIgnoreCase));
            if (exact is not null)
                return exact;
        }

        return ResolveDefaultVariant(listing);
    }

    private static string InstalledSigmascopeSourceLabel(MarketplacePlugin variant, IExposedPlugin installedPlugin)
    {
        if (!string.IsNullOrWhiteSpace(variant.SourceName))
            return variant.SourceName;
        if (!installedPlugin.IsThirdParty)
            return "Dalamud official";
        return "Installed source unknown";
    }

    private string BuildEnvironmentPluginIdentityLine(MarketplacePlugin plugin)
    {
        var artifactHash = NormalizeArtifactHash(plugin.SecurityArtifactSha256);
        if (string.IsNullOrWhiteSpace(artifactHash))
            return "Plugin identity not yet published";

        var variants = catalog.GetVariants(plugin.InternalName);
        var identical = variants.Count(x =>
            x.HasCompletedSecurityScan &&
            NormalizeArtifactHash(x.SecurityArtifactSha256).Equals(artifactHash, StringComparison.OrdinalIgnoreCase));
        var baseline = ResolveDefaultVariant(plugin);
        var baselineHash = NormalizeArtifactHash(baseline.SecurityArtifactSha256);
        var shortHash = artifactHash.Length > 12 ? artifactHash[..12] : artifactHash;

        if (!string.IsNullOrWhiteSpace(baselineHash) && !baselineHash.Equals(artifactHash, StringComparison.OrdinalIgnoreCase))
            return $"Plugin {shortHash}…  •  differs from preferred package";
        if (identical > 1)
            return $"Plugin {shortHash}…  •  Sigmascope evidence shared by {identical} identical packages";
        return $"Plugin {shortHash}…  •  exact package security identity";
    }

    private static string BuildEnvironmentSigmascopeIssueLine(MarketplacePlugin plugin)
    {
        if (!plugin.HasCompletedSecurityScan)
            return string.IsNullOrWhiteSpace(plugin.SecurityStatus) ? "Sigmascope analysis not yet available" : "Sigmascope analysis incomplete";

        var total = plugin.SecurityCriticalCount + plugin.SecurityHighCount +
                    plugin.SecurityCautionCount + plugin.SecurityInformationalCount;
        if (total == 0 && !plugin.HasKnownAtRiskDependency)
            return "No findings in the latest completed static scan";

        var parts = new List<string>();
        if (plugin.SecurityCriticalCount > 0) parts.Add($"{plugin.SecurityCriticalCount} critical");
        if (plugin.SecurityHighCount > 0) parts.Add($"{plugin.SecurityHighCount} high");
        if (plugin.SecurityCautionCount > 0) parts.Add($"{plugin.SecurityCautionCount} medium");
        if (plugin.SecurityInformationalCount > 0) parts.Add($"{plugin.SecurityInformationalCount} low");
        if (plugin.HasKnownAtRiskDependency)
            parts.Add($"OSV {plugin.SecurityKnownAdvisoryCount} known risk{(plugin.SecurityKnownAdvisoryCount == 1 ? string.Empty : "s")}");
        var firstFinding = plugin.SecurityFindings.FirstOrDefault()?.Title;
        return Shorten(
            string.IsNullOrWhiteSpace(firstFinding)
                ? string.Join("  •  ", parts)
                : $"{string.Join("  •  ", parts)}  —  {firstFinding}",
            96);
    }
}
