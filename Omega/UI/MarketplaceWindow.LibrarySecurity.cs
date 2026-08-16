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
    private sealed record InstalledSecurityEntry(
        MarketplacePlugin Listing,
        MarketplacePlugin SecurityVariant,
        IExposedPlugin InstalledPlugin);

    private void DrawLibrarySecurityEnvironment(
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
                return new InstalledSecurityEntry(
                    listing,
                    ResolveInstalledSecurityVariant(listing, installedPlugin),
                    installedPlugin);
            })
            .OrderByDescending(x => SecuritySeverityRank(x.SecurityVariant.SecurityHighestSeverity))
            .ThenByDescending(x => x.SecurityVariant.SecurityCriticalCount)
            .ThenByDescending(x => x.SecurityVariant.SecurityHighCount)
            .ThenBy(x => x.Listing.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var completed = entries.Count(x => x.SecurityVariant.HasCompletedSecurityScan);
        var elevated = entries.Count(x => SecuritySeverityRank(x.SecurityVariant.SecurityHighestSeverity) >= SecuritySeverityRank("high"));
        var caution = entries.Count(x => x.SecurityVariant.HasCompletedSecurityScan &&
                                         SecuritySeverityRank(x.SecurityVariant.SecurityHighestSeverity) == SecuritySeverityRank("caution"));
        var unknown = entries.Length - completed;

        DrawSecurityDisclaimerPanel();
        ImGui.Spacing();
        DrawLibrarySecuritySummary(entries.Length, completed, elevated, caution, unknown);
        ImGui.Spacing();
        ImGui.TextDisabled("Security results are matched to the installed repository package where possible. Omega does not execute plugin code for this view.");
        ImGui.Spacing();

        foreach (var entry in entries)
        {
            DrawLibrarySecurityRow(entry, currentApi, currentDalamudVersion);
            ImGui.Spacing();
        }
    }

    private void DrawLibrarySecuritySummary(int installed, int scanned, int elevated, int caution, int unknown)
    {
        ImGui.TextUnformatted("Installed environment");
        ImGui.SameLine(0f, 12f);
        ImGui.TextDisabled($"{installed} plugins  •  {scanned} scanned  •  {elevated} high/critical  •  {caution} medium  •  {unknown} pending/unknown");

        var label = updates.IsRefreshing ? "Checking…" : "Check newer security data";
        var width = Math.Max(164f, ImGui.CalcTextSize(label).X + 24f);
        ImGui.SameLine(Math.Max(ImGui.GetCursorPosX() + 12f, ImGui.GetWindowWidth() - width - 18f));
        if (ImGui.Button(label, new Vector2(width, 30f)) && !updates.IsRefreshing)
            CheckForUpdates();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Check whether newer Omega Definitions/security summaries are available. Installed plugin code is never executed by this view.");
    }

    private void DrawLibrarySecurityRow(
        InstalledSecurityEntry entry,
        int currentApi,
        Version currentDalamudVersion)
    {
        const float rowHeight = 112f;
        var rowWidth = Math.Max(420f, ImGui.GetContentRegionAvail().X);
        ImGui.BeginChild($"library-security-{StableId(entry.Listing.InternalName)}", new Vector2(rowWidth, rowHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, 52f));
        if (DrawPluginArtwork(
                entry.Listing,
                entry.InstalledPlugin,
                52f,
                52f,
                currentApi,
                currentDalamudVersion,
                showOverlays: false))
        {
            OpenPluginDetails(entry.SecurityVariant);
        }

        ImGui.SameLine(0f, 12f);
        var textStart = ImGui.GetCursorPosX();
        var visual = ResolvePluginSecurityVisual(entry.SecurityVariant);
        ImGui.SetCursorPosY(15f);
        ImGui.BeginGroup();
        ImGui.TextUnformatted(Shorten(entry.Listing.Name, 44));
        ImGui.TextDisabled($"{InstalledVersionText(entry.InstalledPlugin)}  •  {InstalledSecuritySourceLabel(entry.SecurityVariant, entry.InstalledPlugin)}");
        ImGui.TextDisabled(BuildEnvironmentSecurityIssueLine(entry.SecurityVariant));
        ImGui.TextDisabled(BuildEnvironmentPluginIdentityLine(entry.SecurityVariant));
        ImGui.EndGroup();
        if (ImGui.IsItemClicked(ImGuiMouseButton.Left))
            OpenPluginDetails(entry.SecurityVariant);

        const float indicatorWidth = 132f;
        ImGui.SameLine();
        ImGui.SetCursorPos(new Vector2(
            Math.Max(textStart + 260f, MarketplaceLayoutRules.RightAlignedX(ImGui.GetWindowContentRegionMax().X, indicatorWidth)),
            32f));
        ImGui.BeginGroup();
        DrawPluginFontAwesomeRiskIcon(visual.Icon, visual.IconColor, visual.Tooltip, 20f);
        ImGui.SameLine(0f, 8f);
        DrawDiscoverTextBadge(visual.Label, visual.BadgeColor);
        ImGui.EndGroup();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(visual.Tooltip);

        ImGui.EndChild();
    }

    private MarketplacePlugin ResolveInstalledSecurityVariant(MarketplacePlugin listing, IExposedPlugin installedPlugin)
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

    private static string InstalledSecuritySourceLabel(MarketplacePlugin variant, IExposedPlugin installedPlugin)
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
            return $"Plugin {shortHash}…  •  scan shared by {identical} identical packages";
        return $"Plugin {shortHash}…  •  exact package security identity";
    }

    private static string BuildEnvironmentSecurityIssueLine(MarketplacePlugin plugin)
    {
        if (!plugin.HasCompletedSecurityScan)
            return string.IsNullOrWhiteSpace(plugin.SecurityStatus) ? "Security scan not yet available" : "Security scan incomplete";

        var total = plugin.SecurityCriticalCount + plugin.SecurityHighCount +
                    plugin.SecurityCautionCount + plugin.SecurityInformationalCount;
        if (total == 0)
            return "No findings in the latest completed static scan";

        var parts = new List<string>();
        if (plugin.SecurityCriticalCount > 0) parts.Add($"{plugin.SecurityCriticalCount} critical");
        if (plugin.SecurityHighCount > 0) parts.Add($"{plugin.SecurityHighCount} high");
        if (plugin.SecurityCautionCount > 0) parts.Add($"{plugin.SecurityCautionCount} medium");
        if (plugin.SecurityInformationalCount > 0) parts.Add($"{plugin.SecurityInformationalCount} low");
        var firstFinding = plugin.SecurityFindings.FirstOrDefault()?.Title;
        return Shorten(
            string.IsNullOrWhiteSpace(firstFinding)
                ? string.Join("  •  ", parts)
                : $"{string.Join("  •  ", parts)}  —  {firstFinding}",
            96);
    }
}
