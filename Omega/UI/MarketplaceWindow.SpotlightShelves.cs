using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private const float SpotlightShelfCardHeight = 138f;
    private const float SpotlightShelfArtworkSize = 62f;

    private void DrawSpotlightSections(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        DrawSpotlightSectionTitle("Spotlight");
        DrawPromotedSpotlightRow(plugins, installed, currentApi, currentDalamudVersion);

        ImGui.Dummy(new Vector2(1f, 16f));
        DrawSpotlightSectionTitle("Latest additions", "Plugins most recently first seen in Omega Definitions. This is catalog discovery time, not necessarily the plugin's original release date.");
        DrawRecencyShelf(GetLatestAdditions(plugins), installed, "latest-additions", currentApi, currentDalamudVersion);

        ImGui.Dummy(new Vector2(1f, 16f));
        DrawSpotlightSectionTitle("Latest updates", "Plugins with the most recent known publication/update timestamp supplied by their preferred package source. Entries without a reliable timestamp are not promoted here.");
        DrawRecencyShelf(GetLatestUpdates(plugins), installed, "latest-updates", currentApi, currentDalamudVersion);
    }

    private void DrawPromotedSpotlightRow(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        var promoted = PromotedInternalNames
            .Take(SpotlightCardCount)
            .Select(id => plugins.FirstOrDefault(x => x.InternalName.Equals(id, StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        var layout = CalculateSpotlightRowLayout();
        ImGui.SetCursorPosX(ImGui.GetCursorPosX() + layout.OffsetX);
        for (var index = 0; index < SpotlightCardCount; index++)
        {
            if (index > 0)
                ImGui.SameLine(0f, SpotlightCardGap);

            var plugin = promoted[index];
            if (plugin is null)
                DrawMissingSpotlightCard(PromotedInternalNames[index], layout.CardWidth);
            else
                DrawSpotlightCard(plugin, installed, currentApi, currentDalamudVersion, layout.CardWidth);
        }
    }

    private IReadOnlyList<MarketplacePlugin> GetLatestAdditions(IReadOnlyList<MarketplacePlugin> plugins)
        => plugins
            .Where(IsSpotlightShelfCandidate)
            .OrderByDescending(x => pluginRecency.GetFirstSeenUnix(x.InternalName))
            .ThenByDescending(x => PluginRecencyLedger.NormalizeUnix(x.LastUpdate))
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Take(SpotlightCardCount)
            .ToArray();

    private static IReadOnlyList<MarketplacePlugin> GetLatestUpdates(IReadOnlyList<MarketplacePlugin> plugins)
        => plugins
            .Where(x => IsSpotlightShelfCandidate(x) && PluginRecencyLedger.NormalizeUnix(x.LastUpdate) > 0)
            .OrderByDescending(x => PluginRecencyLedger.NormalizeUnix(x.LastUpdate))
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Take(SpotlightCardCount)
            .ToArray();

    private static bool IsSpotlightShelfCandidate(MarketplacePlugin plugin)
        => !plugin.IsHide && !string.IsNullOrWhiteSpace(plugin.InternalName);

    private void DrawRecencyShelf(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        string shelfId,
        int currentApi,
        Version currentDalamudVersion)
    {
        var layout = CalculateSpotlightRowLayout();
        ImGui.SetCursorPosX(ImGui.GetCursorPosX() + layout.OffsetX);
        for (var index = 0; index < SpotlightCardCount; index++)
        {
            if (index > 0)
                ImGui.SameLine(0f, SpotlightCardGap);

            if (index >= plugins.Count)
            {
                ImGui.Dummy(new Vector2(layout.CardWidth, SpotlightShelfCardHeight));
                continue;
            }

            installed.TryGetValue(plugins[index].InternalName, out var installedPlugin);
            DrawRecencyShelfCard(plugins[index], installedPlugin, shelfId, layout.CardWidth, currentApi, currentDalamudVersion);
        }
    }

    private void DrawRecencyShelfCard(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        string shelfId,
        float cardWidth,
        int currentApi,
        Version currentDalamudVersion)
    {
        plugin = ResolveSpotlightVariant(plugin);
        var availabilityStyle = PushUnavailableListingStyle(
            IsListingCurrentlyAvailable(plugin, installedPlugin, currentApi, currentDalamudVersion));
        ImGui.BeginChild(
            $"{shelfId}-{plugin.InternalName}",
            new Vector2(cardWidth, SpotlightShelfCardHeight),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var artworkClicked = DrawPluginArtwork(
            plugin,
            null,
            SpotlightShelfArtworkSize,
            ImGui.GetContentRegionAvail().X,
            currentApi,
            currentDalamudVersion,
            showOverlays: false);

        // Latest additions/updates use the same exact-package scan icon as the product page.
        // Automation remains a separate marker rather than replacing scan state.
        var afterArtwork = ImGui.GetCursorPos();
        const float statusIconSize = 22f;
        const float statusIconGap = 7f;
        var statusHovered = DrawPluginScanAndAutomationIndicators(
            plugin,
            Math.Max(statusIconSize, cardWidth - 8f),
            8f,
            statusIconSize,
            statusIconGap);
        ImGui.SetCursorPos(afterArtwork);

        ImGui.Spacing();
        CenterText(Shorten(plugin.Name, 24));
        CenterText(Shorten(string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author, 24), disabled: true);

        var clicked = ImGui.IsWindowHovered() && ImGui.IsMouseClicked(ImGuiMouseButton.Left);
        if (ImGui.IsWindowHovered() && !statusHovered)
            SetReadableTooltip("Open in Discover");
        ImGui.EndChild();
        PopUnavailableListingStyle(availabilityStyle);

        if (artworkClicked || clicked)
            OpenSpotlightPluginInDiscover(plugin);
    }

    private static void DrawSpotlightSectionTitle(string title, string? explanation = null)
    {
        ImGui.TextUnformatted(title);
        if (!string.IsNullOrWhiteSpace(explanation))
        {
            ImGui.SameLine(0f, 7f);
            ImGui.TextDisabled("(?)");
            if (ImGui.IsItemHovered())
                SetReadableTooltip(explanation);
        }
        ImGui.Spacing();
    }

    private static (float CardWidth, float OffsetX) CalculateSpotlightRowLayout()
    {
        var availableWidth = ImGui.GetContentRegionAvail().X;
        var fittedWidth = (availableWidth - (SpotlightCardGap * (SpotlightCardCount - 1))) / SpotlightCardCount;
        var cardWidth = Math.Clamp(fittedWidth, SpotlightCardMinWidth, SpotlightCardMaxWidth);
        var rowWidth = (cardWidth * SpotlightCardCount) + (SpotlightCardGap * (SpotlightCardCount - 1));
        return (cardWidth, Math.Max(0f, (availableWidth - rowWidth) * 0.5f));
    }
}
