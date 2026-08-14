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
        DrawSpotlightSectionTitle("Latest additions");
        DrawRecencyShelf(GetLatestAdditions(plugins), "latest-additions", currentApi, currentDalamudVersion);

        ImGui.Dummy(new Vector2(1f, 16f));
        DrawSpotlightSectionTitle("Latest updates");
        DrawRecencyShelf(GetLatestUpdates(plugins), "latest-updates", currentApi, currentDalamudVersion);
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

            DrawRecencyShelfCard(plugins[index], shelfId, layout.CardWidth, currentApi, currentDalamudVersion);
        }
    }

    private void DrawRecencyShelfCard(
        MarketplacePlugin plugin,
        string shelfId,
        float cardWidth,
        int currentApi,
        Version currentDalamudVersion)
    {
        plugin = ResolveSpotlightVariant(plugin);
        ImGui.BeginChild(
            $"{shelfId}-{plugin.InternalName}",
            new Vector2(cardWidth, SpotlightShelfCardHeight),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        _ = DrawPluginArtwork(
            plugin,
            null,
            SpotlightShelfArtworkSize,
            ImGui.GetContentRegionAvail().X,
            currentApi,
            currentDalamudVersion,
            showOverlays: false,
            useFallbackTexture: false);
        ImGui.Spacing();
        CenterText(Shorten(plugin.Name, 24));
        CenterText(Shorten(string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author, 24), disabled: true);

        var clicked = ImGui.IsWindowHovered() && ImGui.IsMouseClicked(ImGuiMouseButton.Left);
        if (ImGui.IsWindowHovered())
            ImGui.SetTooltip("Open in Discover");
        ImGui.EndChild();

        if (clicked)
            OpenSpotlightPluginInDiscover(plugin);
    }

    private static void DrawSpotlightSectionTitle(string title)
    {
        ImGui.TextUnformatted(title);
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
