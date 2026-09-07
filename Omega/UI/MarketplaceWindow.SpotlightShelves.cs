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

        ImGui.Dummy(Ui(1f, 16f));
        DrawSpotlightSectionTitle("Latest additions", "Plugins most recently first seen in Omega Definitions. This is catalog discovery time, not necessarily the plugin's original release date.");
        DrawRecencyShelf(GetLatestAdditions(plugins), installed, "latest-additions", currentApi, currentDalamudVersion);

        ImGui.Dummy(Ui(1f, 16f));
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
        for (var index = 0; index < SpotlightCardCount; index++)
        {
            var column = index % layout.Columns;
            if (column == 0)
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + layout.OffsetX);
            else
                ImGui.SameLine(0f, Ui(SpotlightCardGap));

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
        if (plugins.Count == 0)
        {
            ImGui.TextDisabled(shelfId.Equals("latest-additions", StringComparison.Ordinal)
                ? "No recent additions are available yet."
                : "No recent updates are available yet.");
            return;
        }

        var layout = CalculateSpotlightRowLayout();
        for (var index = 0; index < SpotlightCardCount; index++)
        {
            var column = index % layout.Columns;
            if (column == 0)
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + layout.OffsetX);
            else
                ImGui.SameLine(0f, Ui(SpotlightCardGap));

            if (index >= plugins.Count)
            {
                ImGui.Dummy(new Vector2(layout.CardWidth, Ui(SpotlightShelfCardHeight)));
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
            new Vector2(cardWidth, Ui(SpotlightShelfCardHeight)),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var cardMin = ImGui.GetWindowPos();
        var cardMax = cardMin + ImGui.GetWindowSize();
        var artworkSize = Ui(SpotlightShelfArtworkSize);
        var artworkLayoutWidth = ImGui.GetContentRegionAvail().X;
        var artworkClicked = DrawPluginArtwork(
            plugin,
            installedPlugin,
            artworkSize,
            artworkLayoutWidth,
            currentApi,
            currentDalamudVersion,
            showOverlays: false,
            showListingRibbons: true,
            listingPanelMin: cardMin,
            listingPanelMax: cardMax);

        ImGui.Spacing();
        var textWidth = Math.Max(Ui(32f), ImGui.GetContentRegionAvail().X - Ui(8f));
        DrawCenteredFittedText(plugin.Name, textWidth);
        DrawCenteredFittedText(
            string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author,
            textWidth,
            disabled: true);

        var clicked = ImGui.IsWindowHovered() && ImGui.IsMouseClicked(ImGuiMouseButton.Left);
        if (ImGui.IsWindowHovered())
            SetReadableTooltip("Open in Discover");
        DrawPluginPanelUpdateState(plugin, installedPlugin, currentApi, currentDalamudVersion, cardMax);
        ImGui.EndChild();
        PopUnavailableListingStyle(availabilityStyle);

        if (artworkClicked || clicked)
            OpenSpotlightPluginInDiscover(plugin);
    }

    private static void DrawCenteredFittedText(string text, float maximumWidth, bool disabled = false)
    {
        var fitted = FitTextToWidth(text, maximumWidth);
        CenterText(fitted, disabled);
        if (!fitted.Equals(text, StringComparison.Ordinal) && ImGui.IsItemHovered())
            SetReadableTooltip(text);
    }

    private static string FitTextToWidth(string text, float maximumWidth)
    {
        text ??= string.Empty;
        if (text.Length == 0 || ImGui.CalcTextSize(text).X <= maximumWidth)
            return text;

        const string ellipsis = "…";
        var low = 0;
        var high = text.Length;
        while (low < high)
        {
            var mid = (low + high + 1) / 2;
            var candidate = text[..mid].TrimEnd() + ellipsis;
            if (ImGui.CalcTextSize(candidate).X <= maximumWidth)
                low = mid;
            else
                high = mid - 1;
        }
        return text[..Math.Max(0, low)].TrimEnd() + ellipsis;
    }

    private static void DrawSpotlightSectionTitle(string title, string? explanation = null)
    {
        ImGui.TextUnformatted(title);
        if (!string.IsNullOrWhiteSpace(explanation))
        {
            ImGui.SameLine(0f, Ui(7f));
            ImGui.TextDisabled("(?)");
            if (ImGui.IsItemHovered())
                SetReadableTooltip(explanation);
        }
        ImGui.Spacing();
    }

    private static (float CardWidth, float OffsetX, int Columns) CalculateSpotlightRowLayout()
    {
        var availableWidth = Math.Max(Ui(1f), ImGui.GetContentRegionAvail().X);
        var columns = ResponsiveColumns(availableWidth, SpotlightCardMinWidth, SpotlightCardCount, SpotlightCardGap);
        var cardWidth = ResponsiveCardWidth(
            availableWidth,
            columns,
            SpotlightCardGap,
            SpotlightCardMinWidth,
            SpotlightCardMaxWidth);
        var rowWidth = (cardWidth * columns) + (Ui(SpotlightCardGap) * (columns - 1));
        return (cardWidth, Math.Max(0f, (availableWidth - rowWidth) * 0.5f), columns);
    }
}
