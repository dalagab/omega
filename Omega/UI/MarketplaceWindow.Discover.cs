using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Plugin;

namespace Dalagab.Omega;

/// <summary>
/// Owns the fixed-density Discover shelf. Discover always presents five stable-width cards across
/// and three visible rows; filtering changes the contents, never the card dimensions.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private const int DiscoverColumns = 5;
    private const int DiscoverVisibleRows = 3;
    private const float DiscoverTileWidth = 188f;
    private const float DiscoverCardHeight = 190f;
    private const float DiscoverGap = 14f;
    private const float DiscoverRowGap = 14f;
    private const float DiscoverIconSize = 128f;
    private const float DiscoverGridWidth = (DiscoverTileWidth * DiscoverColumns) + (DiscoverGap * (DiscoverColumns - 1));
    private const float DiscoverSplitMinimumWidth = DiscoverGridWidth + 344f;
    private bool resetDiscoverGridScroll;

    private void DrawDiscoverGrid(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        var rowHeight = DiscoverCardHeight + DiscoverRowGap;
        var viewportHeight = (rowHeight * DiscoverVisibleRows) - DiscoverRowGap + 2f;
        ImGui.BeginChild("omega-discover-fixed-grid", new Vector2(0f, viewportHeight), false,
            ImGuiWindowFlags.AlwaysVerticalScrollbar);
        if (resetDiscoverGridScroll)
        {
            ImGui.SetScrollY(0f);
            resetDiscoverGridScroll = false;
        }

        DrawVirtualizedDiscoverGrid(plugins, installed, currentApi, currentDalamudVersion, rowHeight);
        ImGui.EndChild();
    }

    private void DrawVirtualizedDiscoverGrid(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion,
        float rowHeight)
    {
        var contentStartY = ImGui.GetCursorPosY();
        var available = ImGui.GetContentRegionAvail().X;
        var contentStartX = ImGui.GetCursorPosX() + Math.Max(0f, (available - DiscoverGridWidth) * 0.5f);
        var visible = StorefrontVirtualization.Calculate(
            plugins.Count,
            DiscoverColumns,
            rowHeight,
            ImGui.GetScrollY(),
            ImGui.GetWindowHeight(),
            contentStartY,
            bufferRows: 1);

        for (var row = visible.FirstRow; row < visible.LastRowExclusive; row++)
            DrawDiscoverRow(plugins, installed, currentApi, currentDalamudVersion, row, contentStartX, contentStartY, rowHeight);

        ImGui.SetCursorPos(new Vector2(contentStartX, contentStartY + (visible.TotalRows * rowHeight)));
        ImGui.Dummy(new Vector2(1f, 1f));
    }

    private void DrawDiscoverRow(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion,
        int row,
        float contentStartX,
        float contentStartY,
        float rowHeight)
    {
        ImGui.SetCursorPos(new Vector2(contentStartX, contentStartY + (row * rowHeight)));
        var firstIndex = row * DiscoverColumns;
        var lastIndex = Math.Min(plugins.Count, firstIndex + DiscoverColumns);
        for (var index = firstIndex; index < lastIndex; index++)
        {
            var plugin = plugins[index];
            installed.TryGetValue(plugin.InternalName, out var installedPlugin);
            DrawDiscoverCard(plugin, installedPlugin, currentApi, currentDalamudVersion);
            if (index + 1 < lastIndex)
                ImGui.SameLine(0f, DiscoverGap);
        }
    }

    private void DrawDiscoverCard(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        var selected = IsPluginSelected(plugin);
        var cardMin = ImGui.GetCursorScreenPos();
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, 8f);
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 1f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.055f, 0.060f, 0.065f, 0.72f));
        ImGui.PushStyleColor(ImGuiCol.Border, selected
            ? new Vector4(0.12f, 0.72f, 0.67f, 0.88f)
            : new Vector4(0.22f, 0.24f, 0.26f, 0.44f));
        ImGui.BeginChild($"discover-card-{plugin.InternalName}-{StableId(plugin.SourceUrl)}",
            new Vector2(DiscoverTileWidth, DiscoverCardHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.Dummy(new Vector2(1f, 8f));
        DrawPluginArtwork(plugin, installedPlugin, DiscoverIconSize, DiscoverTileWidth - 16f,
            currentApi, currentDalamudVersion, true, showOverlays: false, useFallbackTexture: false);
        ImGui.Spacing();
        DrawCenteredTileText(Shorten(plugin.Name, 25), DiscoverTileWidth - 16f, false);
        DrawCenteredTileText(Shorten(string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author, 28),
            DiscoverTileWidth - 16f, true);

        var hovered = ImGui.IsWindowHovered(ImGuiHoveredFlags.ChildWindows);
        if (hovered && ImGui.IsMouseClicked(ImGuiMouseButton.Left))
            OpenPluginDetails(plugin);
        if (hovered && !string.IsNullOrWhiteSpace(plugin.Punchline))
            ImGui.SetTooltip(plugin.Punchline);

        ImGui.EndChild();
        ImGui.PopStyleColor(2);
        ImGui.PopStyleVar(2);

        if (hovered && !selected)
        {
            var cardMax = cardMin + new Vector2(DiscoverTileWidth, DiscoverCardHeight);
            ImGui.GetWindowDrawList().AddRect(cardMin, cardMax,
                ImGui.ColorConvertFloat4ToU32(new Vector4(0.22f, 0.62f, 0.60f, 0.62f)), 8f, ImDrawFlags.None, 1.2f);
        }
    }

    private bool IsPluginSelected(MarketplacePlugin plugin)
        => detailsOpen && selectedPlugin is not null &&
           selectedPlugin.InternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase) &&
           NormalizeUrl(selectedPlugin.SourceUrl).Equals(NormalizeUrl(plugin.SourceUrl), StringComparison.OrdinalIgnoreCase);
}
