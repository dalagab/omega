using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Plugin;

namespace Dalagab.Omega;

/// <summary>
/// Owns Discover's two-tier presentation: screenshot-rich plugins receive Store-style cards first,
/// then metadata-only plugins continue in the compact virtualized list. Both tiers open the same
/// full product page and preserve bounded ImGui submission for large catalogues.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private const int DiscoverRichColumns = 3;
    private const float DiscoverRichCardHeight = 314f;
    private const float DiscoverRichRowGap = 14f;
    private const float DiscoverRichColumnGap = 14f;
    private const float DiscoverRichScreenshotHeight = 150f;
    private const float DiscoverListRowHeight = 116f;
    private const float DiscoverListRowGap = 10f;
    private const float DiscoverListIconSize = 76f;
    private readonly Dictionary<string, MarketplacePresentationContent> discoverPresentationCache =
        new(StringComparer.OrdinalIgnoreCase);
    private long discoverPresentationRevision = -1;
    private bool resetDiscoverListScroll;

    private void DrawDiscoverList(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        EnsureDiscoverPresentationCache();
        var rich = new List<(MarketplacePlugin Plugin, MarketplacePresentationContent Content)>();
        var basic = new List<MarketplacePlugin>();
        foreach (var plugin in plugins)
        {
            var content = GetDiscoverPresentation(plugin);
            if (content.Images.Count > 0)
                rich.Add((plugin, content));
            else
                basic.Add(plugin);
        }

        ImGui.BeginChild("omega-discover-results", Vector2.Zero, false, ImGuiWindowFlags.AlwaysVerticalScrollbar);
        if (resetDiscoverListScroll)
        {
            ImGui.SetScrollY(0f);
            resetDiscoverListScroll = false;
        }

        DrawDiscoverHybridResults(rich, basic, installed, currentApi, currentDalamudVersion);
        ImGui.EndChild();
    }

    private void DrawDiscoverHybridResults(
        IReadOnlyList<(MarketplacePlugin Plugin, MarketplacePresentationContent Content)> rich,
        IReadOnlyList<MarketplacePlugin> basic,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        var contentStartY = ImGui.GetCursorPosY();
        var cursorEndY = contentStartY;
        if (rich.Count > 0)
        {
            ImGui.SetCursorPosY(contentStartY);
            ImGui.TextUnformatted("Featured");

            var gridStartY = contentStartY + 30f;
            var availableWidth = Math.Max(420f, ImGui.GetContentRegionAvail().X - 4f);
            var cardWidth = Math.Max(
                250f,
                (availableWidth - (DiscoverRichColumnGap * (DiscoverRichColumns - 1))) / DiscoverRichColumns);
            const float gridStartX = 0f;
            var stride = DiscoverRichCardHeight + DiscoverRichRowGap;
            var visible = StorefrontVirtualization.Calculate(
                rich.Count,
                DiscoverRichColumns,
                stride,
                ImGui.GetScrollY(),
                ImGui.GetWindowHeight(),
                gridStartY,
                bufferRows: 1);

            for (var row = visible.FirstRow; row < visible.LastRowExclusive; row++)
            {
                for (var column = 0; column < DiscoverRichColumns; column++)
                {
                    var index = (row * DiscoverRichColumns) + column;
                    if (index >= rich.Count)
                        break;
                    var entry = rich[index];
                    installed.TryGetValue(entry.Plugin.InternalName, out var installedPlugin);
                    ImGui.SetCursorPos(new Vector2(
                        gridStartX + (column * (cardWidth + DiscoverRichColumnGap)),
                        gridStartY + (row * stride)));
                    DrawDiscoverRichCard(
                        entry.Plugin,
                        entry.Content,
                        installedPlugin,
                        currentApi,
                        currentDalamudVersion,
                        cardWidth);
                }
            }

            cursorEndY = gridStartY + (visible.TotalRows * stride);
        }

        if (basic.Count > 0)
        {
            var listHeaderY = cursorEndY + (rich.Count > 0 ? 12f : 0f);
            ImGui.SetCursorPosY(listHeaderY);
            ImGui.TextUnformatted("The rest");

            var listStartY = listHeaderY + 30f;
            var stride = DiscoverListRowHeight + DiscoverListRowGap;
            var visible = StorefrontVirtualization.Calculate(
                basic.Count,
                1,
                stride,
                ImGui.GetScrollY(),
                ImGui.GetWindowHeight(),
                listStartY,
                bufferRows: 2);

            for (var index = visible.FirstRow; index < visible.LastRowExclusive && index < basic.Count; index++)
            {
                ImGui.SetCursorPosY(listStartY + (index * stride));
                var plugin = basic[index];
                installed.TryGetValue(plugin.InternalName, out var installedPlugin);
                DrawDiscoverResultRow(plugin, installedPlugin, currentApi, currentDalamudVersion);
            }

            cursorEndY = listStartY + (visible.TotalRows * stride);
        }

        ImGui.SetCursorPosY(Math.Max(cursorEndY, contentStartY + 1f));
        ImGui.Dummy(new Vector2(1f, 1f));
    }

    private void DrawDiscoverRichCard(
        MarketplacePlugin plugin,
        MarketplacePresentationContent content,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion,
        float cardWidth)
    {
        var availabilityStyle = PushUnavailableListingStyle(
            IsListingCurrentlyAvailable(plugin, installedPlugin, currentApi, currentDalamudVersion));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, 9f);
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 1f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.045f, 0.052f, 0.064f, 0.78f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.18f, 0.20f, 0.23f, 0.48f));
        ImGui.BeginChild(
            $"discover-rich-{plugin.InternalName}",
            new Vector2(cardWidth, DiscoverRichCardHeight),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var cardMin = ImGui.GetWindowPos();
        var cardMax = cardMin + ImGui.GetWindowSize();
        DrawDiscoverRichCardHeader(plugin, content, installedPlugin, currentApi, currentDalamudVersion, cardWidth);
        DrawDiscoverRichCardScreenshot(plugin.InternalName, content.Images[0], cardWidth);

        var hovered = ImGui.IsWindowHovered(ImGuiHoveredFlags.ChildWindows);
        if (hovered && ImGui.IsMouseClicked(ImGuiMouseButton.Left))
            OpenPluginDetails(plugin);
        ImGui.EndChild();
        if (hovered)
        {
            ImGui.GetWindowDrawList().AddRect(
                cardMin + new Vector2(0.5f, 0.5f),
                cardMax - new Vector2(0.5f, 0.5f),
                ImGui.ColorConvertFloat4ToU32(new Vector4(0.18f, 0.54f, 0.54f, 0.44f)),
                9f,
                ImDrawFlags.None,
                1.2f);
        }
        ImGui.PopStyleColor(2);
        ImGui.PopStyleVar(2);
        PopUnavailableListingStyle(availabilityStyle);
    }

    private void DrawDiscoverRichCardHeader(
        MarketplacePlugin plugin,
        MarketplacePresentationContent content,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion,
        float cardWidth)
    {
        ImGui.SetCursorPos(new Vector2(12f, 12f));
        DrawPluginArtwork(plugin, installedPlugin, 46f, 46f, currentApi, currentDalamudVersion,
            queueIfVisible: true, showOverlays: false);
        ImGui.SameLine(0f, 10f);
        ImGui.BeginGroup();
        ImGui.TextUnformatted(Shorten(plugin.Name, 32));
        var author = string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author;
        var category = PrimaryPluginCategory(plugin);
        ImGui.TextDisabled(Shorten(string.IsNullOrWhiteSpace(category) ? author : $"{author}  •  {category}", 42));
        ImGui.EndGroup();

        var badgeX = Math.Max(12f, cardWidth - 82f);
        var badgeY = 12f;
        if (content.IsEnhanced)
        {
            ImGui.SetCursorPos(new Vector2(badgeX + 48f, badgeY));
            ImGui.TextColored(new Vector4(0.94f, 0.78f, 0.27f, 1f), "★");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("Enhanced listing: Omega indexed metadata from the plugin's public project page.");
        }
        if (catalog.GetVariants(plugin.InternalName).Any(x => x.SourceIsOfficial))
        {
            ImGui.SetCursorPos(new Vector2(badgeX, badgeY + 28f));
            DrawDiscoverTextBadge("Official", new Vector4(0.09f, 0.38f, 0.44f, 0.92f));
        }
        else if (IsNsfwPlugin(plugin))
        {
            ImGui.SetCursorPos(new Vector2(badgeX, badgeY + 28f));
            DrawDiscoverTextBadge("NSFW", new Vector4(0.56f, 0.16f, 0.22f, 0.94f));
        }

        ImGui.SetCursorPos(new Vector2(12f, 70f));
        if (!string.IsNullOrWhiteSpace(content.Summary))
        {
            ImGui.PushTextWrapPos(cardWidth - 12f);
            ImGui.TextWrapped(Shorten(content.Summary.Replace('\n', ' '), 155));
            ImGui.PopTextWrapPos();
        }
        if (installedPlugin is not null)
        {
            ImGui.SetCursorPos(new Vector2(12f, 125f));
            ImGui.TextDisabled("Installed");
        }
    }

    private void DrawDiscoverRichCardScreenshot(string internalName, string url, float cardWidth)
    {
        var screenshotY = DiscoverRichCardHeight - DiscoverRichScreenshotHeight - 12f;
        ImGui.SetCursorPos(new Vector2(12f, screenshotY));
        var width = Math.Max(120f, cardWidth - 24f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.025f, 0.030f, 0.038f, 0.90f));
        ImGui.BeginChild($"discover-rich-image-{StableId(internalName)}-{StableId(url)}", new Vector2(width, DiscoverRichScreenshotHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
        var texture = iconCache.GetOrQueue(url);
        if (texture is null || texture.Size.X <= 0 || texture.Size.Y <= 0)
        {
            var text = "Loading preview…";
            var size = ImGui.CalcTextSize(text);
            var available = ImGui.GetContentRegionAvail();
            ImGui.SetCursorPos(new Vector2(Math.Max(0f, (available.X - size.X) * 0.5f), Math.Max(0f, (available.Y - size.Y) * 0.5f)));
            ImGui.TextDisabled(text);
        }
        else
        {
            var available = ImGui.GetContentRegionAvail();
            var scale = Math.Min(available.X / texture.Size.X, available.Y / texture.Size.Y);
            var size = texture.Size * scale;
            ImGui.SetCursorPos(new Vector2(Math.Max(0f, (available.X - size.X) * 0.5f), Math.Max(0f, (available.Y - size.Y) * 0.5f)));
            ImGui.Image(texture.Handle, size);
        }
        ImGui.EndChild();
        ImGui.PopStyleColor();
    }

    private void DrawDiscoverResultRow(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        var availabilityStyle = PushUnavailableListingStyle(
            IsListingCurrentlyAvailable(plugin, installedPlugin, currentApi, currentDalamudVersion));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, 8f);
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 1f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.045f, 0.052f, 0.064f, 0.76f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.18f, 0.20f, 0.23f, 0.48f));
        ImGui.BeginChild($"discover-result-{plugin.InternalName}", new Vector2(0f, DiscoverListRowHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var rowWidth = ImGui.GetContentRegionAvail().X;
        var start = ImGui.GetCursorScreenPos();
        ImGui.SetCursorPos(new Vector2(12f, 18f));
        DrawPluginArtwork(plugin, installedPlugin, DiscoverListIconSize, DiscoverListIconSize, currentApi, currentDalamudVersion,
            queueIfVisible: true, showOverlays: false);
        ImGui.SameLine(0f, 16f);
        ImGui.BeginGroup();
        ImGui.SetCursorPosY(18f);
        ImGui.TextUnformatted(Shorten(plugin.Name, 52));
        var authorText = string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author;
        var category = PrimaryPluginCategory(plugin);
        ImGui.TextDisabled(string.IsNullOrWhiteSpace(category) ? authorText : $"{authorText}  •  {category}");
        ImGui.Spacing();
        var content = GetDiscoverPresentation(plugin);
        if (!string.IsNullOrWhiteSpace(content.Summary))
        {
            ImGui.PushTextWrapPos(Math.Max(220f, rowWidth - 235f));
            ImGui.TextWrapped(Shorten(content.Summary.Replace('\n', ' '), 150));
            ImGui.PopTextWrapPos();
        }
        ImGui.EndGroup();

        DrawDiscoverRowBadges(plugin, installedPlugin, content, rowWidth);
        var hovered = ImGui.IsWindowHovered(ImGuiHoveredFlags.ChildWindows);
        if (hovered && ImGui.IsMouseClicked(ImGuiMouseButton.Left))
            OpenPluginDetails(plugin);
        if (hovered)
            ImGui.GetWindowDrawList().AddRect(start, start + new Vector2(ImGui.GetWindowSize().X - 1f, DiscoverListRowHeight - 1f),
                ImGui.ColorConvertFloat4ToU32(new Vector4(0.18f, 0.54f, 0.54f, 0.58f)), 8f, ImDrawFlags.None, 1.2f);

        ImGui.EndChild();
        ImGui.PopStyleColor(2);
        ImGui.PopStyleVar(2);
        PopUnavailableListingStyle(availabilityStyle);
    }

    private void DrawDiscoverRowBadges(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        MarketplacePresentationContent content,
        float rowWidth)
    {
        var x = Math.Max(0f, rowWidth - 132f);
        var y = 18f;
        if (content.IsEnhanced)
        {
            ImGui.SetCursorPos(new Vector2(x + 92f, y));
            ImGui.TextColored(new Vector4(0.94f, 0.78f, 0.27f, 1f), "★");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("Enhanced listing: public project metadata indexed by Omega.");
        }
        if (catalog.GetVariants(plugin.InternalName).Any(v => v.SourceIsOfficial))
        {
            ImGui.SetCursorPos(new Vector2(x, y));
            DrawDiscoverTextBadge("Official", new Vector4(0.09f, 0.38f, 0.44f, 0.92f));
            y += 30f;
        }
        if (IsNsfwPlugin(plugin))
        {
            ImGui.SetCursorPos(new Vector2(x, y));
            DrawDiscoverTextBadge("NSFW", new Vector4(0.56f, 0.16f, 0.22f, 0.94f));
            y += 30f;
        }
        if (installedPlugin is not null)
        {
            ImGui.SetCursorPos(new Vector2(x, y));
            ImGui.TextDisabled("Installed");
        }
    }

    private MarketplacePresentationContent GetDiscoverPresentation(MarketplacePlugin plugin)
    {
        EnsureDiscoverPresentationCache();
        if (discoverPresentationCache.TryGetValue(plugin.InternalName, out var cached))
            return cached;
        var content = MarketplacePresentationRules.Choose(plugin, catalog.GetPresentationVariants(plugin.InternalName));
        discoverPresentationCache[plugin.InternalName] = content;
        return content;
    }

    private void EnsureDiscoverPresentationCache()
    {
        if (discoverPresentationRevision == catalog.Revision)
            return;
        discoverPresentationRevision = catalog.Revision;
        discoverPresentationCache.Clear();
    }

    private static void DrawDiscoverTextBadge(string label, Vector4 color)
    {
        var size = new Vector2(Math.Max(72f, ImGui.CalcTextSize(label).X + 22f), 24f);
        var min = ImGui.GetCursorScreenPos();
        var draw = ImGui.GetWindowDrawList();
        draw.AddRectFilled(min, min + size, ImGui.ColorConvertFloat4ToU32(color), 6f);
        var textSize = ImGui.CalcTextSize(label);
        draw.AddText(min + new Vector2((size.X - textSize.X) * 0.5f, (size.Y - textSize.Y) * 0.5f), 0xFFFFFFFF, label);
        ImGui.Dummy(size);
    }

    private static string PrimaryPluginCategory(MarketplacePlugin plugin)
        => plugin.EffectiveCategories.FirstOrDefault()
           ?? plugin.Tags.FirstOrDefault(x => !IsContentRatingTag(x))
           ?? string.Empty;
}
