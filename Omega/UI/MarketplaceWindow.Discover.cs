using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Plugin;

namespace Dalagab.Omega;

/// <summary>
/// Owns Discover's user-selectable presentation. Dynamic keeps the screenshot-rich Store cards plus
/// list fallback, CompactCards renders every plugin as a smaller icon-first card, and List renders
/// every plugin as a dense row. All modes open the same product page and stay virtualized.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private const int DiscoverRichColumns = 3;
    private const int DiscoverCompactColumns = 4;
    private const float DiscoverRichCardHeight = 314f;
    private const float DiscoverCompactCardHeight = 132f;
    private const float DiscoverCompactCardGap = 12f;
    private const float DiscoverCompactIconSize = 54f;
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
    private Vector2? discoverListingClipMin;
    private Vector2? discoverListingClipMax;

    private void DrawDiscoverList(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        EnsureDiscoverPresentationCache();

        ImGui.BeginChild("omega-discover-results", Vector2.Zero, false, ImGuiWindowFlags.AlwaysVerticalScrollbar);
        // The ribbon clip must be anchored to the child WINDOW, not its content region.
        // Content-region coordinates include the current scroll offset, which caused the clip
        // rectangle itself to travel upward while scrolling and let buffered/off-screen ribbons
        // escape into Discover's search/filter header. The window rectangle stays fixed on screen.
        var resultsWindowPos = ImGui.GetWindowPos();
        var resultsWindowSize = ImGui.GetWindowSize();
        discoverListingClipMin = resultsWindowPos;
        discoverListingClipMax = resultsWindowPos + resultsWindowSize;
        if (resetDiscoverListScroll)
        {
            ImGui.SetScrollY(0f);
            resetDiscoverListScroll = false;
        }

        switch (configuration.DiscoverLayout)
        {
            case DiscoverLayoutMode.CompactCards:
                DrawDiscoverCompactResults(plugins, installed, currentApi, currentDalamudVersion);
                break;
            case DiscoverLayoutMode.List:
                DrawDiscoverListResults(plugins, installed, currentApi, currentDalamudVersion);
                break;
            default:
            {
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
                DrawDiscoverHybridResults(rich, basic, installed, currentApi, currentDalamudVersion);
                break;
            }
        }

        discoverListingClipMin = null;
        discoverListingClipMax = null;
        ImGui.EndChild();
    }

    private void DrawDiscoverCompactResults(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (plugins.Count == 0)
            return;

        var contentStartY = ImGui.GetCursorPosY();
        var availableWidth = Math.Max(Ui(1f), ImGui.GetContentRegionAvail().X - Ui(4f));
        var columns = ResponsiveColumns(availableWidth, 205f, DiscoverCompactColumns, DiscoverCompactCardGap);
        var gap = Ui(DiscoverCompactCardGap);
        var cardWidth = ResponsiveCardWidth(availableWidth, columns, DiscoverCompactCardGap, 180f);
        var cardHeight = Ui(DiscoverCompactCardHeight);
        var stride = cardHeight + gap;
        var visible = StorefrontVirtualization.Calculate(
            plugins.Count,
            columns,
            stride,
            ImGui.GetScrollY(),
            ImGui.GetWindowHeight(),
            contentStartY,
            bufferRows: 2);

        for (var row = visible.FirstRow; row < visible.LastRowExclusive; row++)
        {
            for (var column = 0; column < columns; column++)
            {
                var index = (row * columns) + column;
                if (index >= plugins.Count)
                    break;

                var plugin = plugins[index];
                installed.TryGetValue(plugin.InternalName, out var installedPlugin);
                ImGui.SetCursorPos(new Vector2(
                    column * (cardWidth + gap),
                    contentStartY + (row * stride)));
                DrawDiscoverCompactCard(plugin, installedPlugin, currentApi, currentDalamudVersion, cardWidth);
            }
        }

        ImGui.SetCursorPosY(contentStartY + (visible.TotalRows * stride));
        ImGui.Dummy(Ui(1f, 1f));
    }

    private void DrawDiscoverCompactCard(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion,
        float cardWidth)
    {
        var availabilityStyle = PushUnavailableListingStyle(
            IsListingCurrentlyAvailable(plugin, installedPlugin, currentApi, currentDalamudVersion));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, Ui(8f));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 1f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.045f, 0.052f, 0.064f, 0.76f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.18f, 0.20f, 0.23f, 0.48f));
        ImGui.BeginChild($"discover-compact-{plugin.InternalName}",
            new Vector2(cardWidth, Ui(DiscoverCompactCardHeight)), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var cardMin = ImGui.GetWindowPos();
        var cardMax = cardMin + ImGui.GetWindowSize();
        ImGui.SetCursorPos(Ui(12f, 38f));
        var artworkClicked = DrawPluginArtwork(
            plugin, installedPlugin, Ui(DiscoverCompactIconSize), Ui(DiscoverCompactIconSize), currentApi, currentDalamudVersion,
            queueIfVisible: true, showOverlays: false, showInstalledMarker: false, showListingRibbons: true,
            listingPanelMin: cardMin, listingPanelMax: cardMax);

        ImGui.SameLine(0f, Ui(10f));
        ImGui.BeginGroup();
        ImGui.SetCursorPosY(Ui(40f));
        DrawDiscoverPluginTitle(Shorten(plugin.Name, 28), installedPlugin is not null);
        var author = string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author;
        ImGui.TextDisabled(Shorten(author, 30));
        var category = PrimaryPluginCategory(plugin);
        if (!string.IsNullOrWhiteSpace(category))
            ImGui.TextDisabled(Shorten(category, 30));
        ImGui.EndGroup();

        var hovered = ImGui.IsWindowHovered(ImGuiHoveredFlags.ChildWindows);
        if (artworkClicked || (hovered && ImGui.IsMouseClicked(ImGuiMouseButton.Left)))
            OpenPluginDetails(plugin);
        DrawPluginPanelUpdateState(plugin, installedPlugin, currentApi, currentDalamudVersion, cardMax);
        ImGui.EndChild();

        if (hovered)
        {
            ImGui.GetWindowDrawList().AddRect(
                cardMin + Ui(0.5f, 0.5f),
                cardMax - Ui(0.5f, 0.5f),
                ImGui.ColorConvertFloat4ToU32(new Vector4(0.18f, 0.54f, 0.54f, 0.48f)),
                Ui(8f),
                ImDrawFlags.None,
                Ui(1.2f));
        }

        ImGui.PopStyleColor(2);
        ImGui.PopStyleVar(2);
        PopUnavailableListingStyle(availabilityStyle);
    }

    private void DrawDiscoverListResults(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (plugins.Count == 0)
            return;

        var contentStartY = ImGui.GetCursorPosY();
        var stride = Ui(DiscoverListRowHeight + DiscoverListRowGap);
        var visible = StorefrontVirtualization.Calculate(
            plugins.Count,
            1,
            stride,
            ImGui.GetScrollY(),
            ImGui.GetWindowHeight(),
            contentStartY,
            bufferRows: 2);

        for (var index = visible.FirstRow; index < visible.LastRowExclusive && index < plugins.Count; index++)
        {
            ImGui.SetCursorPosY(contentStartY + (index * stride));
            var plugin = plugins[index];
            installed.TryGetValue(plugin.InternalName, out var installedPlugin);
            DrawDiscoverResultRow(plugin, installedPlugin, currentApi, currentDalamudVersion);
        }

        ImGui.SetCursorPosY(contentStartY + (visible.TotalRows * stride));
        ImGui.Dummy(Ui(1f, 1f));
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

            var gridStartY = contentStartY + Ui(30f);
            var availableWidth = Math.Max(Ui(1f), ImGui.GetContentRegionAvail().X - Ui(4f));
            var columns = ResponsiveColumns(availableWidth, 250f, DiscoverRichColumns, DiscoverRichColumnGap);
            var columnGap = Ui(DiscoverRichColumnGap);
            var cardWidth = ResponsiveCardWidth(availableWidth, columns, DiscoverRichColumnGap, 220f);
            const float gridStartX = 0f;
            var cardHeight = Ui(DiscoverRichCardHeight);
            var stride = cardHeight + Ui(DiscoverRichRowGap);
            var visible = StorefrontVirtualization.Calculate(
                rich.Count,
                columns,
                stride,
                ImGui.GetScrollY(),
                ImGui.GetWindowHeight(),
                gridStartY,
                bufferRows: 1);

            for (var row = visible.FirstRow; row < visible.LastRowExclusive; row++)
            {
                for (var column = 0; column < columns; column++)
                {
                    var index = (row * columns) + column;
                    if (index >= rich.Count)
                        break;
                    var entry = rich[index];
                    installed.TryGetValue(entry.Plugin.InternalName, out var installedPlugin);
                    ImGui.SetCursorPos(new Vector2(
                        gridStartX + (column * (cardWidth + columnGap)),
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
            var listHeaderY = cursorEndY + (rich.Count > 0 ? Ui(12f) : 0f);
            ImGui.SetCursorPosY(listHeaderY);
            ImGui.TextUnformatted("The rest");

            var listStartY = listHeaderY + Ui(30f);
            var stride = Ui(DiscoverListRowHeight + DiscoverListRowGap);
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
        ImGui.Dummy(new Vector2(Ui(1f), Ui(1f)));
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
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, Ui(9f));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 1f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.045f, 0.052f, 0.064f, 0.78f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.18f, 0.20f, 0.23f, 0.48f));
        ImGui.BeginChild(
            $"discover-rich-{plugin.InternalName}",
            new Vector2(cardWidth, Ui(DiscoverRichCardHeight)),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var cardMin = ImGui.GetWindowPos();
        var cardMax = cardMin + ImGui.GetWindowSize();
        var artworkClicked = DrawDiscoverRichCardHeader(
            plugin, content, installedPlugin, currentApi, currentDalamudVersion, cardWidth, cardMin, cardMax);
        var screenshotClicked = DrawDiscoverRichCardScreenshot(plugin.InternalName, content.Images[0], cardWidth);

        var hovered = ImGui.IsWindowHovered(ImGuiHoveredFlags.ChildWindows);
        if (artworkClicked || (!screenshotClicked && hovered && ImGui.IsMouseClicked(ImGuiMouseButton.Left)))
            OpenPluginDetails(plugin);
        DrawPluginPanelUpdateState(plugin, installedPlugin, currentApi, currentDalamudVersion, cardMax);
        ImGui.EndChild();
        if (hovered)
        {
            ImGui.GetWindowDrawList().AddRect(
                cardMin + Ui(0.5f, 0.5f),
                cardMax - Ui(0.5f, 0.5f),
                ImGui.ColorConvertFloat4ToU32(new Vector4(0.18f, 0.54f, 0.54f, 0.44f)),
                Ui(9f),
                ImDrawFlags.None,
                Ui(1.2f));
        }
        ImGui.PopStyleColor(2);
        ImGui.PopStyleVar(2);
        PopUnavailableListingStyle(availabilityStyle);
    }

    private bool DrawDiscoverRichCardHeader(
        MarketplacePlugin plugin,
        MarketplacePresentationContent content,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion,
        float cardWidth,
        Vector2 cardMin,
        Vector2 cardMax)
    {
        var installed = installedPlugin is not null;
        ImGui.SetCursorPos(Ui(12f, 12f));
        var artworkClicked = DrawPluginArtwork(
            plugin, installedPlugin, Ui(46f), Ui(46f), currentApi, currentDalamudVersion,
            queueIfVisible: true, showOverlays: false, showInstalledMarker: false, showListingRibbons: true,
            listingPanelMin: cardMin, listingPanelMax: cardMax);
        ImGui.SameLine(0f, Ui(10f));
        ImGui.BeginGroup();
        DrawDiscoverPluginTitle(Shorten(plugin.Name, 32), installed);
        var author = string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author;
        var category = PrimaryPluginCategory(plugin);
        ImGui.TextDisabled(Shorten(string.IsNullOrWhiteSpace(category) ? author : $"{author}  •  {category}", 42));
        ImGui.EndGroup();

        var rightEdge = Math.Max(Ui(70f), cardWidth - Ui(12f));
        DrawDiscoverOriginAndContentBadges(plugin, rightEdge, Ui(42f));

        ImGui.SetCursorPos(Ui(12f, 70f));
        if (!string.IsNullOrWhiteSpace(content.Summary))
        {
            ImGui.PushTextWrapPos(cardWidth - Ui(12f));
            ImGui.TextWrapped(Shorten(content.Summary.Replace('\n', ' '), 155));
            ImGui.PopTextWrapPos();
        }
        return artworkClicked;
    }

    private bool DrawDiscoverRichCardScreenshot(string internalName, string url, float cardWidth)
    {
        var screenshotY = Ui(DiscoverRichCardHeight - DiscoverRichScreenshotHeight - 12f);
        ImGui.SetCursorPos(new Vector2(Ui(12f), screenshotY));
        var width = Math.Max(Ui(120f), cardWidth - Ui(24f));
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.025f, 0.030f, 0.038f, 0.90f));
        ImGui.BeginChild($"discover-rich-image-{StableId(internalName)}-{StableId(url)}", new Vector2(width, Ui(DiscoverRichScreenshotHeight)), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
        var texture = iconCache.GetOrQueue(url);
        if (texture is null || texture.Size.X <= 0 || texture.Size.Y <= 0)
        {
            var text = "Loading preview…";
            var size = ImGui.CalcTextSize(text);
            SetCursorCenteredInCurrentContent(size);
            ImGui.TextDisabled(text);
        }
        else
        {
            var contentSize = ImGui.GetWindowContentRegionMax() - ImGui.GetWindowContentRegionMin();
            var scale = Math.Min(contentSize.X / texture.Size.X, contentSize.Y / texture.Size.Y);
            var size = texture.Size * scale;
            SetCursorCenteredInCurrentContent(size);
            ImGui.Image(texture.Handle, size);
        }

        var screenshotHovered = ImGui.IsWindowHovered();
        var screenshotClicked = screenshotHovered && ImGui.IsMouseClicked(ImGuiMouseButton.Left);
        if (screenshotHovered)
            SetReadableTooltip("View larger screenshot");

        ImGui.EndChild();
        ImGui.PopStyleColor();

        if (screenshotClicked)
            OpenScreenshotViewer(url);
        return screenshotClicked;
    }

    private void DrawDiscoverResultRow(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        var availabilityStyle = PushUnavailableListingStyle(
            IsListingCurrentlyAvailable(plugin, installedPlugin, currentApi, currentDalamudVersion));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, Ui(8f));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 1f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.045f, 0.052f, 0.064f, 0.76f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.18f, 0.20f, 0.23f, 0.48f));
        ImGui.BeginChild($"discover-result-{plugin.InternalName}", new Vector2(0f, Ui(DiscoverListRowHeight)), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var rowWidth = ImGui.GetContentRegionAvail().X;
        var rowMin = ImGui.GetWindowPos();
        var rowMax = rowMin + ImGui.GetWindowSize();
        var installed = installedPlugin is not null;
        ImGui.SetCursorPos(Ui(12f, 18f));
        var artworkClicked = DrawPluginArtwork(
            plugin, installedPlugin, Ui(DiscoverListIconSize), Ui(DiscoverListIconSize), currentApi, currentDalamudVersion,
            queueIfVisible: true, showOverlays: false, showInstalledMarker: false, showListingRibbons: true,
            listingPanelMin: rowMin, listingPanelMax: rowMax);
        ImGui.SameLine(0f, Ui(16f));
        ImGui.BeginGroup();
        ImGui.SetCursorPosY(Ui(18f));
        DrawDiscoverPluginTitle(Shorten(plugin.Name, 52), installed);
        var authorText = string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author;
        var category = PrimaryPluginCategory(plugin);
        ImGui.TextDisabled(string.IsNullOrWhiteSpace(category) ? authorText : $"{authorText}  •  {category}");
        ImGui.Spacing();
        var content = GetDiscoverPresentation(plugin);
        if (!string.IsNullOrWhiteSpace(content.Summary))
        {
            ImGui.PushTextWrapPos(Math.Max(Ui(220f), rowWidth - Ui(235f)));
            ImGui.TextWrapped(Shorten(content.Summary.Replace('\n', ' '), 150));
            ImGui.PopTextWrapPos();
        }
        ImGui.EndGroup();

        DrawDiscoverRowBadges(plugin, content, rowWidth, currentApi, currentDalamudVersion);
        var hovered = ImGui.IsWindowHovered(ImGuiHoveredFlags.ChildWindows);
        if (artworkClicked || (hovered && ImGui.IsMouseClicked(ImGuiMouseButton.Left)))
            OpenPluginDetails(plugin);
        if (hovered)
            ImGui.GetWindowDrawList().AddRect(
                rowMin + Ui(0.5f, 0.5f),
                rowMax - Ui(0.5f, 0.5f),
                ImGui.ColorConvertFloat4ToU32(new Vector4(0.18f, 0.54f, 0.54f, 0.58f)),
                Ui(8f),
                ImDrawFlags.None,
                Ui(1.2f));

        DrawPluginPanelUpdateState(plugin, installedPlugin, currentApi, currentDalamudVersion, rowMax);
        ImGui.EndChild();
        ImGui.PopStyleColor(2);
        ImGui.PopStyleVar(2);
        PopUnavailableListingStyle(availabilityStyle);
    }

    private void DrawDiscoverRowBadges(
        MarketplacePlugin plugin,
        MarketplacePresentationContent content,
        float rowWidth,
        int currentApi,
        Version currentDalamudVersion)
    {
        var rightEdge = Math.Max(Ui(70f), rowWidth - Ui(12f));
        DrawDiscoverOriginAndContentBadges(plugin, rightEdge, Ui(50f));
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
        var size = new Vector2(Math.Max(Ui(72f), ImGui.CalcTextSize(label).X + Ui(22f)), Ui(24f));
        var min = ImGui.GetCursorScreenPos();
        var draw = ImGui.GetWindowDrawList();
        draw.AddRectFilled(min, min + size, ImGui.ColorConvertFloat4ToU32(color), Ui(6f));
        var textSize = ImGui.CalcTextSize(label);
        draw.AddText(min + new Vector2((size.X - textSize.X) * 0.5f, (size.Y - textSize.Y) * 0.5f), 0xFFFFFFFF, label);
        ImGui.Dummy(size);
    }


    private readonly record struct PluginAutomationState(
        Vector4 Color,
        string Tooltip);

    private void DrawDiscoverTopRightIndicators(
        MarketplacePlugin plugin,
        MarketplacePresentationContent content,
        int currentApi,
        Version currentDalamudVersion,
        float rightEdge,
        float y)
    {
        var iconSize = Ui(22f);
        var gap = Ui(7f);
        var unavailable = !HasInstallableVariant(plugin.InternalName, currentApi, currentDalamudVersion);
        var hasPrimaryMarker = unavailable || content.IsEnhanced;
        var primaryX = rightEdge - iconSize;
        var securityRightEdge = hasPrimaryMarker ? primaryX - gap : rightEdge;

        // Listing security must describe the same default repository package the user will see
        // after opening the product page. Automation is a separate capability marker and must
        // never replace the scan-result icon.
        var securityPlugin = ResolveDefaultVariant(plugin);
        _ = DrawPluginScanAndAutomationIndicators(securityPlugin, securityRightEdge, y, iconSize, gap);

        if (unavailable)
        {
            ImGui.SetCursorPos(new Vector2(primaryX, y));
            DrawDiscoverStatusGlyph(
                "↓",
                new Vector4(0.88f, 0.18f, 0.20f, 1f),
                DescribeInstallUnavailability(plugin.InternalName, currentApi, currentDalamudVersion),
                iconSize);
        }
        else if (content.IsEnhanced)
        {
            ImGui.SetCursorPos(new Vector2(primaryX, y));
            DrawDiscoverStarIndicator(iconSize);
        }
    }

    private bool DrawPluginScanAndAutomationIndicators(
        MarketplacePlugin plugin,
        float rightEdge,
        float y,
        float iconSize,
        float gap)
    {
        var scanX = rightEdge - iconSize;
        ImGui.SetCursorPos(new Vector2(scanX, y));
        DrawPluginSigmascopeIndicator(plugin, iconSize);
        var hovered = ImGui.IsItemHovered();

        var nextX = scanX - gap - iconSize;
        if (plugin.HasKnownAtRiskDependency)
        {
            var tooltip = configuration.ShowAdvancedSecurityInformation
                ? $"Known risk: OSV reports {plugin.SecurityKnownAdvisoryCount} {(plugin.SecurityKnownAdvisoryCount == 1 ? "advisory" : "advisories")} affecting dependency versions used by this plugin package. Highest advisory severity: {plugin.SecurityKnownAdvisoryHighestSeverity}."
                : $"A library used by this plugin has {plugin.SecurityKnownAdvisoryCount} known security {(plugin.SecurityKnownAdvisoryCount == 1 ? "problem" : "problems")}.";
            ImGui.SetCursorPos(new Vector2(nextX, y));
            DrawPluginFontAwesomeRiskIcon(FontAwesomeIcon.ExclamationTriangle, new Vector4(0.96f, 0.16f, 0.19f, 1f), tooltip, iconSize);
            hovered |= ImGui.IsItemHovered();
            nextX -= gap + iconSize;
        }

        var automation = GetPluginAutomationState(plugin);
        if (automation is null)
            return hovered;

        ImGui.SetCursorPos(new Vector2(nextX, y));
        DrawPluginRadiationIcon(automation.Value.Color, automation.Value.Tooltip, iconSize);
        return hovered || ImGui.IsItemHovered();
    }

    private void DrawDiscoverOriginAndContentBadges(MarketplacePlugin plugin, float rightEdge, float y)
    {
        var official = catalog.GetVariants(plugin.InternalName).Any(v => v.SourceIsOfficial) || plugin.SourceIsOfficial;
        if (official)
        {
            ImGui.SetCursorPos(new Vector2(rightEdge - Ui(26f), y));
            DrawDalamudOfficialLogoBadge(Ui(26f));
        }

        if (IsNsfwPlugin(plugin))
        {
            var nsfwWidth = Ui(72f);
            var x = official ? rightEdge - Ui(26f) - Ui(8f) - nsfwWidth : rightEdge - nsfwWidth;
            ImGui.SetCursorPos(new Vector2(Math.Max(0f, x), y + Ui(1f)));
            DrawDiscoverTextBadge("18+", new Vector4(0.56f, 0.16f, 0.22f, 0.94f));
        }
    }

    private PluginAutomationState? GetPluginAutomationState(MarketplacePlugin plugin)
    {
        if (pluginAutomationStateCatalogRevision != catalog.Revision)
        {
            pluginAutomationStateCatalogRevision = catalog.Revision;
            pluginAutomationStateCache.Clear();
        }

        var cacheKey = $"{plugin.InternalName}\u001f{plugin.SourceUrl}\u001f{plugin.AssemblyVersionText}\u001f{plugin.SecurityArtifactSha256}\u001f{configuration.ShowAdvancedSecurityInformation}";
        if (pluginAutomationStateCache.TryGetValue(cacheKey, out var cached))
            return cached;

        var state = ResolvePluginAutomationState(plugin);
        pluginAutomationStateCache[cacheKey] = state;
        return state;
    }

    private PluginAutomationState? ResolvePluginAutomationState(MarketplacePlugin plugin)
    {
        // Automation is deliberately separate from scan severity. A radiation marker may be added
        // beside the scan icon, but it can never replace or recolor the package's scan result.
        if (!plugin.HasCompletedSecurityScan)
            return null;

        if (HasPluginAutomation(plugin))
        {
            return new PluginAutomationState(
                new Vector4(0.96f, 0.76f, 0.10f, 1f),
                configuration.ShowAdvancedSecurityInformation
                    ? $"Automation capability observed: {AutomationLevelLabel(plugin.SecurityAutomationLevel)}. Open the plugin page for the static-analysis evidence."
                    : "This plugin can automate actions in the game.");
        }

        var dependencyAutomation = FindRequiredDependencyAutomation(
            plugin,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            depth: 0);
        if (dependencyAutomation is null)
            return null;

        return new PluginAutomationState(
            new Vector4(0.96f, 0.76f, 0.10f, 1f),
            configuration.ShowAdvancedSecurityInformation
                ? $"Automation exposure through required dependency {dependencyAutomation.DependencyName}: {AutomationLevelLabel(dependencyAutomation.AutomationLevel)}. Path: {dependencyAutomation.Path}."
                : $"This plugin needs {dependencyAutomation.DependencyName}, which can automate actions in the game.");
    }

    private sealed record DependencyAutomationMatch(string DependencyName, string AutomationLevel, string Path);

    private DependencyAutomationMatch? FindRequiredDependencyAutomation(
        MarketplacePlugin plugin,
        HashSet<string> visited,
        int depth)
    {
        const int maximumDependencyRiskDepth = 8;
        var visitKey = $"{plugin.InternalName}\u001f{plugin.SourceUrl}";
        if (depth >= maximumDependencyRiskDepth || !visited.Add(visitKey) || !plugin.HasCompletedSecurityScan)
            return null;

        var dependencies = plugin.SecurityDependencies
            .Where(x => IsRequiredDependency(x) && x.IsPluginDependency && !string.IsNullOrWhiteSpace(x.TargetInternalName))
            .GroupBy(x => x.TargetInternalName, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .ToArray();

        foreach (var dependency in dependencies)
        {
            var targetSeed = catalog.GetVariants(dependency.TargetInternalName).FirstOrDefault();
            if (targetSeed is null)
                continue;

            // Dependency automation follows the same default-package rule as normal product navigation.
            var target = ResolveDefaultVariant(targetSeed);
            if (!target.HasCompletedSecurityScan)
                continue;

            var targetName = string.IsNullOrWhiteSpace(target.Name) ? dependency.Name : target.Name;
            if (string.IsNullOrWhiteSpace(targetName))
                targetName = dependency.TargetInternalName;

            if (HasPluginAutomation(target))
            {
                return new DependencyAutomationMatch(
                    targetName,
                    target.SecurityAutomationLevel,
                    $"{plugin.InternalName} → {dependency.TargetInternalName}");
            }

            var nestedVisited = new HashSet<string>(visited, StringComparer.OrdinalIgnoreCase);
            var nested = FindRequiredDependencyAutomation(target, nestedVisited, depth + 1);
            if (nested is not null)
            {
                var prefix = $"{plugin.InternalName} → ";
                var nestedPath = nested.Path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                    ? nested.Path
                    : prefix + nested.Path;
                return nested with { Path = nestedPath };
            }
        }

        return null;
    }

    private static bool HasPluginAutomation(MarketplacePlugin plugin)
        => AutomationRank(plugin.SecurityAutomationLevel) >= AutomationRank("ui-automation") ||
           plugin.SecurityAutomationCapabilities.Any(x => AutomationRank(x.AutomationLevel) >= AutomationRank("ui-automation"));

    private static int AutomationRank(string? level)
        => (level ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "full-gameplay-automation" => 4,
            "character-automation" => 3,
            "ui-automation" => 2,
            "observational" => 1,
            _ => 0,
        };

    private static void DrawPluginFontAwesomeRiskIcon(FontAwesomeIcon icon, Vector4 color, string tooltip, float size)
    {
        var min = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##discover-risk-icon-{icon}-{ImGui.GetID(tooltip)}", new Vector2(size, size));
        var draw = ImGui.GetWindowDrawList();

        // Use Dalamud's bundled Font Awesome font for consistent marketplace status glyphs.
        // The fixed-width icon font lets us center by the actual glyph bounds instead of hand-tuning
        // punctuation inside a custom triangle.
        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = icon.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        var glyphPos = min + new Vector2(
            (size - glyphSize.X) * 0.5f,
            (size - glyphSize.Y) * 0.5f);
        draw.AddText(glyphPos, ImGui.ColorConvertFloat4ToU32(color), glyph);
        ImGui.PopFont();

        if (ImGui.IsItemHovered())
            SetReadableTooltip(tooltip);
    }

    private static void DrawPluginRadiationIcon(Vector4 color, string tooltip, float size)
    {
        var min = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##discover-risk-radiation-{ImGui.GetID(tooltip)}", new Vector2(size, size));
        var draw = ImGui.GetWindowDrawList();
        var center = min + new Vector2(size * 0.5f, size * 0.5f);
        var outerRadius = size * 0.47f;
        var innerRadius = size * 0.16f;
        var dark = ImGui.ColorConvertFloat4ToU32(new Vector4(0.045f, 0.050f, 0.055f, 1f));
        draw.AddCircleFilled(center, outerRadius, ImGui.ColorConvertFloat4ToU32(color), 28);

        for (var blade = 0; blade < 3; blade++)
        {
            var angle = (-MathF.PI * 0.5f) + (blade * (MathF.PI * 2f / 3f));
            const float spread = 0.52f;
            var inner = center + new Vector2(MathF.Cos(angle), MathF.Sin(angle)) * innerRadius;
            var outerA = center + new Vector2(MathF.Cos(angle - spread), MathF.Sin(angle - spread)) * (outerRadius * 0.86f);
            var outerB = center + new Vector2(MathF.Cos(angle + spread), MathF.Sin(angle + spread)) * (outerRadius * 0.86f);
            draw.AddTriangleFilled(inner, outerA, outerB, dark);
        }
        draw.AddCircleFilled(center, size * 0.095f, dark, 16);

        if (ImGui.IsItemHovered())
            SetReadableTooltip(tooltip);
    }

    private static void DrawDiscoverPluginTitle(string title, bool installed)
    {
        if (installed)
            ImGui.TextColored(new Vector4(0.69f, 0.71f, 0.75f, 1f), title);
        else
            ImGui.TextUnformatted(title);
    }

    private static void DrawDiscoverInstalledMarker(Vector2 artworkMin, float artworkSize)
    {
        // Installed state is an artwork overlay, never part of row/card geometry. This helper
        // is called from inside the artwork child so the marker is guaranteed to render above
        // the plugin image while installed and uninstalled icons remain identically aligned.
        var size = Math.Clamp(artworkSize * 0.32f, Ui(18f), Ui(24f));
        var min = artworkMin + Ui(3f, 3f);
        var center = min + new Vector2(size * 0.5f, size * 0.5f);
        var draw = ImGui.GetWindowDrawList();
        var markerBorder = ImGui.ColorConvertFloat4ToU32(new Vector4(0.025f, 0.030f, 0.038f, 0.98f));
        var installedGreen = ImGui.ColorConvertFloat4ToU32(new Vector4(0.20f, 0.72f, 0.42f, 0.98f));
        var checkColor = ImGui.ColorConvertFloat4ToU32(new Vector4(0.97f, 1.00f, 0.98f, 1f));

        // The dark rim keeps the installed check legible on bright or green plugin artwork.
        draw.AddCircleFilled(center, size * 0.52f, markerBorder, 24);
        draw.AddCircleFilled(center, size * 0.44f, installedGreen, 24);
        var a = min + new Vector2(size * 0.25f, size * 0.51f);
        var b = min + new Vector2(size * 0.43f, size * 0.68f);
        var c = min + new Vector2(size * 0.77f, size * 0.32f);
        var stroke = Math.Clamp(size * 0.105f, Ui(2f), Ui(2.6f));
        draw.AddLine(a, b, checkColor, stroke);
        draw.AddLine(b, c, checkColor, stroke);
    }

    private static void DrawDiscoverStarIndicator(float size)
    {
        var min = ImGui.GetCursorScreenPos();
        ImGui.Dummy(new Vector2(size, size));
        const string glyph = "★";
        var glyphSize = ImGui.CalcTextSize(glyph);
        ImGui.GetWindowDrawList().AddText(
            min + new Vector2((size - glyphSize.X) * 0.5f, (size - glyphSize.Y) * 0.5f),
            ImGui.ColorConvertFloat4ToU32(new Vector4(0.94f, 0.78f, 0.27f, 1f)),
            glyph);
        if (ImGui.IsItemHovered())
            SetReadableTooltip("Enhanced listing: public project metadata indexed by Omega.");
    }

    private static void DrawDiscoverStatusGlyph(string glyph, Vector4 color, string tooltip, float size)
    {
        var min = ImGui.GetCursorScreenPos();
        ImGui.Dummy(new Vector2(size, size));
        var glyphSize = ImGui.CalcTextSize(glyph);
        ImGui.GetWindowDrawList().AddText(
            min + new Vector2((size - glyphSize.X) * 0.5f, (size - glyphSize.Y) * 0.5f),
            ImGui.ColorConvertFloat4ToU32(color),
            glyph);
        if (ImGui.IsItemHovered())
            SetReadableTooltip(tooltip);
    }

    private static void DrawDalamudOfficialLogoBadge(float size)
    {
        var min = ImGui.GetCursorScreenPos();
        ImGui.Dummy(new Vector2(size, size));
        var draw = ImGui.GetWindowDrawList();
        try
        {
            var texture = Plugin.DalamudAssets.GetDalamudTextureWrap(global::Dalamud.DalamudAsset.LogoSmall);
            var sourceSize = texture.Size;
            var scale = Math.Min((size - 4f) / sourceSize.X, (size - 4f) / sourceSize.Y);
            var drawSize = sourceSize * scale;
            var imageMin = min + new Vector2((size - drawSize.X) * 0.5f, (size - drawSize.Y) * 0.5f);
            draw.AddImage(texture.Handle, imageMin, imageMin + drawSize);
        }
        catch
        {
            const string glyph = "◆";
            var glyphSize = ImGui.CalcTextSize(glyph);
            draw.AddText(
                min + new Vector2((size - glyphSize.X) * 0.5f, (size - glyphSize.Y) * 0.5f),
                ImGui.ColorConvertFloat4ToU32(new Vector4(0.90f, 0.18f, 0.24f, 1f)),
                glyph);
        }
        if (ImGui.IsItemHovered())
            SetReadableTooltip("Dalamud official repository");
    }

    private static string PrimaryPluginCategory(MarketplacePlugin plugin)
        => plugin.EffectiveCategories.FirstOrDefault()
           ?? plugin.Tags.FirstOrDefault(x => !IsContentRatingTag(x))
           ?? string.Empty;
}
