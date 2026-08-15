using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
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
        var artworkClicked = DrawDiscoverRichCardHeader(
            plugin, content, installedPlugin, currentApi, currentDalamudVersion, cardWidth);
        var screenshotClicked = DrawDiscoverRichCardScreenshot(plugin.InternalName, content.Images[0], cardWidth);

        var hovered = ImGui.IsWindowHovered(ImGuiHoveredFlags.ChildWindows);
        if (artworkClicked || (!screenshotClicked && hovered && ImGui.IsMouseClicked(ImGuiMouseButton.Left)))
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

    private bool DrawDiscoverRichCardHeader(
        MarketplacePlugin plugin,
        MarketplacePresentationContent content,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion,
        float cardWidth)
    {
        var installed = installedPlugin is not null;
        if (installed)
            DrawDiscoverInstalledMarker(new Vector2(8f, 22f));

        var artworkX = installed ? 42f : 12f;
        ImGui.SetCursorPos(new Vector2(artworkX, 12f));
        var artworkClicked = DrawPluginArtwork(
            plugin, installedPlugin, 46f, 46f, currentApi, currentDalamudVersion,
            queueIfVisible: true, showOverlays: false);
        ImGui.SameLine(0f, 10f);
        ImGui.BeginGroup();
        DrawDiscoverPluginTitle(Shorten(plugin.Name, 32), installed);
        var author = string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author;
        var category = PrimaryPluginCategory(plugin);
        ImGui.TextDisabled(Shorten(string.IsNullOrWhiteSpace(category) ? author : $"{author}  •  {category}", 42));
        ImGui.EndGroup();

        var rightEdge = Math.Max(70f, cardWidth - 12f);
        DrawDiscoverTopRightIndicators(plugin, content, currentApi, currentDalamudVersion, rightEdge, 12f);
        DrawDiscoverOriginAndContentBadges(plugin, rightEdge, 42f);

        ImGui.SetCursorPos(new Vector2(12f, 70f));
        if (!string.IsNullOrWhiteSpace(content.Summary))
        {
            ImGui.PushTextWrapPos(cardWidth - 12f);
            ImGui.TextWrapped(Shorten(content.Summary.Replace('\n', ' '), 155));
            ImGui.PopTextWrapPos();
        }
        return artworkClicked;
    }

    private bool DrawDiscoverRichCardScreenshot(string internalName, string url, float cardWidth)
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

        var screenshotHovered = ImGui.IsWindowHovered();
        var screenshotClicked = screenshotHovered && ImGui.IsMouseClicked(ImGuiMouseButton.Left);
        if (screenshotHovered)
            ImGui.SetTooltip("View larger screenshot");

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
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, 8f);
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 1f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.045f, 0.052f, 0.064f, 0.76f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.18f, 0.20f, 0.23f, 0.48f));
        ImGui.BeginChild($"discover-result-{plugin.InternalName}", new Vector2(0f, DiscoverListRowHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var rowWidth = ImGui.GetContentRegionAvail().X;
        var start = ImGui.GetCursorScreenPos();
        var installed = installedPlugin is not null;
        if (installed)
            DrawDiscoverInstalledMarker(new Vector2(8f, 44f));
        ImGui.SetCursorPos(new Vector2(installed ? 44f : 12f, 18f));
        var artworkClicked = DrawPluginArtwork(
            plugin, installedPlugin, DiscoverListIconSize, DiscoverListIconSize, currentApi, currentDalamudVersion,
            queueIfVisible: true, showOverlays: false);
        ImGui.SameLine(0f, 16f);
        ImGui.BeginGroup();
        ImGui.SetCursorPosY(18f);
        DrawDiscoverPluginTitle(Shorten(plugin.Name, 52), installed);
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

        DrawDiscoverRowBadges(plugin, content, rowWidth, currentApi, currentDalamudVersion);
        var hovered = ImGui.IsWindowHovered(ImGuiHoveredFlags.ChildWindows);
        if (artworkClicked || (hovered && ImGui.IsMouseClicked(ImGuiMouseButton.Left)))
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
        MarketplacePresentationContent content,
        float rowWidth,
        int currentApi,
        Version currentDalamudVersion)
    {
        var rightEdge = Math.Max(70f, rowWidth - 12f);
        DrawDiscoverTopRightIndicators(plugin, content, currentApi,
            currentDalamudVersion, rightEdge, 18f);
        DrawDiscoverOriginAndContentBadges(plugin, rightEdge, 50f);
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


    private enum PluginRiskIconKind
    {
        FontAwesome,
        Radiation,
    }

    private readonly record struct PluginRiskState(
        PluginRiskIconKind IconKind,
        FontAwesomeIcon Icon,
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
        const float iconSize = 22f;
        const float gap = 7f;
        var unavailable = !HasInstallableVariant(plugin.InternalName, currentApi, currentDalamudVersion);
        var hasPrimaryMarker = unavailable || content.IsEnhanced;
        var primaryX = rightEdge - iconSize;
        var riskX = hasPrimaryMarker ? primaryX - gap - iconSize : primaryX;

        ImGui.SetCursorPos(new Vector2(riskX, y));
        DrawPluginRiskIndicator(plugin, iconSize);

        if (unavailable)
        {
            ImGui.SetCursorPos(new Vector2(primaryX, y));
            DrawDiscoverStatusGlyph(
                "↓",
                new Vector4(0.88f, 0.18f, 0.20f, 1f),
                $"No compatible API {currentApi} package is currently installable from the known sources.",
                iconSize);
        }
        else if (content.IsEnhanced)
        {
            ImGui.SetCursorPos(new Vector2(primaryX, y));
            DrawDiscoverStarIndicator(iconSize);
        }
    }

    private void DrawDiscoverOriginAndContentBadges(MarketplacePlugin plugin, float rightEdge, float y)
    {
        var official = catalog.GetVariants(plugin.InternalName).Any(v => v.SourceIsOfficial) || plugin.SourceIsOfficial;
        if (official)
        {
            ImGui.SetCursorPos(new Vector2(rightEdge - 26f, y));
            DrawDalamudOfficialLogoBadge(26f);
        }

        if (IsNsfwPlugin(plugin))
        {
            var nsfwWidth = 72f;
            var x = official ? rightEdge - 26f - 8f - nsfwWidth : rightEdge - nsfwWidth;
            ImGui.SetCursorPos(new Vector2(Math.Max(0f, x), y + 1f));
            DrawDiscoverTextBadge("NSFW", new Vector4(0.56f, 0.16f, 0.22f, 0.94f));
        }
    }

    private void DrawPluginRiskIndicator(MarketplacePlugin plugin, float size)
    {
        var state = GetPluginRiskState(plugin);
        if (state.IconKind == PluginRiskIconKind.Radiation)
            DrawPluginRadiationIcon(state.Color, state.Tooltip, size);
        else
            DrawPluginFontAwesomeRiskIcon(state.Icon, state.Color, state.Tooltip, size);
    }

    private PluginRiskState GetPluginRiskState(MarketplacePlugin plugin)
    {
        if (pluginRiskStateCatalogRevision != catalog.Revision)
        {
            pluginRiskStateCatalogRevision = catalog.Revision;
            pluginRiskStateCache.Clear();
        }

        if (pluginRiskStateCache.TryGetValue(plugin.InternalName, out var cached))
            return cached;

        var state = ResolvePluginRiskState(plugin);
        pluginRiskStateCache[plugin.InternalName] = state;
        return state;
    }

    private PluginRiskState ResolvePluginRiskState(MarketplacePlugin plugin)
    {
        var variants = new[] { plugin }
            .Concat(catalog.GetPresentationVariants(plugin.InternalName))
            .Where(x => x.HasCompletedSecurityScan)
            .GroupBy(x => $"{x.SourceUrl}\u001f{x.AssemblyVersionText}", StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .ToArray();

        if (variants.Length == 0)
        {
            return new PluginRiskState(
                PluginRiskIconKind.FontAwesome,
                FontAwesomeIcon.Question,
                new Vector4(0.46f, 0.48f, 0.52f, 1f),
                "Unknown: no completed Omega static security scan is available for this plugin yet.");
        }

        var automation = variants
            .Where(HasPluginAutomation)
            .OrderByDescending(x => AutomationRank(x.SecurityAutomationLevel))
            .ThenByDescending(x => SecuritySeverityRank(x.SecurityHighestSeverity))
            .FirstOrDefault();
        if (automation is not null)
        {
            return new PluginRiskState(
                PluginRiskIconKind.Radiation,
                default,
                new Vector4(0.96f, 0.76f, 0.10f, 1f),
                $"Automation capability observed: {AutomationLevelLabel(automation.SecurityAutomationLevel)}. " +
                "Open the plugin page for the static-analysis evidence.");
        }

        var dependencyAutomation = FindRequiredDependencyAutomation(
            plugin.InternalName,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            depth: 0);
        if (dependencyAutomation is not null)
        {
            return new PluginRiskState(
                PluginRiskIconKind.Radiation,
                default,
                new Vector4(0.96f, 0.76f, 0.10f, 1f),
                $"Automation exposure through required dependency {dependencyAutomation.DependencyName}: " +
                $"{AutomationLevelLabel(dependencyAutomation.AutomationLevel)}. Path: {dependencyAutomation.Path}.");
        }

        var highest = variants
            .OrderByDescending(x => SecuritySeverityRank(x.SecurityHighestSeverity))
            .First();
        return (highest.SecurityHighestSeverity ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "critical" or "high" => new PluginRiskState(
                PluginRiskIconKind.FontAwesome,
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.86f, 0.15f, 0.17f, 1f),
                $"High risk: highest static-analysis finding is {highest.SecurityHighestSeverity}."),
            "caution" or "medium" => new PluginRiskState(
                PluginRiskIconKind.FontAwesome,
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.94f, 0.43f, 0.10f, 1f),
                "Medium risk: at least one caution-level static-analysis finding was observed."),
            "low" => new PluginRiskState(
                PluginRiskIconKind.FontAwesome,
                FontAwesomeIcon.ExclamationTriangle,
                new Vector4(0.94f, 0.76f, 0.12f, 1f),
                "Low risk: only low-level static-analysis findings were observed."),
            "informational" => new PluginRiskState(
                PluginRiskIconKind.FontAwesome,
                FontAwesomeIcon.InfoCircle,
                new Vector4(0.18f, 0.48f, 0.82f, 1f),
                "Informational only: no risk finding above informational was observed."),
            _ => new PluginRiskState(
                PluginRiskIconKind.FontAwesome,
                FontAwesomeIcon.InfoCircle,
                new Vector4(0.18f, 0.48f, 0.82f, 1f),
                "No risk findings were observed by the completed static scan."),
        };
    }

    private sealed record DependencyAutomationMatch(string DependencyName, string AutomationLevel, string Path);

    private DependencyAutomationMatch? FindRequiredDependencyAutomation(
        string internalName,
        HashSet<string> visited,
        int depth)
    {
        const int maximumDependencyRiskDepth = 8;
        if (depth >= maximumDependencyRiskDepth || !visited.Add(internalName))
            return null;

        var dependencies = catalog.GetPresentationVariants(internalName)
            .Where(x => x.HasCompletedSecurityScan)
            .SelectMany(x => x.SecurityDependencies)
            .Where(x => IsRequiredDependency(x) && x.IsPluginDependency && !string.IsNullOrWhiteSpace(x.TargetInternalName))
            .GroupBy(x => x.TargetInternalName, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .ToArray();

        foreach (var dependency in dependencies)
        {
            var targetVariants = catalog.GetPresentationVariants(dependency.TargetInternalName)
                .Where(x => x.HasCompletedSecurityScan)
                .ToArray();
            var directAutomation = targetVariants
                .Where(HasPluginAutomation)
                .OrderByDescending(x => AutomationRank(x.SecurityAutomationLevel))
                .FirstOrDefault();
            var targetName = targetVariants.FirstOrDefault()?.Name;
            if (string.IsNullOrWhiteSpace(targetName))
                targetName = dependency.Name;
            if (string.IsNullOrWhiteSpace(targetName))
                targetName = dependency.TargetInternalName;

            if (directAutomation is not null)
            {
                return new DependencyAutomationMatch(
                    targetName,
                    directAutomation.SecurityAutomationLevel,
                    $"{internalName} → {dependency.TargetInternalName}");
            }

            var nestedVisited = new HashSet<string>(visited, StringComparer.OrdinalIgnoreCase);
            var nested = FindRequiredDependencyAutomation(dependency.TargetInternalName, nestedVisited, depth + 1);
            if (nested is not null)
            {
                var prefix = $"{internalName} → ";
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

    private static int SecuritySeverityRank(string? severity)
        => (severity ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "critical" => 5,
            "high" => 4,
            "caution" or "medium" => 3,
            "low" => 2,
            "informational" => 1,
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
            ImGui.SetTooltip(tooltip);
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
            ImGui.SetTooltip(tooltip);
    }

    private static void DrawDiscoverPluginTitle(string title, bool installed)
    {
        if (installed)
            ImGui.TextColored(new Vector4(0.69f, 0.71f, 0.75f, 1f), title);
        else
            ImGui.TextUnformatted(title);
    }

    private static void DrawDiscoverInstalledMarker(Vector2 localPosition)
    {
        const float size = 26f;
        var min = ImGui.GetWindowPos() + localPosition;
        var center = min + new Vector2(size * 0.5f, size * 0.5f);
        var draw = ImGui.GetWindowDrawList();
        var installedGreen = ImGui.ColorConvertFloat4ToU32(new Vector4(0.20f, 0.72f, 0.42f, 0.98f));
        var checkColor = ImGui.ColorConvertFloat4ToU32(new Vector4(0.97f, 1.00f, 0.98f, 1f));

        draw.AddCircleFilled(center, size * 0.45f, installedGreen, 24);
        draw.AddLine(min + new Vector2(6.5f, 13.2f), min + new Vector2(11.0f, 17.3f), checkColor, 2.7f);
        draw.AddLine(min + new Vector2(10.8f, 17.3f), min + new Vector2(19.6f, 8.4f), checkColor, 2.7f);
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
            ImGui.SetTooltip("Enhanced listing: public project metadata indexed by Omega.");
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
            ImGui.SetTooltip(tooltip);
    }

    private static void DrawDalamudOfficialLogoBadge(float size)
    {
        var min = ImGui.GetCursorScreenPos();
        ImGui.Dummy(new Vector2(size, size));
        var draw = ImGui.GetWindowDrawList();
        draw.AddRectFilled(
            min,
            min + new Vector2(size, size),
            ImGui.ColorConvertFloat4ToU32(new Vector4(0.10f, 0.035f, 0.045f, 0.78f)),
            5f);
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
            ImGui.SetTooltip("Dalamud official repository");
    }

    private static string PrimaryPluginCategory(MarketplacePlugin plugin)
        => plugin.EffectiveCategories.FirstOrDefault()
           ?? plugin.Tags.FirstOrDefault(x => !IsContentRatingTag(x))
           ?? string.Empty;
}
