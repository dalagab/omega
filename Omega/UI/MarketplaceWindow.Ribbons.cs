using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Plugin;

namespace Dalagab.Omega;

/// <summary>
/// Owns the compact ribbon language shared by plugin listing panels.
/// Ribbon background color communicates Sigmascope finding level; the glyph communicates source/status.
/// Ownership/collection ribbons occupy the card's top-left edge; Sigmascope/automation occupy
/// its top-right edge. They are emitted from the artwork child's draw layer only to guarantee
/// correct Z-order over nested artwork, while their coordinates remain card-anchored.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private readonly record struct SigmascopeRibbonVisual(
        Vector4 Background,
        FontAwesomeIcon Icon,
        uint IconColor,
        string Tooltip);

    private void DrawPluginCardTopRibbons(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Vector2 panelMin,
        Vector2 panelMax)
    {
        // Listing ribbons belong to the CARD, not the artwork. This method is intentionally
        // invoked from the artwork child after the image has been emitted, because ImGui
        // renders nested child windows above their parent draw lists. Expanding this child
        // draw-list clip to the card bounds keeps the ribbons on the card's top edge while
        // guaranteeing that they composite in front of the artwork instead of behind it.
        var draw = ImGui.GetWindowDrawList();
        // The artwork child owns the draw layer so ribbons composite above the plugin image, but
        // its normal clip is only the icon. Expand to the card bounds, then clamp those bounds to
        // Discover's fixed on-screen results-window rectangle when present. This keeps card-top
        // ribbons visible while preventing buffered/off-screen cards from painting over the
        // search/filter header or another visible row while the results child scrolls.
        var clipMin = panelMin;
        var clipMax = panelMax;
        if (discoverListingClipMin is { } viewportMin && discoverListingClipMax is { } viewportMax)
        {
            clipMin = Vector2.Max(clipMin, viewportMin);
            clipMax = Vector2.Min(clipMax, viewportMax);
            if (clipMax.X <= clipMin.X || clipMax.Y <= clipMin.Y)
                return;
        }
        draw.PushClipRect(clipMin, clipMax, false);
        try
        {
            var ribbonWidth = Ui(24f);
            var ribbonHeight = Ui(30f);
            var ribbonGap = Ui(3f);
            var edgeInset = Ui(8f);
            var leftX = panelMin.X + edgeInset;
            var rightX = panelMax.X - edgeInset - ribbonWidth;
            var topY = panelMin.Y;

            // Ownership/profile state: TOP-LEFT, side-by-side.
            if (installedPlugin is not null)
            {
                DrawPanelRibbon(
                    $"installed-{plugin.InternalName}",
                    new Vector2(leftX, topY),
                    ribbonWidth,
                    ribbonHeight,
                    new Vector4(0.18f, 0.70f, 0.39f, 0.98f),
                    FontAwesomeIcon.Check,
                    0xFFFFFFFF,
                    "Installed through Dalamud");
                leftX += ribbonWidth + ribbonGap;
            }

            var namedCollections = collectionSnapshot
                .Where(x => !x.IsDefault && CollectionContainsPlugin(x, plugin.InternalName))
                .Select(CollectionDisplayName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (namedCollections.Length > 0)
            {
                DrawPanelRibbon(
                    $"collection-{plugin.InternalName}",
                    new Vector2(leftX, topY),
                    ribbonWidth,
                    ribbonHeight,
                    new Vector4(0.38f, 0.31f, 0.70f, 0.98f),
                    FontAwesomeIcon.Folder,
                    0xFFFFFFFF,
                    $"In collection{(namedCollections.Length == 1 ? string.Empty : "s")}: {string.Join(", ", namedCollections)}");
            }

            // Sigmascope/automation state: TOP-RIGHT, side-by-side. Sigmascope owns the
            // outermost right position and automation, when present, sits immediately left.
            var security = ResolveSigmascopeRibbonVisual(plugin, currentApi);
            DrawPanelRibbon(
                $"security-{plugin.InternalName}",
                new Vector2(rightX, topY),
                ribbonWidth,
                ribbonHeight,
                security.Background,
                security.Icon,
                security.IconColor,
                security.Tooltip);

            var automation = GetPluginAutomationState(plugin);
            if (automation is not null)
            {
                DrawPanelRibbon(
                    $"automation-{plugin.InternalName}",
                    new Vector2(rightX - ribbonWidth - ribbonGap, topY),
                    ribbonWidth,
                    ribbonHeight,
                    new Vector4(0.05f, 0.62f, 0.78f, 0.99f),
                    FontAwesomeIcon.Robot,
                    0xFFFFFFFF,
                    automation.Value.Tooltip);
            }
        }
        finally
        {
            draw.PopClipRect();
        }
    }

    private void DrawPluginPanelUpdateState(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion,
        Vector2 panelMax)
    {
        if (installedPlugin is not null &&
            GetAvailableUpdateVersion(plugin.InternalName, installedPlugin, currentApi, currentDalamudVersion) is { } updateVersion)
        {
            DrawPanelUpdateIndicator(plugin, installedPlugin, updateVersion, panelMax);
        }
    }

    private SigmascopeRibbonVisual ResolveSigmascopeRibbonVisual(MarketplacePlugin plugin, int currentApi)
    {
        var severity = EffectiveRibbonSecuritySeverity(plugin);
        var background = SigmascopeRibbonColor(plugin, severity);

        if (!plugin.HasCompletedSecurityScan)
        {
            var visual = configuration.ShowAdvancedSecurityInformation
                ? ResolveSigmascopeVisual(plugin)
                : ResolveSimpleSigmascopeVisual(plugin);
            return new SigmascopeRibbonVisual(
                background,
                FontAwesomeIcon.Question,
                0xFFFFFFFF,
                visual.Tooltip);
        }

        if (!plugin.SecuritySourceAvailable)
        {
            return new SigmascopeRibbonVisual(
                background,
                FontAwesomeIcon.Question,
                0xFFFFFFFF,
                configuration.ShowAdvancedSecurityInformation
                    ? $"{SigmascopeRibbonLabel(severity)} Sigmascope finding level. Plugin package analysis is available, but source attribution is unresolved. This does not imply anything about the developer's source-disclosure intent."
                    : "Omega checked this plugin, but could not confirm where this copy came from.");
        }

        var highestKnownApi = HighestKnownApiFor(plugin.InternalName, currentApi);
        var outdated = highestKnownApi > 0 && highestKnownApi < currentApi;
        var iconColor = 0xFFFFFFFF;
        var status = outdated
            ? $"Unsupported on Dalamud API {currentApi}; newest known API is {highestKnownApi}."
            : "Public source indexed by Omega.";
        var simpleStatus = outdated
            ? "This plugin does not support your current Dalamud version."
            : "Omega found a public source for this plugin.";
        var simpleVisual = ResolveSimpleSigmascopeVisual(plugin);
        return new SigmascopeRibbonVisual(
            background,
            outdated ? FontAwesomeIcon.Lock : FontAwesomeIcon.Star,
            iconColor,
            configuration.ShowAdvancedSecurityInformation
                ? $"{SigmascopeRibbonLabel(severity)} Sigmascope finding level. {status}"
                : $"{simpleVisual.Tooltip} {simpleStatus}");
    }

    private static string EffectiveRibbonSecuritySeverity(MarketplacePlugin plugin)
    {
        var severity = (plugin.SecurityHighestSeverity ?? string.Empty).Trim().ToLowerInvariant();
        if (!plugin.HasKnownAtRiskDependency)
            return severity;

        var advisory = (plugin.SecurityKnownAdvisoryHighestSeverity ?? string.Empty).Trim().ToLowerInvariant();
        var staticRank = SecuritySeverityRank(severity);
        var advisoryRank = SecuritySeverityRank(advisory);
        if (advisoryRank > staticRank)
            return advisory;
        if (advisoryRank == 0 && staticRank < SecuritySeverityRank("medium"))
            return "medium";
        return severity;
    }

    private static Vector4 SigmascopeRibbonColor(MarketplacePlugin plugin, string severity)
    {
        if (!plugin.HasCompletedSecurityScan)
            return new Vector4(0.32f, 0.34f, 0.38f, 0.98f);

        return severity switch
        {
            "informational" or "info" => new Vector4(0.16f, 0.47f, 0.82f, 0.99f),
            "none" or "" => new Vector4(0.78f, 0.58f, 0.14f, 0.99f),
            "low" => new Vector4(0.91f, 0.76f, 0.13f, 0.99f),
            "caution" or "medium" => new Vector4(0.91f, 0.43f, 0.10f, 0.99f),
            "high" or "critical" => new Vector4(0.78f, 0.10f, 0.14f, 0.99f),
            _ => new Vector4(0.78f, 0.58f, 0.14f, 0.99f),
        };
    }

    private static string SigmascopeRibbonLabel(string severity)
        => severity switch
        {
            "informational" or "info" => "Informational",
            "none" or "" => "No findings",
            "low" => "Low",
            "caution" or "medium" => "Medium",
            "high" or "critical" => "High",
            _ => "Scanned",
        };

    private static void DrawPanelRibbon(
        string id,
        Vector2 min,
        float width,
        float height,
        Vector4 background,
        FontAwesomeIcon icon,
        uint iconColor,
        string tooltip)
    {
        var draw = ImGui.GetWindowDrawList();
        var tailHeight = Math.Min(Ui(6f), height * 0.25f);
        var bodyBottom = min.Y + height - tailHeight;
        var maxX = min.X + width;
        var centerX = min.X + (width * 0.5f);
        var velvetTop = ImGui.ColorConvertFloat4ToU32(new Vector4(
            Math.Min(1f, (background.X * 1.10f) + 0.025f),
            Math.Min(1f, (background.Y * 1.10f) + 0.025f),
            Math.Min(1f, (background.Z * 1.10f) + 0.025f),
            background.W));
        var velvetBottom = ImGui.ColorConvertFloat4ToU32(new Vector4(
            background.X * 0.72f,
            background.Y * 0.72f,
            background.Z * 0.72f,
            background.W));
        var border = ImGui.ColorConvertFloat4ToU32(new Vector4(0.02f, 0.03f, 0.04f, 0.72f));

        // A restrained top-to-bottom shade gives the ribbon a cloth/velvet depth without
        // changing the semantic status colour or adding texture assets.
        draw.AddRectFilledMultiColor(
            min,
            new Vector2(maxX, bodyBottom),
            velvetTop,
            velvetTop,
            velvetBottom,
            velvetBottom);
        draw.AddTriangleFilled(
            new Vector2(min.X, bodyBottom),
            new Vector2(maxX, bodyBottom),
            new Vector2(centerX, min.Y + height),
            velvetBottom);
        draw.AddLine(min, new Vector2(min.X, bodyBottom), border, Ui(1f));
        draw.AddLine(new Vector2(maxX, min.Y), new Vector2(maxX, bodyBottom), border, Ui(1f));

        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = icon.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        // Most fixed-width Font Awesome glyphs need a small optical correction in the narrow flag.
        // Robot/folder were slightly over-corrected, while the star is already centered as-is.
        var glyphOffsetX = icon switch
        {
            FontAwesomeIcon.Star => 0f,
            FontAwesomeIcon.Robot => Ui(1.0f),
            FontAwesomeIcon.Folder => Ui(1.0f),
            _ => Ui(1.5f),
        };
        var glyphScale = icon == FontAwesomeIcon.Folder ? 0.92f : 1f;
        var scaledGlyphSize = glyphSize * glyphScale;
        var glyphCenter = new Vector2(centerX + glyphOffsetX, min.Y + (height * 0.5f));
        var glyphOrigin = glyphCenter - (scaledGlyphSize * 0.5f);
        var glyphFont = ImGui.GetFont();
        var glyphFontSize = ImGui.GetFontSize() * glyphScale;
        if (icon == FontAwesomeIcon.Lock)
        {
            // Give the unsupported lock a little more visual weight without adding a backing disk.
            draw.AddText(glyphFont, glyphFontSize, glyphOrigin + new Vector2(-Ui(0.45f), 0f), iconColor, glyph);
            draw.AddText(glyphFont, glyphFontSize, glyphOrigin + new Vector2(Ui(0.45f), 0f), iconColor, glyph);
        }
        draw.AddText(glyphFont, glyphFontSize, glyphOrigin, iconColor, glyph);
        ImGui.PopFont();

        var mouse = ImGui.GetMousePos();
        if (mouse.X >= min.X && mouse.X <= maxX && mouse.Y >= min.Y && mouse.Y <= min.Y + height)
            SetReadableTooltip(tooltip);
    }


    private static void DrawPanelUpdateIndicator(
        MarketplacePlugin plugin,
        IExposedPlugin installedPlugin,
        Version updateVersion,
        Vector2 panelMax)
    {
        var size = Ui(20f);
        var inset = Ui(9f);
        var min = panelMax - new Vector2(size + inset, size + inset);
        var draw = ImGui.GetWindowDrawList();

        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = FontAwesomeIcon.SyncAlt.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        draw.AddText(
            min + new Vector2((size - glyphSize.X) * 0.5f, (size - glyphSize.Y) * 0.5f),
            ImGui.ColorConvertFloat4ToU32(new Vector4(0.98f, 0.73f, 0.23f, 1f)),
            glyph);
        ImGui.PopFont();

        var mouse = ImGui.GetMousePos();
        if (mouse.X >= min.X && mouse.X <= min.X + size && mouse.Y >= min.Y && mouse.Y <= min.Y + size)
        {
            var installed = installedPlugin.Version?.ToString() ?? "installed version";
            SetReadableTooltip($"Update available for {plugin.Name}: {installed} → {updateVersion}");
        }
    }
}
