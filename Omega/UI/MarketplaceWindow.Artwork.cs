using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void DrawPluginTile(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion,
        float width)
    {
        var selectedVariant = plugin;
        var startX = ImGui.GetCursorPosX();
        ImGui.BeginGroup();

        var iconSize = Math.Clamp(width - 16f, 112f, 150f);
        var tileVisible = ImGui.IsRectVisible(new Vector2(width, iconSize + 54f));
        if (DrawPluginArtwork(selectedVariant, installedPlugin, iconSize, width, currentApi, currentDalamudVersion, tileVisible))
            OpenPluginDetails(selectedVariant);

        DrawCenteredTileText(Shorten(selectedVariant.Name, 24), width, false);
        DrawCenteredTileText(Shorten(string.IsNullOrWhiteSpace(selectedVariant.Author) ? "Unknown author" : selectedVariant.Author, 28), width, true);

        ImGui.SetCursorPosX(startX);
        ImGui.Dummy(new Vector2(width, 1f));
        ImGui.EndGroup();
    }

    private bool DrawPluginArtwork(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        float iconSize,
        float layoutWidth,
        int currentApi,
        Version currentDalamudVersion,
        bool queueIfVisible = true,
        bool showOverlays = true,
        bool useFallbackTexture = true)
    {
        var startX = ImGui.GetCursorPosX();
        ImGui.SetCursorPosX(startX + Math.Max(0f, (layoutWidth - iconSize) * 0.5f));
        var overlayMin = ImGui.GetCursorScreenPos();
        var overlaySize = new Vector2(iconSize, iconSize);

        ImGui.PushStyleColor(ImGuiCol.ChildBg, 0u);
        ImGui.BeginChild($"artwork-{plugin.InternalName}-{StableId(plugin.SourceUrl)}", new Vector2(iconSize, iconSize), false,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var clicked = DrawArtworkImage(plugin, iconSize, queueIfVisible, useFallbackTexture, ref overlayMin, ref overlaySize);
        var overlayConsumed = showOverlays &&
                              DrawArtworkTopLayer(plugin, installedPlugin, overlayMin, overlaySize, currentApi, currentDalamudVersion);

        ImGui.EndChild();
        ImGui.PopStyleColor();
        ImGui.SetCursorPosX(startX);
        return clicked && !overlayConsumed;
    }

    private bool DrawArtworkImage(
        MarketplacePlugin plugin,
        float iconSize,
        bool queueIfVisible,
        bool useFallbackTexture,
        ref Vector2 overlayMin,
        ref Vector2 overlaySize)
    {
        var texture = queueIfVisible ? iconCache.GetOrQueue(plugin.IconUrl) : null;
        if (texture is null && queueIfVisible && plugin.SourceIsOfficial)
            texture = iconCache.GetOrQueue(GetOfficialDalamudIconUrl(plugin));

        var usingFallback = texture is null;
        if (texture is null && useFallbackTexture && fallbackIconTexture is not null)
            texture = fallbackIconTexture.GetWrapOrDefault();

        if (texture is null || texture.Size.X <= 0 || texture.Size.Y <= 0)
            return DrawArtworkPlaceholder(plugin, iconSize);

        var scale = Math.Min(iconSize / texture.Size.X, iconSize / texture.Size.Y);
        var drawSize = texture.Size * scale;
        ImGui.SetCursorPos(new Vector2(
            Math.Max(0f, (iconSize - drawSize.X) * 0.5f),
            Math.Max(0f, (iconSize - drawSize.Y) * 0.5f)));
        overlayMin = ImGui.GetCursorScreenPos();
        overlaySize = drawSize;
        ImGui.Image(texture.Handle, drawSize);
        var clicked = ImGui.IsItemClicked();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(usingFallback
                ? $"{plugin.Name} has no usable artwork. Dalagab Group fallback shown."
                : string.IsNullOrWhiteSpace(plugin.Punchline) ? $"Open {plugin.Name}" : plugin.Punchline);
        return clicked;
    }

    private static string GetOfficialDalamudIconUrl(MarketplacePlugin plugin)
        => string.IsNullOrWhiteSpace(plugin.InternalName)
            ? string.Empty
            : $"https://raw.githubusercontent.com/goatcorp/DalamudPluginsD17/refs/heads/main/stable/{Uri.EscapeDataString(plugin.InternalName)}/images/icon.png";

    private bool DrawArtworkPlaceholder(MarketplacePlugin plugin, float iconSize)
    {
        ImGui.InvisibleButton(
            $"artwork-placeholder-{plugin.InternalName}-{StableId(plugin.SourceUrl)}",
            new Vector2(iconSize, iconSize));
        var clicked = ImGui.IsItemClicked();
        var min = ImGui.GetItemRectMin();
        var max = min + new Vector2(iconSize, iconSize);
        var draw = ImGui.GetWindowDrawList();
        draw.AddRectFilled(min, max, ImGui.GetColorU32(ImGuiCol.FrameBg), 10f);

        var text = PluginInitials(plugin);
        var textSize = ImGui.CalcTextSize(text);
        draw.AddText(
            min + new Vector2((iconSize - textSize.X) * 0.5f, (iconSize - textSize.Y) * 0.5f),
            ImGui.GetColorU32(ImGuiCol.TextDisabled),
            text);
        return clicked;
    }

    private static string PluginInitials(MarketplacePlugin plugin)
    {
        var source = string.IsNullOrWhiteSpace(plugin.Name) ? plugin.InternalName : plugin.Name;
        var words = source.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (words.Length >= 2)
            return string.Concat(words[0][0], words[1][0]).ToUpperInvariant();
        if (words.Length == 1)
            return words[0].Length >= 2 ? words[0][..2].ToUpperInvariant() : words[0].ToUpperInvariant();
        return "Ω";
    }

    private bool DrawArtworkTopLayer(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        Vector2 overlayMin,
        Vector2 overlaySize,
        int currentApi,
        Version currentDalamudVersion)
    {
        var isSelected = detailsOpen && selectedPlugin is not null &&
                         selectedPlugin.InternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase) &&
                         NormalizeUrl(selectedPlugin.SourceUrl).Equals(NormalizeUrl(plugin.SourceUrl), StringComparison.OrdinalIgnoreCase);
        var overlayMax = overlayMin + overlaySize;
        var draw = ImGui.GetWindowDrawList();
        draw.PushClipRect(overlayMin, overlayMax, true);
        DrawArtworkSelection(plugin, overlayMin, overlaySize, isSelected, currentApi);
        DrawApiBadge(plugin, overlayMin, overlaySize, currentApi, currentDalamudVersion);
        var consumed = DrawArtworkOverlayActions(
            plugin,
            installedPlugin,
            overlayMin,
            overlaySize,
            currentApi,
            currentDalamudVersion);
        draw.PopClipRect();
        return consumed;
    }

    private void DrawApiBadge(
        MarketplacePlugin plugin,
        Vector2 artworkMin,
        Vector2 artworkSize,
        int currentApi,
        Version currentDalamudVersion)
    {
        var stableApi = catalog.GetStableApiLevel(plugin.InternalName, currentApi);
        var api = stableApi > 0
            ? stableApi
            : plugin.DisplayApiLevel(currentApi, configuration.PreferTestingBuilds);
        var supported = stableApi > 0
            ? stableApi == currentApi && catalog.GetVariants(plugin.InternalName).Any(v =>
                v.DalamudApiLevel == stableApi &&
                (v.MinimumDalamudVersion is null || v.MinimumDalamudVersion <= currentDalamudVersion))
            : plugin.SupportsApiLevel(currentApi, configuration.PreferTestingBuilds) &&
              (plugin.MinimumDalamudVersion is null || plugin.MinimumDalamudVersion <= currentDalamudVersion);
        var text = api > 0 ? api.ToString() : "?";
        var textSize = ImGui.CalcTextSize(text);
        var badgeHeight = 24f;
        var badgeWidth = Math.Max(28f, textSize.X + 14f);
        const float inset = 6f;
        var artworkMax = artworkMin + artworkSize;
        var min = new Vector2(artworkMax.X - badgeWidth - inset, artworkMin.Y + inset);
        var max = min + new Vector2(badgeWidth, badgeHeight);
        var color = supported
            ? new Vector4(0.08f, 0.62f, 0.32f, 0.96f)
            : new Vector4(0.72f, 0.12f, 0.16f, 0.96f);
        var draw = ImGui.GetWindowDrawList();
        draw.AddRectFilled(min, max, ImGui.ColorConvertFloat4ToU32(color), badgeHeight * 0.5f);
        draw.AddText(
            min + new Vector2((badgeWidth - textSize.X) * 0.5f, (badgeHeight - textSize.Y) * 0.5f),
            0xFFFFFFFF,
            text);

        var mouse = ImGui.GetMousePos();
        if (mouse.X >= min.X && mouse.X <= max.X && mouse.Y >= min.Y && mouse.Y <= max.Y)
            ImGui.SetTooltip(stableApi > 0
                ? supported
                    ? $"Stable API {text} supported"
                    : $"Stable API {text} not supported by this Dalamud API {currentApi} build"
                : supported
                    ? $"API {text} supported"
                    : $"API {text} not supported by this Dalamud API {currentApi} build");
    }

    private void DrawArtworkSelection(
        MarketplacePlugin plugin,
        Vector2 artworkMin,
        Vector2 artworkSize,
        bool isSelected,
        int currentApi)
    {
        var draw = ImGui.GetWindowDrawList();
        var artworkMax = artworkMin + artworkSize;
        if (isSelected)
        {
            draw.AddRect(
                artworkMin,
                artworkMax,
                ImGui.ColorConvertFloat4ToU32(new Vector4(0.13f, 0.86f, 0.77f, 1f)),
                9f,
                ImDrawFlags.None,
                3f);
            DrawArtworkLabel("Selected", artworkMin + new Vector2(6f, 6f), new Vector4(0.05f, 0.48f, 0.44f, 0.96f));
        }

        if (plugin.IsUnmaintained(currentApi))
        {
            var y = isSelected ? 34f : 6f;
            DrawArtworkLabel("Unmaintained", artworkMin + new Vector2(6f, y), new Vector4(0.66f, 0.24f, 0.08f, 0.97f));
        }
    }

    private static void DrawArtworkLabel(string text, Vector2 min, Vector4 color)
    {
        var textSize = ImGui.CalcTextSize(text);
        var size = new Vector2(textSize.X + 12f, 22f);
        var draw = ImGui.GetWindowDrawList();
        draw.AddRectFilled(min, min + size, ImGui.ColorConvertFloat4ToU32(color), 11f);
        draw.AddText(min + new Vector2(6f, (22f - textSize.Y) * 0.5f), 0xFFFFFFFF, text);
    }

    /// <summary>
    /// Draws compact icon-only actions entirely inside the artwork bounds.
    /// Repository preparation is intentionally not exposed here; install always opens the
    /// repository chooser and the coordinator handles Dalamud integration behind that action.
    /// </summary>
    private bool DrawArtworkOverlayActions(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        Vector2 artworkMin,
        Vector2 artworkSize,
        int currentApi,
        Version currentDalamudVersion)
    {
        const float gap = 6f;
        const float inset = 7f;
        var size = Math.Clamp(Math.Min(artworkSize.X, artworkSize.Y) * 0.22f, 24f, 30f);
        var canInstall = installedPlugin is null && HasInstallableVariant(plugin.InternalName, currentApi, currentDalamudVersion);
        var actionCount = canInstall ? 2 : 1;
        var artworkMax = artworkMin + artworkSize;
        var rowWidth = (size * actionCount) + (gap * (actionCount - 1));
        var infoX = artworkMax.X - inset - rowWidth;
        var installX = infoX + size + gap;
        var y = artworkMax.Y - inset - size;
        var consumed = false;

        if (DrawArtworkIconButton(
                FontAwesomeIcon.InfoCircle,
                $"art-info-{plugin.InternalName}-{StableId(plugin.SourceUrl)}",
                new Vector2(infoX, y),
                size,
                artworkMin,
                artworkMax,
                "Plugin information"))
        {
            OpenPluginDetails(plugin);
            consumed = true;
        }

        if (!canInstall)
            return consumed;

        if (DrawArtworkIconButton(
                FontAwesomeIcon.Download,
                $"art-install-{plugin.InternalName}-{StableId(plugin.SourceUrl)}",
                new Vector2(installX, y),
                size,
                artworkMin,
                artworkMax,
                "Install plugin"))
        {
            OpenInstallChooser(plugin);
            consumed = true;
        }

        return consumed;
    }

    private static bool DrawArtworkIconButton(
        FontAwesomeIcon icon,
        string id,
        Vector2 screenPos,
        float size,
        Vector2 clipMin,
        Vector2 clipMax,
        string tooltip)
    {
        var restore = ImGui.GetCursorScreenPos();
        ImGui.SetCursorScreenPos(screenPos);
        ImGui.InvisibleButton($"##{id}", new Vector2(size, size));
        var hovered = ImGui.IsItemHovered();
        var active = ImGui.IsItemActive();
        var clicked = ImGui.IsItemClicked();

        var draw = ImGui.GetWindowDrawList();
        draw.PushClipRect(clipMin, clipMax, true);
        var bg = new Vector4(0.025f, 0.07f, 0.09f, active ? 1f : hovered ? 0.98f : 0.92f);
        var border = new Vector4(0.12f, 0.82f, 0.73f, hovered ? 1f : 0.80f);
        var min = screenPos;
        var max = screenPos + new Vector2(size, size);
        draw.AddRectFilled(min, max, ImGui.ColorConvertFloat4ToU32(bg), size * 0.5f);
        draw.AddRect(min, max, ImGui.ColorConvertFloat4ToU32(border), size * 0.5f, ImDrawFlags.None, 1.3f);

        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = icon.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        draw.AddText(
            min + new Vector2((size - glyphSize.X) * 0.5f, (size - glyphSize.Y) * 0.5f),
            0xFFFFFFFF,
            glyph);
        ImGui.PopFont();
        draw.PopClipRect();

        if (hovered)
            ImGui.SetTooltip(tooltip);

        ImGui.SetCursorScreenPos(restore);
        return clicked;
    }

    private static void DrawCenteredTileText(string text, float width, bool disabled)
    {
        var startX = ImGui.GetCursorPosX();
        var textWidth = ImGui.CalcTextSize(text).X;
        ImGui.SetCursorPosX(startX + Math.Max(0f, (width - textWidth) * 0.5f));
        if (disabled)
            ImGui.TextDisabled(text);
        else
            ImGui.TextUnformatted(text);
        ImGui.SetCursorPosX(startX);
    }

    private void OpenPluginDetails(MarketplacePlugin plugin)
    {
        selectedPlugin = ResolveSelectedVariant(plugin);
        detailsOpen = true;

        // With the central catalog active, opening details does not fan out to curated sources; only
        // matching user-added repositories may be checked. In fallback mode the prior per-plugin
        // conditional source check is retained.
        _ = updates.RefreshPluginSourcesAsync(plugin.InternalName);
    }

    private MarketplacePlugin ResolveSelectedVariant(MarketplacePlugin plugin)
    {
        var variants = catalog.GetVariants(plugin.InternalName);
        if (variants.Count == 0)
            return plugin;

        if (selectedVariantSource.TryGetValue(plugin.InternalName, out var sourceUrl))
        {
            var selected = variants.FirstOrDefault(x =>
                NormalizeUrl(x.SourceUrl).Equals(NormalizeUrl(sourceUrl), StringComparison.OrdinalIgnoreCase));
            if (selected is not null)
                return selected;
        }

        return variants[0];
    }

    private string StableId(string value)
    {
        value ??= string.Empty;
        if (stableIdCache.TryGetValue(value, out var cached))
            return cached;

        var id = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)))[..10];
        stableIdCache[value] = id;
        return id;
    }

}
