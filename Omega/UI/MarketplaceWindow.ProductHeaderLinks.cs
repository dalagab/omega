using System.Diagnostics;
using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;

namespace Dalagab.Omega;

/// <summary>
/// Keeps project navigation inside the product header instead of adding detached action rows.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private static string ResolveEnhancedProjectUrl(
        MarketplacePlugin plugin,
        MarketplacePresentationContent content)
    {
        var enhanced = content.Variant.OmegaWebsiteUrl;
        if (IsWebUrl(enhanced))
            return enhanced;
        return ResolveProjectUrl(plugin);
    }

    private static bool IsWebUrl(string? candidate)
        => Uri.TryCreate(candidate, UriKind.Absolute, out var uri) &&
           (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase));

    private void DrawProductWebsiteIcon(MarketplacePlugin plugin, string url)
    {
        const float size = 22f;
        const float rounding = 5f;
        var min = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##product-project-{StableId(plugin.InternalName)}", new Vector2(size, size));
        var hovered = ImGui.IsItemHovered();
        var active = ImGui.IsItemActive();
        var clicked = ImGui.IsItemClicked();
        var draw = ImGui.GetWindowDrawList();

        if (hovered || active)
        {
            draw.AddRectFilled(
                min,
                min + new Vector2(size, size),
                ImGui.ColorConvertFloat4ToU32(new Vector4(0.07f, 0.18f, 0.20f, active ? 0.95f : 0.74f)),
                rounding);
        }

        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = FontAwesomeIcon.Globe.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        draw.AddText(
            min + new Vector2((size - glyphSize.X) * 0.5f, (size - glyphSize.Y) * 0.5f),
            hovered ? ImGui.GetColorU32(ImGuiCol.Text) : ImGui.GetColorU32(ImGuiCol.TextDisabled),
            glyph);
        ImGui.PopFont();

        if (hovered)
            ImGui.SetTooltip("Open project page");
        if (clicked)
            OpenProductWebsite(plugin, url);
    }

    private void OpenProductWebsite(MarketplacePlugin plugin, string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega could not open project URL for {Plugin}", plugin.InternalName);
            operationMessage = $"Could not open the project page for {plugin.Name}.";
        }
    }
}
