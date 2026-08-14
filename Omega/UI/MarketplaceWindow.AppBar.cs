using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;

namespace Dalagab.Omega;

/// <summary>
/// Owns Omega's application-level top bar: product mark, global marketplace search, and window controls.
/// Page content starts below this chrome so every marketplace destination shares one stable frame.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private const float AppBarHeight = 42f;
    private const float AppBarIconSize = 22f;
    private const float AppBarControlSize = 32f;
    private const float AppBarSearchWidth = 480f;

    private void DrawApplicationBar()
    {
        ImGui.BeginChild("omega-application-bar", new Vector2(0f, AppBarHeight), false,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        DrawApplicationMark();
        DrawGlobalSearch();
        DrawApplicationControls();

        ImGui.EndChild();
    }

    private void DrawApplicationMark()
    {
        var y = (AppBarHeight - AppBarIconSize) * 0.5f;
        ImGui.SetCursorPos(new Vector2(4f, y));
        var min = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton("##omega-application-mark", new Vector2(AppBarIconSize, AppBarIconSize));
        var texture = omegaIconTexture?.GetWrapOrDefault();
        if (texture is not null)
            ImGui.GetWindowDrawList().AddImage(texture.Handle, min, min + new Vector2(AppBarIconSize, AppBarIconSize));
        else
            DrawFallbackApplicationMark(min);

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Omega");
    }

    private static void DrawFallbackApplicationMark(Vector2 min)
    {
        const string glyph = "Ω";
        var glyphSize = ImGui.CalcTextSize(glyph);
        var pos = min + new Vector2((AppBarIconSize - glyphSize.X) * 0.5f, (AppBarIconSize - glyphSize.Y) * 0.5f);
        ImGui.GetWindowDrawList().AddText(pos, ImGui.GetColorU32(ImGuiCol.Text), glyph);
    }

    private void DrawGlobalSearch()
    {
        var width = ImGui.GetWindowWidth();
        var reserved = (AppBarControlSize * 2f) + 58f;
        var searchWidth = Math.Min(AppBarSearchWidth, Math.Max(240f, width - (reserved * 2f)));
        var x = Math.Max(40f, (width - searchWidth) * 0.5f);
        ImGui.SetCursorPos(new Vector2(x, 5f));
        ImGui.SetNextItemWidth(searchWidth);

        var previous = search;
        if (!ImGui.InputTextWithHint("##omega-global-search", "Search plugins, authors, tags...", ref search, 256))
            return;
        if (search.Equals(previous, StringComparison.Ordinal))
            return;

        ActivateGlobalSearch();
    }

    private void ActivateGlobalSearch()
    {
        var wasDiscover = activeView == MarketplaceView.Discover;
        activeView = MarketplaceView.Discover;
        detailsOpen = false;
        selectedPlugin = null;
        resetStorefrontScroll = true;
        resetDiscoverListScroll = true;

        if (wasDiscover)
            return;

        author = string.Empty;
        selectedSource = "All sources";
        selectedCategory = "All categories";
        selectedTags.Clear();
        selectedApi = 0;
        statusFilter = MarketplaceStatusFilter.All;
        securityFilter = MarketplaceSecurityFilter.All;
    }

    private void DrawApplicationControls()
    {
        const float gap = 4f;
        var x = ImGui.GetWindowWidth() - (AppBarControlSize * 2f) - gap - 4f;
        ImGui.SetCursorPos(new Vector2(x, 5f));
        if (DrawApplicationIconButton(FontAwesomeIcon.Minus, "minimize", "Minimize Omega", false))
            EnterMinimizedMode();

        ImGui.SameLine(0f, gap);
        if (DrawApplicationIconButton(FontAwesomeIcon.Times, "close", "Close Omega", true))
            IsOpen = false;
    }

    private static bool DrawApplicationIconButton(
        FontAwesomeIcon icon,
        string id,
        string tooltip,
        bool danger)
    {
        const float rounding = 6f;
        var min = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##omega-appbar-{id}", new Vector2(AppBarControlSize, AppBarControlSize));
        var hovered = ImGui.IsItemHovered();
        var held = ImGui.IsItemActive();
        var clicked = ImGui.IsItemClicked();
        var draw = ImGui.GetWindowDrawList();

        if (hovered || held)
        {
            var background = danger
                ? new Vector4(0.42f, 0.08f, 0.11f, held ? 0.92f : 0.72f)
                : new Vector4(0.060f, 0.080f, 0.105f, held ? 0.90f : 0.72f);
            draw.AddRectFilled(min, min + new Vector2(AppBarControlSize, AppBarControlSize),
                ImGui.ColorConvertFloat4ToU32(background), rounding);
        }

        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = icon.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        var glyphPos = min + new Vector2(
            (AppBarControlSize - glyphSize.X) * 0.5f,
            (AppBarControlSize - glyphSize.Y) * 0.5f);
        draw.AddText(glyphPos, hovered || held ? ImGui.GetColorU32(ImGuiCol.Text) : ImGui.GetColorU32(ImGuiCol.TextDisabled), glyph);
        ImGui.PopFont();

        if (hovered)
            ImGui.SetTooltip(tooltip);
        return clicked;
    }
}
