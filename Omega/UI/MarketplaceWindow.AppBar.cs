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
    private const float AppBarControlSize = 32f;
    private const float AppBarSearchWidth = 480f;

    private void DrawApplicationBar()
    {
        ImGui.BeginChild("omega-application-bar", new Vector2(0f, Ui(AppBarHeight)), false,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        DrawApplicationMark();
        var (searchX, searchWidth) = GetGlobalSearchLayout();
        DrawProductBackButton(searchX);
        DrawGlobalSearch(searchX, searchWidth);
        DrawApplicationControls();

        ImGui.EndChild();
    }

    private void DrawApplicationMark()
    {
        const string label = "Omega";
        var labelSize = ImGui.CalcTextSize(label);
        var hitSize = labelSize + Ui(12f, 8f);
        var y = Math.Max(0f, (Ui(AppBarHeight) - hitSize.Y) * 0.5f);
        ImGui.SetCursorPos(new Vector2(Ui(4f), y));
        ImGui.InvisibleButton("##omega-application-mark", hitSize);
        var min = ImGui.GetItemRectMin();
        var draw = ImGui.GetWindowDrawList();
        var textPos = min + new Vector2(Ui(6f), (hitSize.Y - labelSize.Y) * 0.5f);
        draw.AddText(textPos, ImGui.GetColorU32(ImGuiCol.Text), label);

        // Small red core in the first O: a quiet Omega identity mark without bringing the old logo back.
        var firstLetterSize = ImGui.CalcTextSize("O");
        var omegaDotCenter = textPos + new Vector2(firstLetterSize.X * 0.50f, firstLetterSize.Y * 0.52f);
        draw.AddCircleFilled(
            omegaDotCenter,
            Ui(2.15f),
            ImGui.ColorConvertFloat4ToU32(new Vector4(0.88f, 0.16f, 0.20f, 1f)),
            12);

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Omega");
    }

    private static (float X, float Width) GetGlobalSearchLayout()
    {
        var width = ImGui.GetWindowWidth();
        var reserved = (Ui(AppBarControlSize) * 2f) + Ui(58f);
        var searchWidth = Math.Min(Ui(AppBarSearchWidth), Math.Max(Ui(220f), width - (reserved * 2f)));
        var x = Math.Max(Ui(92f), (width - searchWidth) * 0.5f);
        return (x, searchWidth);
    }

    private void DrawProductBackButton(float searchX)
    {
        if (!detailsOpen || activeView != MarketplaceView.Discover)
            return;

        var x = Math.Max(Ui(68f), searchX - Ui(AppBarControlSize) - Ui(10f));
        ImGui.SetCursorPos(new Vector2(x, Ui(5f)));
        var returnLabel = detailsReturnView == MarketplaceView.Library
            ? detailsReturnLibrarySection == LibrarySection.Sigmascope ? "Back to Library / Sigmascope" : "Back to Library"
            : $"Back to {ViewTitle(detailsReturnView)}";
        if (!DrawApplicationIconButton(FontAwesomeIcon.ArrowLeft, "discover-product-back", returnLabel, false))
            return;

        detailsOpen = false;
        selectedPlugin = null;
        activeView = detailsReturnView;
        if (activeView == MarketplaceView.Library)
            librarySection = detailsReturnLibrarySection;
        resetStorefrontScroll = false;
        resetDiscoverListScroll = false;
    }

    private void DrawGlobalSearch(float x, float searchWidth)
    {
        var hasSearch = !string.IsNullOrEmpty(search);
        var gap = Ui(4f);
        var clearSize = hasSearch ? Ui(AppBarControlSize) : 0f;
        var inputWidth = Math.Max(Ui(160f), searchWidth - clearSize - (hasSearch ? gap : 0f));

        ImGui.SetCursorPos(new Vector2(x, Ui(5f)));
        ImGui.SetNextItemWidth(inputWidth);
        ImGui.PushStyleColor(ImGuiCol.FrameBg, new Vector4(0.145f, 0.155f, 0.175f, 0.96f));
        ImGui.PushStyleColor(ImGuiCol.FrameBgHovered, new Vector4(0.175f, 0.185f, 0.205f, 0.98f));
        ImGui.PushStyleColor(ImGuiCol.FrameBgActive, new Vector4(0.195f, 0.205f, 0.225f, 1f));

        var previous = search;
        var changed = ImGui.InputTextWithHint(
            "##omega-global-search",
            "Search plugins, descriptions, READMEs, authors, tags...",
            ref search,
            256);
        ImGui.PopStyleColor(3);

        var clearClicked = false;
        if (hasSearch)
        {
            ImGui.SameLine(0f, gap);
            clearClicked = DrawApplicationIconButton(FontAwesomeIcon.Times, "search-clear", "Clear search", false);
        }

        if (clearClicked)
        {
            search = string.Empty;
            ActivateGlobalSearch();
            return;
        }

        if (changed && !search.Equals(previous, StringComparison.Ordinal))
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

        selectedAuthors.Clear();
        authorSearch = string.Empty;
        selectedSource = "All sources";
        selectedCategory = "All categories";
        selectedTags.Clear();
        selectedApi = 0;
        statusFilter = MarketplaceStatusFilter.All;
        securityFilter = MarketplaceSecurityFilter.All;
        contentFilter = MarketplaceContentFilter.All;
    }

    private void DrawApplicationControls()
    {
        var gap = Ui(4f);
        var controlSize = Ui(AppBarControlSize);
        var x = ImGui.GetWindowWidth() - (controlSize * 2f) - gap - Ui(4f);
        ImGui.SetCursorPos(new Vector2(x, Ui(5f)));
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
        var rounding = Ui(6f);
        var controlSize = Ui(AppBarControlSize);
        var min = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##omega-appbar-{id}", new Vector2(controlSize, controlSize));
        var hovered = ImGui.IsItemHovered();
        var held = ImGui.IsItemActive();
        var clicked = ImGui.IsItemClicked();
        var draw = ImGui.GetWindowDrawList();

        if (hovered || held)
        {
            var background = danger
                ? new Vector4(0.42f, 0.08f, 0.11f, held ? 0.92f : 0.72f)
                : new Vector4(0.060f, 0.080f, 0.105f, held ? 0.90f : 0.72f);
            draw.AddRectFilled(min, min + new Vector2(controlSize, controlSize),
                ImGui.ColorConvertFloat4ToU32(background), rounding);
        }

        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = icon.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        var glyphPos = min + new Vector2(
            (controlSize - glyphSize.X) * 0.5f,
            (controlSize - glyphSize.Y) * 0.5f);
        draw.AddText(glyphPos, hovered || held ? ImGui.GetColorU32(ImGuiCol.Text) : ImGui.GetColorU32(ImGuiCol.TextDisabled), glyph);
        ImGui.PopFont();

        if (hovered)
            ImGui.SetTooltip(tooltip);
        return clicked;
    }
}
