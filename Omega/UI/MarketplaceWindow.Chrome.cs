using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Utility;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private static void PushOmegaTheme()
    {
        ImGui.PushStyleColor(ImGuiCol.WindowBg, new Vector4(0.025f, 0.031f, 0.045f, 0.985f));
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0f, 0f, 0f, 0f));
        ImGui.PushStyleColor(ImGuiCol.PopupBg, new Vector4(0.035f, 0.043f, 0.060f, 0.99f));
        ImGui.PushStyleColor(ImGuiCol.FrameBg, new Vector4(0.070f, 0.085f, 0.115f, 0.95f));
        ImGui.PushStyleColor(ImGuiCol.FrameBgHovered, new Vector4(0.095f, 0.120f, 0.155f, 0.98f));
        ImGui.PushStyleColor(ImGuiCol.FrameBgActive, new Vector4(0.105f, 0.145f, 0.180f, 1f));
        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.070f, 0.085f, 0.115f, 0.92f));
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.090f, 0.150f, 0.175f, 1f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive, new Vector4(0.070f, 0.190f, 0.205f, 1f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.12f, 0.17f, 0.21f, 0.65f));
        ImGui.PushStyleColor(ImGuiCol.ScrollbarBg, new Vector4(0f, 0f, 0f, 0f));
        ImGui.PushStyleColor(ImGuiCol.ScrollbarGrab, new Vector4(0.11f, 0.22f, 0.24f, 0.78f));
        ImGui.PushStyleColor(ImGuiCol.ScrollbarGrabHovered, new Vector4(0.12f, 0.34f, 0.34f, 0.95f));

        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(18f, 16f));
        ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, 16f);
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, 14f);
        ImGui.PushStyleVar(ImGuiStyleVar.PopupRounding, 14f);
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 12f);
        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(11f, 7f));
        ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(10f, 8f));
        ImGui.PushStyleVar(ImGuiStyleVar.ScrollbarSize, 9f);
    }

    private static void PopOmegaTheme()
    {
        ImGui.PopStyleVar(8);
        ImGui.PopStyleColor(13);
    }

    private void DrawSidebar(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        RefreshCollectionsIfNeeded();
        var mainPlugins = catalog.GetMainProjection(currentApi).Plugins;
        var counts = GetSidebarCounts(mainPlugins, installed, currentApi, currentDalamudVersion);

        // The icon rail starts at the same vertical baseline as the right-side content.
        ImGui.Dummy(new Vector2(0f, 38f));
        DrawSidebarViewIcon(MarketplaceView.Spotlight, FontAwesomeIcon.Star, "Spotlight", PromotedInternalNames.Length);
        DrawSidebarViewIcon(MarketplaceView.Discover, FontAwesomeIcon.Search, "Discover", mainPlugins.Count);
        DrawSidebarFooter(counts);
    }

    private void DrawSidebarFooter((int Installed, int Installable, int Outdated, int Updates) counts)
    {
        const float footerHeight = 192f;
        var targetY = Math.Max(ImGui.GetCursorPosY() + 12f, ImGui.GetWindowHeight() - footerHeight);
        ImGui.SetCursorPosY(targetY);

        if (DrawSidebarIcon(FontAwesomeIcon.Cog, "sidebar-settings", "Settings", settingsOpen))
            OpenSettings();

        ImGui.Spacing();
        DrawSidebarUtilityIcon(MarketplaceView.Updates, FontAwesomeIcon.Download, "Updates", counts.Updates, notificationCount: counts.Updates);
        DrawSidebarUtilityIcon(MarketplaceView.Library, FontAwesomeIcon.List, "Library", counts.Installed);

        ImGui.Spacing();
        ImGui.TextDisabled(BuildInfo.Version);
        if (ImGui.IsItemHovered())
        {
            var catalogRevision = string.IsNullOrWhiteSpace(catalog.CatalogRevision) ? "Not available" : catalog.CatalogRevision;
            var securityRevision = string.IsNullOrWhiteSpace(catalog.SecurityRevision) ? "Not available" : catalog.SecurityRevision;
            ImGui.SetTooltip($"Omega v{BuildInfo.Version}\nCatalog Revision: {catalogRevision}\nSecurity Revision: {securityRevision}");
        }
    }

    private void DrawSidebarUtilityIcon(MarketplaceView view, FontAwesomeIcon icon, string label, int count, int notificationCount = 0)
    {
        var tooltip = count > 0 ? $"{label} ({count})" : label;
        if (!DrawSidebarIcon(icon, $"sidebar-utility-{view}", tooltip, activeView == view, notificationCount))
            return;

        if (activeView != view)
            filtersOpen = false;
        activeView = view;
        detailsOpen = false;
        selectedPlugin = null;
        resetStorefrontScroll = true;
        if (view == MarketplaceView.Library)
            RefreshCollectionsIfNeeded(force: true);
    }

    private void OpenSettings()
    {
        InvalidateSourceCaches();
        settingsOpen = true;
        requestSettingsPopup = true;
    }

    private void RefreshSources()
    {
        if (updates.IsRefreshing)
            return;
        InvalidateSourceCaches();
        _ = updates.RefreshAsync();
    }

    private void DrawSidebarViewIcon(MarketplaceView view, FontAwesomeIcon icon, string label, int count)
    {
        var tooltip = count > 0 ? $"{label} ({count})" : label;
        if (!DrawSidebarIcon(icon, $"sidebar-view-{view}", tooltip, activeView == view))
            return;

        if (activeView != view)
            filtersOpen = false;
        activeView = view;
        detailsOpen = false;
        selectedPlugin = null;
        resetStorefrontScroll = true;
    }

    private static bool DrawSidebarIcon(FontAwesomeIcon icon, string id, string tooltip, bool active, int notificationCount = 0)
    {
        const float size = 42f;
        const float rounding = 6f;
        var available = ImGui.GetContentRegionAvail().X;
        var cursorX = ImGui.GetCursorPosX();
        ImGui.SetCursorPosX(cursorX + Math.Max(0f, (available - size) * 0.5f));

        var screen = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##omega-nav-{id}", new Vector2(size, size));
        var hovered = ImGui.IsItemHovered();
        var held = ImGui.IsItemActive();
        var clicked = ImGui.IsItemClicked();
        var draw = ImGui.GetWindowDrawList();

        // Resting navigation is visually part of the rail: no pill background and no border.
        // Only hover/active states receive a subtle square panel tint.
        if (active || hovered || held)
        {
            var background = ImGui.ColorConvertFloat4ToU32(active || held
                ? new Vector4(0.050f, 0.145f, 0.160f, 0.78f)
                : new Vector4(0.060f, 0.080f, 0.105f, 0.72f));
            draw.AddRectFilled(screen, screen + new Vector2(size, size), background, rounding);
        }

        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = icon.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        var glyphPosition = screen + new Vector2((size - glyphSize.X) * 0.5f, (size - glyphSize.Y) * 0.5f);
        var glyphColor = active || hovered
            ? ImGui.GetColorU32(ImGuiCol.Text)
            : ImGui.GetColorU32(ImGuiCol.TextDisabled);
        draw.AddText(glyphPosition, glyphColor, glyph);
        ImGui.PopFont();

        if (notificationCount > 0)
        {
            var countText = notificationCount > 99 ? "99+" : notificationCount.ToString();
            var textSize = ImGui.CalcTextSize(countText);
            const float badgeHeight = 15f;
            var badgeWidth = Math.Max(badgeHeight, textSize.X + 6f);
            var badgeMax = screen + new Vector2(size - 1f, 11f);
            var badgeMin = badgeMax - new Vector2(badgeWidth, badgeHeight);
            var badgeColor = ImGui.ColorConvertFloat4ToU32(new Vector4(0.50f, 0.10f, 0.13f, 0.94f));
            var badgeBorder = ImGui.ColorConvertFloat4ToU32(new Vector4(0.68f, 0.25f, 0.28f, 0.62f));
            draw.AddRectFilled(badgeMin, badgeMax, badgeColor, badgeHeight * 0.5f);
            draw.AddRect(badgeMin, badgeMax, badgeBorder, badgeHeight * 0.5f, ImDrawFlags.None, 1f);
            draw.AddText(
                badgeMin + new Vector2((badgeWidth - textSize.X) * 0.5f, (badgeHeight - textSize.Y) * 0.5f),
                0xFFFFFFFF,
                countText);
        }

        if (hovered)
            ImGui.SetTooltip(tooltip);
        return clicked;
    }

    private void DrawContentHeader(Version dalamudVersion, int currentApi)
    {
        ImGui.TextUnformatted(ViewTitle(activeView));

        if (!string.IsNullOrWhiteSpace(operationMessage))
            ImGui.TextWrapped(operationMessage);

        ImGui.Spacing();
    }

    private void DrawCatalogStatus(int currentApi)
    {
        if (!catalog.HasLoaded)
            ImGui.TextDisabled("Catalog database is empty — open Settings and refresh the online catalog");
        else if (!catalog.MatchesConfiguredSources(configuration.Repositories))
            ImGui.TextDisabled("Some enabled custom sources are not loaded — refresh them from Settings");
        else if (catalog.LastRefresh is not null)
            ImGui.TextDisabled($"{catalog.GetMainProjection(currentApi).Plugins.Count} plugins • {catalog.CachedRepositoryCount} database sources • {updates.ModeLabel} • checked {catalog.LastRefresh.Value.LocalDateTime:t}");

        if (!string.IsNullOrWhiteSpace(catalog.LastError))
        {
            ImGui.TextDisabled("Some sources failed during the last source refresh. Hover for details.");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(catalog.LastError);
        }

        if (!string.IsNullOrWhiteSpace(updates.LastOnlineError) && updates.Mode == CatalogAcquisitionMode.LocalCache)
        {
            ImGui.TextDisabled("Online catalog unavailable — Omega kept the last local SQLite database.");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(updates.LastOnlineError);
        }
    }

    public override void PreDraw()
    {
        Flags &= ~(ImGuiWindowFlags.NoMove | ImGuiWindowFlags.NoResize);

        if (isMinimized)
        {
            SizeConstraints = null;
            return;
        }

        SizeConstraints = new WindowSizeConstraints
        {
            MinimumSize = DefaultExpandedWindowSize,
            MaximumSize = new Vector2(float.MaxValue),
        };

        if (!migrateLegacyFullscreenGeometry)
            return;

        // 0.8.1.5 wrote forced-full-screen geometry into ImGui persistence. Override it
        // for exactly one expanded frame, then hand size/position ownership back to ImGui.
        var viewport = ImGui.GetMainViewport();
        var scaledDefault = DefaultExpandedWindowSize * ImGuiHelpers.GlobalScale;
        Size = DefaultExpandedWindowSize;
        SizeCondition = ImGuiCond.Always;
        Position = new Vector2(
            Math.Max(0f, (viewport.Size.X - scaledDefault.X) * 0.5f),
            Math.Max(0f, (viewport.Size.Y - scaledDefault.Y) * 0.5f));
        PositionCondition = ImGuiCond.Always;
    }

    private void CompleteLegacyFullscreenGeometryMigration()
    {
        if (!migrateLegacyFullscreenGeometry)
            return;

        migrateLegacyFullscreenGeometry = false;
        configuration.WindowGeometryRevision = 1;
        configuration.Save();

        // The one forced frame has already updated ImGui's persisted geometry. Future
        // frames must not impose any size or position, so user resizing remains authoritative.
        Size = null;
        Position = null;
        SizeCondition = ImGuiCond.FirstUseEver;
        PositionCondition = ImGuiCond.None;
    }

    private void CaptureExpandedWindowState()
    {
        expandedWindowSize = ImGui.GetWindowSize();
        expandedWindowPosition = ImGui.GetWindowPos();

        // Repair persisted geometry left behind by the old child-window minimize bug.
        // A normal Omega window can be narrow, but it should never be app-bar height.
        if (expandedWindowSize.Y > 96f)
            return;

        expandedWindowSize = DefaultExpandedWindowSize;
        ImGui.SetWindowSize(expandedWindowSize, ImGuiCond.Always);
    }

    private void EnterMinimizedMode()
    {
        // The minimize button is drawn inside the application-bar child window.
        // Do not recapture size or position here: those values would belong
        // to that child, not the top-level Omega window. Draw() already
        // snapshots the expanded top-level size and position before entering the
        // application bar, so preserve that state until restore.
        minimizedDragMoved = false;
        isMinimized = true;
        Flags |= ImGuiWindowFlags.NoBackground;
    }

    private void RestoreFromMinimizedMode()
    {
        isMinimized = false;
        minimizedDragMoved = false;
        Flags &= ~ImGuiWindowFlags.NoBackground;
        ImGui.SetWindowPos(expandedWindowPosition, ImGuiCond.Always);
        ImGui.SetWindowSize(expandedWindowSize, ImGuiCond.Always);
    }

    private void DrawMinimizedWindow()
    {
        const float windowSize = 58f;
        const float iconSize = 54f;
        ImGui.SetWindowSize(new Vector2(windowSize, windowSize), ImGuiCond.Always);
        ImGui.SetCursorPos(new Vector2(2f, 2f));

        var iconMin = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton("##omega-minimized-icon", new Vector2(iconSize, iconSize));
        if (ImGui.IsItemActivated())
            minimizedDragMoved = false;

        if (ImGui.IsItemActive() && ImGui.IsMouseDragging(ImGuiMouseButton.Left, 3f))
        {
            var delta = ImGui.GetIO().MouseDelta;
            minimizedDragMoved = true;
            ImGui.SetWindowPos(ImGui.GetWindowPos() + delta, ImGuiCond.Always);
            iconMin += delta;
        }

        var restore = ImGui.IsItemDeactivated() && !minimizedDragMoved;
        DrawMinimizedOmegaIcon(iconMin, iconSize);

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Click to restore Omega • drag to move");

        if (restore)
            RestoreFromMinimizedMode();
    }

    private void DrawMinimizedOmegaIcon(Vector2 iconMin, float iconSize)
    {
        var draw = ImGui.GetWindowDrawList();
        var iconMax = iconMin + new Vector2(iconSize, iconSize);
        var texture = omegaIconTexture?.GetWrapOrDefault();
        if (texture is not null)
        {
            draw.AddImage(texture.Handle, iconMin, iconMax);
            return;
        }

        draw.AddRectFilled(iconMin, iconMax, ImGui.GetColorU32(ImGuiCol.FrameBg), 12f);
        var glyph = "Ω";
        var glyphSize = ImGui.CalcTextSize(glyph);
        draw.AddText(
            iconMin + new Vector2((iconSize - glyphSize.X) * 0.5f, (iconSize - glyphSize.Y) * 0.5f),
            ImGui.GetColorU32(ImGuiCol.Text),
            glyph);
    }

    private static bool DrawPillButton(string label, string id, Vector2 size, bool active, bool danger = false)
    {
        var screen = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##omega-pill-{id}", size);
        var hovered = ImGui.IsItemHovered();
        var held = ImGui.IsItemActive();
        var clicked = ImGui.IsItemClicked();
        var draw = ImGui.GetWindowDrawList();

        uint bg;
        uint border;
        if (danger)
        {
            bg = ImGui.ColorConvertFloat4ToU32(held
                ? new Vector4(0.55f, 0.10f, 0.13f, 0.95f)
                : hovered
                    ? new Vector4(0.38f, 0.09f, 0.12f, 0.92f)
                    : new Vector4(0.14f, 0.07f, 0.09f, 0.80f));
            border = ImGui.ColorConvertFloat4ToU32(new Vector4(0.70f, 0.16f, 0.20f, hovered ? 0.95f : 0.55f));
        }
        else
        {
            bg = ImGui.ColorConvertFloat4ToU32(active || held
                ? new Vector4(0.035f, 0.29f, 0.30f, 0.95f)
                : hovered
                    ? new Vector4(0.055f, 0.20f, 0.22f, 0.95f)
                    : new Vector4(0.065f, 0.080f, 0.105f, 0.88f));
            border = ImGui.ColorConvertFloat4ToU32(new Vector4(0.08f, 0.55f, 0.52f, active || hovered ? 0.90f : 0.28f));
        }

        draw.AddRectFilled(screen, screen + size, bg, size.Y * 0.5f);
        draw.AddRect(screen, screen + size, border, size.Y * 0.5f, ImDrawFlags.None, 1f);

        var textSize = ImGui.CalcTextSize(label);
        var textPos = screen + new Vector2((size.X - textSize.X) * 0.5f, (size.Y - textSize.Y) * 0.5f);
        draw.AddText(textPos, ImGui.GetColorU32(ImGuiCol.Text), label);
        return clicked;
    }

}
