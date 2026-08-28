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

        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, Ui(18f, 16f));
        ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, Ui(16f));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, Ui(14f));
        ImGui.PushStyleVar(ImGuiStyleVar.PopupRounding, Ui(14f));
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, Ui(12f));
        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Ui(11f, 7f));
        ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, Ui(10f, 8f));
        ImGui.PushStyleVar(ImGuiStyleVar.ScrollbarSize, Ui(9f));
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
        var mainProjection = catalog.GetMainProjection(currentApi);
        var mainPlugins = mainProjection.Plugins;
        var discoverPluginCount = MarketplaceCatalogRules.CountUniquePlugins(mainProjection.Variants);
        var counts = GetSidebarCounts(mainPlugins, installed, currentApi, currentDalamudVersion);

        // Keep the primary destinations visually attached to the top application bar.
        ImGui.Dummy(Ui(0f, 6f));
        DrawSidebarViewIcon(MarketplaceView.Spotlight, FontAwesomeIcon.Star, "Spotlight", 0);
        DrawSidebarViewIcon(MarketplaceView.Discover, FontAwesomeIcon.Search, "Discover", discoverPluginCount);
        DrawSidebarFooter(counts);
    }

    private void DrawSidebarFooter((int Installed, int Installable, int Outdated, int Updates) counts)
    {
        var footerHeight = Ui(192f);
        var targetY = Math.Max(ImGui.GetCursorPosY() + Ui(12f), ImGui.GetWindowHeight() - footerHeight);
        ImGui.SetCursorPosY(targetY);

        if (DrawSidebarIcon(FontAwesomeIcon.Cog, "sidebar-settings", "Settings", settingsOpen))
            OpenSettings();

        ImGui.Spacing();
        var definitionsUpdateCount = updates.DefinitionsUpdateAvailable ? 1 : 0;
        var applicationUpdateCount = selfUpdates.UpdateAvailable ? 1 : 0;
        DrawSidebarUtilityIcon(
            MarketplaceView.Updates,
            FontAwesomeIcon.Download,
            "Updates",
            counts.Updates + applicationUpdateCount + definitionsUpdateCount,
            notificationCount: counts.Updates + applicationUpdateCount,
            definitionsAttention: updates.DefinitionsUpdateAvailable);
        DrawSidebarUtilityIcon(MarketplaceView.Library, FontAwesomeIcon.List, "Library", counts.Installed);

        ImGui.Spacing();
        var versionSize = ImGui.CalcTextSize(BuildInfo.Version);
        var versionButtonSize = versionSize + Ui(8f, 4f);
        var versionAvailable = ImGui.GetContentRegionAvail().X;
        var versionCursorX = ImGui.GetCursorPosX();
        ImGui.SetCursorPosX(versionCursorX + Math.Max(0f, (versionAvailable - versionButtonSize.X) * 0.5f));
        ImGui.InvisibleButton("##omega-about-version", versionButtonSize);
        var versionHovered = ImGui.IsItemHovered();
        var versionPosition = ImGui.GetItemRectMin();
        ImGui.GetWindowDrawList().AddText(
            versionPosition + new Vector2((versionButtonSize.X - versionSize.X) * 0.5f, Ui(2f)),
            ImGui.GetColorU32(versionHovered ? ImGuiCol.Text : ImGuiCol.TextDisabled),
            BuildInfo.Version);
        if (versionHovered)
            ImGui.SetTooltip("About Omega");
        if (ImGui.IsItemClicked())
            OpenAbout();
    }

    private void DrawSidebarUtilityIcon(
        MarketplaceView view,
        FontAwesomeIcon icon,
        string label,
        int count,
        int notificationCount = 0,
        bool definitionsAttention = false)
    {
        var tooltip = count > 0 ? $"{label} ({count})" : label;
        if (definitionsAttention)
            tooltip += " — Definitions update available";
        if (!DrawSidebarIcon(icon, $"sidebar-utility-{view}", tooltip, activeView == view, notificationCount, definitionsAttention))
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
        RefreshDalamudRepositoryAwareness();
        settingsOpen = true;
        requestSettingsPopup = true;
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

    private bool DrawSidebarIcon(
        FontAwesomeIcon icon,
        string id,
        string tooltip,
        bool active,
        int notificationCount = 0,
        bool definitionsAttention = false)
    {
        var size = Ui(42f);
        var rounding = Ui(6f);
        var available = ImGui.GetContentRegionAvail().X;
        var cursorX = ImGui.GetCursorPosX();
        ImGui.SetCursorPosX(cursorX + Math.Max(0f, (available - size) * 0.5f));

        var screen = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##omega-nav-{id}", new Vector2(size, size));
        RememberTutorialTarget(id);
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

        if (definitionsAttention)
        {
            // Definitions availability is deliberately distinct from plugin/app updates: a blue
            // exclamation circle sits on the upper-left of the Downloads rail icon and survives
            // restarts through CatalogUpdateCoordinator's persisted online state.
            var center = screen + Ui(4f, 5f);
            var radius = Ui(8f);
            draw.AddCircleFilled(center, radius, ImGui.ColorConvertFloat4ToU32(new Vector4(0.12f, 0.48f, 0.86f, 0.98f)), 20);
            draw.AddCircle(center, radius, ImGui.ColorConvertFloat4ToU32(new Vector4(0.38f, 0.70f, 1f, 0.96f)), 20, 1f);
            var mark = "!";
            var markSize = ImGui.CalcTextSize(mark);
            draw.AddText(center - (markSize * 0.5f), 0xFFFFFFFF, mark);
        }

        if (notificationCount > 0)
        {
            var countText = notificationCount > 99 ? "99+" : notificationCount.ToString();
            var textSize = ImGui.CalcTextSize(countText);
            var badgeHeight = Ui(15f);
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

    private void DrawContentHeader(
        Version dalamudVersion,
        int currentApi,
        IReadOnlyDictionary<string, IExposedPlugin> installed)
    {
        ImGui.TextUnformatted(ViewTitle(activeView));

        if (activeView == MarketplaceView.Updates)
        {
            DrawUpdatesToolbar(installed, currentApi, dalamudVersion);
            DrawApplicationUpdateBanner();
        }

        if (ShouldDrawOperationStatus())
            ImGui.TextWrapped(operationMessage);

        ImGui.Spacing();
    }

    private bool ShouldDrawOperationStatus()
    {
        if (string.IsNullOrWhiteSpace(operationMessage))
            return false;
        if (installTask is not null || updateTask is not null || updateAllActive || updateAllDefinitionsTask is not null ||
            uninstallTask is not null || repositoryTask is not null || collectionOperationTask is not null ||
            configBackupTask is not null || updates.IsRefreshing || selfUpdates.IsChecking)
            return true;

        var message = operationMessage.ToLowerInvariant();
        return message.Contains("failed", StringComparison.Ordinal) ||
               message.Contains("error", StringComparison.Ordinal) ||
               message.Contains("could not", StringComparison.Ordinal) ||
               message.Contains("unavailable", StringComparison.Ordinal);
    }

    private void DrawApplicationUpdateBanner()
    {
        if (!selfUpdates.UpdateAvailable)
            return;

        ImGui.Spacing();
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.035f, 0.09f, 0.18f, 0.76f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.12f, 0.42f, 0.78f, 0.78f));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, Ui(4f));
        ImGui.BeginChild("omega-application-update-banner", new Vector2(0f, Ui(72f)), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
        ImGui.TextUnformatted($"Omega {selfUpdates.AvailableDisplayVersion} is available");
        ImGui.TextDisabled($"You are running Omega {BuildInfo.Version}. Dalamud remains the update authority.");
        ImGui.SameLine(Math.Max(Ui(340f), ImGui.GetWindowWidth() - Ui(190f)));
        if (ImGui.Button("Open Dalamud updates"))
            Plugin.PluginInterface.OpenPluginInstallerTo(PluginInstallerOpenKind.UpdateablePlugins, "Omega");
        ImGui.EndChild();
        ImGui.PopStyleVar();
        ImGui.PopStyleColor(2);
        ImGui.Spacing();
    }

    private void DrawCatalogStatus(int currentApi)
    {
        if (!catalog.HasLoaded)
            ImGui.TextDisabled("Definitions are empty — open Settings and check for updates");
        else if (!catalog.MatchesConfiguredSources(configuration.Repositories))
            ImGui.TextDisabled("Some enabled custom sources are not loaded — check for updates from Settings");
        else if (catalog.LastRefresh is not null)
        {
            var projection = catalog.GetMainProjection(currentApi);
            var uniquePluginCount = MarketplaceCatalogRules.CountUniquePlugins(projection.Variants);
            ImGui.TextDisabled($"{uniquePluginCount} plugins • {catalog.CachedRepositoryCount} Definitions sources • {updates.ModeLabel} • checked {catalog.LastRefresh.Value.LocalDateTime:t}");
        }

        if (!string.IsNullOrWhiteSpace(catalog.LastError))
        {
            ImGui.TextDisabled("Some sources failed during the last source refresh. Hover for details.");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(catalog.LastError);
        }

        if (!string.IsNullOrWhiteSpace(updates.LastOnlineError) && updates.Mode == CatalogAcquisitionMode.LocalCache)
        {
            ImGui.TextDisabled("Online Definitions unavailable — Omega kept the last local Definitions.");
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

        var responsiveMinimum = ResponsiveMinimumWindowLogicalSize();
        SizeConstraints = new WindowSizeConstraints
        {
            MinimumSize = responsiveMinimum,
            MaximumSize = new Vector2(float.MaxValue),
        };
        // WindowHost multiplies Size/SizeConstraints by Dalamud's GlobalScale. Keep the logical
        // default small enough that the resulting physical window remains inside the game viewport.
        Size = ResponsiveDefaultWindowLogicalSize();

        if (!migrateLegacyFullscreenGeometry)
            return;

        // 0.8.1.5 wrote forced-full-screen geometry into ImGui persistence. Override it
        // for exactly one expanded frame, then hand size/position ownership back to ImGui.
        var viewport = ImGui.GetMainViewport();
        var logicalDefault = ResponsiveDefaultWindowLogicalSize();
        var scaledDefault = logicalDefault * ImGuiHelpers.GlobalScale;
        Size = logicalDefault;
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

        var viewport = ImGui.GetMainViewport();
        var maximumComfortable = viewport.WorkSize * 0.96f;
        var preferredPhysical = ResponsiveDefaultWindowLogicalSize() * OmegaUiScale;

        // A previously persisted 100%-scale geometry can become physically larger than the game
        // viewport when Dalamud is moved to 150-200%. Repair only genuinely off-screen geometry;
        // normal user resizing below that boundary remains authoritative.
        if (expandedWindowSize.X > maximumComfortable.X || expandedWindowSize.Y > maximumComfortable.Y)
        {
            expandedWindowSize = new Vector2(
                Math.Min(preferredPhysical.X, maximumComfortable.X),
                Math.Min(preferredPhysical.Y, maximumComfortable.Y));
            ImGui.SetWindowSize(expandedWindowSize, ImGuiCond.Always);
            return;
        }

        // Repair persisted geometry left behind by the old child-window minimize bug.
        // A normal Omega window can be narrow, but it should never be app-bar height.
        if (expandedWindowSize.Y > Ui(96f))
            return;

        expandedWindowSize = preferredPhysical;
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
        if (configuration.MinimizeAsBar)
        {
            DrawMinimizedBar();
            return;
        }

        DrawMinimizedIconWindow();
    }

    private void DrawMinimizedIconWindow()
    {
        var windowSize = Ui(58f);
        var iconSize = Ui(54f);
        ImGui.SetWindowSize(new Vector2(windowSize, windowSize), ImGuiCond.Always);
        ImGui.SetCursorPos(Ui(2f, 2f));

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

    private void DrawMinimizedBar()
    {
        var barSize = Ui(190f, 42f);
        ImGui.SetWindowSize(barSize, ImGuiCond.Always);
        ImGui.SetCursorPos(Vector2.Zero);

        var min = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton("##omega-minimized-bar", barSize);
        if (ImGui.IsItemActivated())
            minimizedDragMoved = false;

        if (ImGui.IsItemActive() && ImGui.IsMouseDragging(ImGuiMouseButton.Left, 3f))
        {
            var delta = ImGui.GetIO().MouseDelta;
            minimizedDragMoved = true;
            ImGui.SetWindowPos(ImGui.GetWindowPos() + delta, ImGuiCond.Always);
            min += delta;
        }

        var restore = ImGui.IsItemDeactivated() && !minimizedDragMoved;
        var draw = ImGui.GetWindowDrawList();
        var max = min + barSize;
        draw.AddRectFilled(min, max, ImGui.ColorConvertFloat4ToU32(new Vector4(0.075f, 0.085f, 0.105f, 0.97f)), Ui(8f));
        draw.AddRect(min, max, ImGui.ColorConvertFloat4ToU32(new Vector4(0.20f, 0.24f, 0.28f, 0.90f)), Ui(8f), ImDrawFlags.None, 1f);

        var iconMin = min + Ui(5f, 5f);
        var iconSize = Ui(32f);
        DrawMinimizedOmegaIcon(iconMin, iconSize);
        var labelPos = min + Ui(48f, 11f);
        draw.AddText(labelPos, ImGui.GetColorU32(ImGuiCol.Text), "Omega");

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

    private static bool DrawRoundedButton(
        string label,
        string id,
        Vector2 size,
        bool active = false,
        bool danger = false,
        bool enabled = true)
    {
        var screen = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##omega-rounded-{id}", size);
        var hovered = enabled && ImGui.IsItemHovered();
        var held = enabled && ImGui.IsItemActive();
        var clicked = enabled && ImGui.IsItemClicked();
        var draw = ImGui.GetWindowDrawList();

        Vector4 bgColor;
        Vector4 borderColor;
        if (!enabled)
        {
            bgColor = new Vector4(0.08f, 0.09f, 0.11f, 0.72f);
            borderColor = new Vector4(0.20f, 0.22f, 0.26f, 0.45f);
        }
        else if (danger)
        {
            bgColor = held
                ? new Vector4(0.55f, 0.10f, 0.13f, 0.95f)
                : hovered
                    ? new Vector4(0.38f, 0.09f, 0.12f, 0.92f)
                    : new Vector4(0.14f, 0.07f, 0.09f, 0.80f);
            borderColor = new Vector4(0.70f, 0.16f, 0.20f, hovered ? 0.95f : 0.55f);
        }
        else
        {
            bgColor = active || held
                ? new Vector4(0.035f, 0.29f, 0.30f, 0.95f)
                : hovered
                    ? new Vector4(0.055f, 0.20f, 0.22f, 0.95f)
                    : new Vector4(0.065f, 0.080f, 0.105f, 0.88f);
            borderColor = new Vector4(0.08f, 0.55f, 0.52f, active || hovered ? 0.90f : 0.28f);
        }

        var rounding = MarketplaceLayoutRules.ControlCornerRadius;
        draw.AddRectFilled(screen, screen + size, ImGui.ColorConvertFloat4ToU32(bgColor), rounding);
        draw.AddRect(screen, screen + size, ImGui.ColorConvertFloat4ToU32(borderColor), rounding, ImDrawFlags.None, 1f);

        var textSize = ImGui.CalcTextSize(label);
        var textPos = screen + new Vector2((size.X - textSize.X) * 0.5f, (size.Y - textSize.Y) * 0.5f);
        draw.AddText(textPos, ImGui.GetColorU32(enabled ? ImGuiCol.Text : ImGuiCol.TextDisabled), label);
        return clicked;
    }

    private static bool DrawToggleSwitch(string id, bool value, bool enabled = true)
    {
        var size = Ui(44f, 22f);
        var min = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##omega-toggle-{id}", size);
        var hovered = enabled && ImGui.IsItemHovered();
        var clicked = enabled && ImGui.IsItemClicked();
        var draw = ImGui.GetWindowDrawList();

        var track = !enabled
            ? new Vector4(0.18f, 0.19f, 0.22f, 0.58f)
            : value
                ? new Vector4(0.03f, hovered ? 0.56f : 0.46f, hovered ? 0.54f : 0.47f, 0.96f)
                : new Vector4(0.22f, 0.24f, 0.28f, hovered ? 0.96f : 0.84f);
        draw.AddRectFilled(min, min + size, ImGui.ColorConvertFloat4ToU32(track), size.Y * 0.5f);

        var knobRadius = Ui(8f);
        var knobX = value ? min.X + size.X - 11f : min.X + 11f;
        var knobColor = enabled
            ? new Vector4(0.94f, 0.95f, 0.96f, 1f)
            : new Vector4(0.62f, 0.64f, 0.68f, 0.75f);
        draw.AddCircleFilled(new Vector2(knobX, min.Y + size.Y * 0.5f), knobRadius, ImGui.ColorConvertFloat4ToU32(knobColor), 18);
        return clicked;
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
