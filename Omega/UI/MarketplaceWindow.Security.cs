using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

/// <summary>
/// Keeps Settings operational and owns Omega's concise product/about surface.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private const string AboutPopupId = "About Omega###DalagabOmegaAbout";

    private void DrawSettingsGeneralTab()
    {
        ImGui.TextUnformatted("Updates");
        ImGui.Spacing();
        if (ImGui.Button(updates.IsRefreshing ? "Checking for updates…" : "Check for updates") && !updates.IsRefreshing)
            CheckForUpdates();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Check for Omega, plugin list, and source updates.");

        ImGui.Spacing();
        if (selfUpdates.UpdateAvailable)
        {
            ImGui.TextColored(new Vector4(0.35f, 0.64f, 0.92f, 1f), $"Omega {selfUpdates.AvailableDisplayVersion} is available — open Updates to install it.");
        }
        if (updates.DefinitionsUpdateAvailable)
        {
            ImGui.TextColored(new Vector4(0.35f, 0.86f, 0.75f, 1f), "Plugin information update available — open Updates to apply it.");
        }
        else if (!string.IsNullOrWhiteSpace(updates.LastOnlineError))
        {
            ImGui.TextDisabled("Omega could not check online right now. Your current plugin information is still available.");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(updates.LastOnlineError);
        }

        ImGui.Dummy(new Vector2(Ui(1f), Ui(10f)));
        ImGui.Separator();
        ImGui.Dummy(new Vector2(Ui(1f), Ui(10f)));
        ImGui.TextUnformatted("General");
        ImGui.Spacing();

        DrawGeneralSetting(
            "Minimize Omega as a bar",
            "Show a small Omega bar instead of hiding the window completely.",
            "general-minimize-bar",
            configuration.MinimizeAsBar,
            value => configuration.MinimizeAsBar = value);
        DrawGeneralSetting(
            "Show Omega in the ESC / System menu",
            "Add Omega to the in-game System menu.",
            "general-system-menu",
            configuration.ShowInSystemMenu,
            value => configuration.ShowInSystemMenu = value);
        DrawGeneralSetting(
            "Show Omega before login",
            "Show Omega on the title screen.",
            "general-title-menu",
            configuration.ShowInTitleScreenMenu,
            value => configuration.ShowInTitleScreenMenu = value);
        DrawGeneralSetting(
            "Search everywhere",
            "Keep the search bar visible on every Omega page. Turn this off to show it only in Discover.",
            "general-search-everywhere",
            configuration.SearchEverywhere,
            value => configuration.SearchEverywhere = value);
        DrawDiscoverLayoutSetting();
        DrawGeneralSetting(
            "Advanced security information",
            "Show technical security details. Leave this off for the simpler view.",
            "general-advanced-security",
            configuration.ShowAdvancedSecurityInformation,
            value => configuration.ShowAdvancedSecurityInformation = value);

        ImGui.Dummy(new Vector2(Ui(1f), Ui(8f)));
        ImGui.TextUnformatted("Source trust");
        ImGui.TextWrapped("Choose whether Omega should ask just because it does not recognize a repository.");
        ImGui.Spacing();
        DrawGeneralSetting(
            "Trust unrecognized sources",
            "Skip only the extra source acknowledgement. Security findings, permission warnings, package differences, compatibility checks, and unsupported-plugin warnings still work.",
            "general-trust-unrecognized-sources",
            configuration.TrustUnrecognizedSources,
            value => configuration.TrustUnrecognizedSources = value);

        ImGui.Dummy(new Vector2(Ui(1f), Ui(8f)));
        ImGui.TextUnformatted("Install permissions");
        ImGui.TextWrapped("Stop and ask before installing a plugin that can do something you do not want.");
        ImGui.TextWrapped("Omega can warn before install, but Dalamud does not let Omega remove abilities after a plugin starts.");
        ImGui.Spacing();

        DrawGeneralSetting(
            "Warn about gameplay automation",
            "The plugin can control your character or play parts of the game for you.",
            "permission-bot-like",
            configuration.WarnOnBotLikeAutomation,
            value => configuration.WarnOnBotLikeAutomation = value);
        DrawGeneralSetting(
            "Warn about camera control",
            "The plugin can move or change the in-game camera.",
            "permission-camera",
            configuration.WarnOnCameraControl,
            value => configuration.WarnOnCameraControl = value);
        DrawGeneralSetting(
            "Warn about chat control",
            "The plugin can send, change, or automate messages in game chat.",
            "permission-chat",
            configuration.WarnOnChatControl,
            value => configuration.WarnOnChatControl = value);
        DrawGeneralSetting(
            "Warn about menu control",
            "The plugin can click, select, or move through game windows and menus for you.",
            "permission-menu",
            configuration.WarnOnMenuControl,
            value => configuration.WarnOnMenuControl = value);

        ImGui.Spacing();
        if (ImGui.Button("Show tutorial again", Ui(170f, 32f)))
            StartTutorial();
    }

    private void DrawDiscoverLayoutSetting()
    {
        var startY = ImGui.GetCursorPosY();
        ImGui.TextUnformatted("Discover layout");
        ImGui.TextDisabled("Choose how plugin results are shown in Discover.");

        var comboWidth = Ui(190f);
        ImGui.SetCursorPos(new Vector2(
            Math.Max(ImGui.GetCursorPosX(), ImGui.GetWindowWidth() - comboWidth - Ui(34f)),
            startY));
        ImGui.SetNextItemWidth(comboWidth);
        if (ImGui.BeginCombo("##general-discover-layout", DiscoverLayoutLabel(configuration.DiscoverLayout)))
        {
            foreach (var mode in Enum.GetValues<DiscoverLayoutMode>())
            {
                var selected = mode == configuration.DiscoverLayout;
                if (ImGui.Selectable(DiscoverLayoutLabel(mode), selected))
                {
                    configuration.DiscoverLayout = mode;
                    configuration.Save();
                    resetDiscoverListScroll = true;
                    resetStorefrontScroll = true;
                }
            }
            ImGui.EndCombo();
        }

        ImGui.SetCursorPosY(Math.Max(ImGui.GetCursorPosY(), startY + Ui(30f)));
        ImGui.TextWrapped(DiscoverLayoutDescription(configuration.DiscoverLayout));
        ImGui.SetCursorPosY(Math.Max(ImGui.GetCursorPosY(), startY + Ui(72f)));
        ImGui.Separator();
        ImGui.Spacing();
    }

    private static string DiscoverLayoutLabel(DiscoverLayoutMode mode)
        => mode switch
        {
            DiscoverLayoutMode.CompactCards => "Compact cards",
            DiscoverLayoutMode.List => "List",
            _ => "Dynamic",
        };

    private static string DiscoverLayoutDescription(DiscoverLayoutMode mode)
        => mode switch
        {
            DiscoverLayoutMode.CompactCards => "Small cards with plugin icons and the same status indicators, without screenshots.",
            DiscoverLayoutMode.List => "One row per plugin for the densest overview.",
            _ => "Show screenshots when a plugin has them, then use list rows for the rest.",
        };

    private void DrawGeneralSetting(string label, string description, string id, bool value, Action<bool> apply)
    {
        // General preferences are a simple list: one explicit checkbox and its explanation per row.
        var startY = ImGui.GetCursorPosY();
        var selected = value;
        if (ImGui.Checkbox($"##settings-{id}", ref selected))
        {
            apply(selected);
            configuration.Save();
            behaviorConfigurationChanged();
        }

        ImGui.SameLine(0f, Ui(10f));
        ImGui.BeginGroup();
        ImGui.TextUnformatted(label);
        ImGui.TextDisabled(description);
        ImGui.EndGroup();

        ImGui.SetCursorPosY(Math.Max(ImGui.GetCursorPosY(), startY + Ui(46f)));
        ImGui.Separator();
        ImGui.Spacing();
    }

    private bool DrawSettingsLegalTab()
    {
        ImGui.TextUnformatted("Agreement");
        ImGui.Spacing();
        DrawSettingsEulaShortcut();
        return eulaReviewOpen;
    }

    private void CheckForUpdates()
    {
        if (updates.IsRefreshing)
            return;
        InvalidateSourceCaches();
        operationMessage = "Checking for updates…";
        _ = CheckForUpdatesFromUiAsync();
    }

    private async Task CheckForUpdatesFromUiAsync()
    {
        await Task.WhenAll(updates.CheckForUpdatesAsync(), selfUpdates.CheckNowAsync()).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(updates.LastOnlineError))
            operationMessage = $"Omega could not refresh the online plugin information: {updates.LastOnlineError}";
        else if (!string.IsNullOrWhiteSpace(selfUpdates.LastError))
            operationMessage = $"Omega update check failed: {selfUpdates.LastError}";
        else
            operationMessage = string.Empty;
    }

    private async Task ApplyDefinitionsUpdateFromUiAsync()
    {
        await updates.ApplyDefinitionsUpdateAsync().ConfigureAwait(false);
        operationMessage = !string.IsNullOrWhiteSpace(updates.LastOnlineError)
            ? $"Plugin information update failed: {updates.LastOnlineError}"
            : updates.DefinitionsUpdateAvailable
                ? "Plugin information update is still waiting to be applied."
                : string.Empty;
    }

    private void OpenAbout()
    {
        aboutOpen = true;
        requestAboutPopup = true;
    }

    private void DrawAboutModal()
    {
        if (!aboutOpen)
            return;

        var keepOpen = aboutOpen;
        ImGui.SetNextWindowSize(UiModalSize(660f, 570f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal(AboutPopupId, ref keepOpen, ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoCollapse))
        {
            aboutOpen = keepOpen;
            return;
        }

        if (DrawOmegaModalHeader("About Omega", "about", showMark: false))
        {
            aboutOpen = false;
            ImGui.CloseCurrentPopup();
            ImGui.EndPopup();
            return;
        }

        DrawAboutIdentityHero();
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();
        DrawAboutVersionAndDefinitions();
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        // Keep identity and Definitions visible while the longer product/help copy below can scroll.
        // Remove the child's extra horizontal padding so the lower copy stays on the same left edge
        // as Version/Definitions instead of drifting inward a second time.
        var aboutScrollPadding = ImGui.GetStyle().WindowPadding;
        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(0f, aboutScrollPadding.Y));
        ImGui.BeginChild("omega-about-scrollable-body", Vector2.Zero, false);
        DrawAboutProductPitch();
        ImGui.EndChild();
        ImGui.PopStyleVar();

        aboutOpen = keepOpen && aboutOpen;
        ImGui.EndPopup();
    }


    private void DrawAboutIdentityHero()
    {
        var iconSize = Ui(112f);
        var leftInset = Ui(12f);
        var startX = ImGui.GetCursorPosX() + leftInset;
        var startY = ImGui.GetCursorPosY();

        ImGui.SetCursorPos(new Vector2(startX, startY));
        var iconMin = ImGui.GetCursorScreenPos();
        ImGui.Dummy(new Vector2(iconSize, iconSize));
        var texture = omegaIconTexture?.GetWrapOrDefault();
        if (texture is not null)
        {
            ImGui.GetWindowDrawList().AddImage(texture.Handle, iconMin, iconMin + new Vector2(iconSize, iconSize));
        }
        else
        {
            ImGui.GetWindowDrawList().AddRectFilled(
                iconMin,
                iconMin + new Vector2(iconSize, iconSize),
                ImGui.GetColorU32(ImGuiCol.FrameBg),
                Ui(16f));
            const string glyph = "Ω";
            var glyphSize = ImGui.CalcTextSize(glyph);
            ImGui.GetWindowDrawList().AddText(
                iconMin + new Vector2((iconSize - glyphSize.X) * 0.5f, (iconSize - glyphSize.Y) * 0.5f),
                ImGui.GetColorU32(ImGuiCol.Text),
                glyph);
        }

        ImGui.SetCursorPos(new Vector2(startX + iconSize + Ui(24f), startY + Ui(12f)));
        ImGui.BeginGroup();
        ImGui.TextUnformatted("Omega");
        ImGui.TextDisabled("Dalagab Group");
        ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.35f, 0.86f, 0.75f, 1f), "Every plugin. One orbit.");
        ImGui.EndGroup();

        ImGui.SetCursorPosY(startY + iconSize);
    }

    private void DrawAboutVersionAndDefinitions()
    {
        var revision = !string.IsNullOrWhiteSpace(catalog.DefinitionsRevision)
            ? catalog.DefinitionsRevision
            : string.IsNullOrWhiteSpace(catalog.CatalogRevision)
                ? (catalog.HasLoaded ? "Loaded revision unavailable" : "Not loaded")
                : catalog.CatalogRevision;

        ImGui.TextUnformatted("Version");
        ImGui.SameLine(0f, Ui(10f));
        var versionValueX = ImGui.GetCursorPosX();
        ImGui.TextColored(new Vector4(0.35f, 0.86f, 0.75f, 1f), BuildInfo.Version);
        DrawAboutCommunityShortcuts(versionValueX);

        ImGui.Spacing();
        ImGui.TextUnformatted("Definitions");
        ImGui.SameLine(0f, Ui(10f));
        ImGui.TextColored(new Vector4(0.35f, 0.86f, 0.75f, 1f), revision);
        if (catalog.DatabaseSizeBytes > 0)
        {
            ImGui.SameLine(0f, Ui(8f));
            ImGui.TextDisabled($"({FormatDefinitionsDatabaseSize(catalog.DatabaseSizeBytes)})");
            if (ImGui.IsItemHovered())
                SetReadableTooltip($"Local Omega Definitions database: {catalog.DatabaseSizeBytes:N0} bytes");
        }
    }

    private static string FormatDefinitionsDatabaseSize(long bytes)
    {
        if (bytes < 1024L)
            return $"{bytes} B";
        if (bytes < 1024L * 1024L)
            return $"{bytes / 1024d:0.0} KiB";
        if (bytes < 1024L * 1024L * 1024L)
            return $"{bytes / (1024d * 1024d):0.0} MiB";
        return $"{bytes / (1024d * 1024d * 1024d):0.00} GiB";
    }

    private void DrawAboutProductPitch()
    {
        ImGui.TextUnformatted("Open Omega");
        ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.35f, 0.86f, 0.75f, 1f), "/omega   /omg");
        ImGui.Spacing();
        ImGui.Spacing();
        DrawAboutWrappedBullet("Discover official and community plugins.");
        DrawAboutWrappedBullet("Compare sources, compatibility and findings.");
        DrawAboutWrappedBullet("Manage plugins, collections and updates.");
    }

    private static void DrawAboutWrappedBullet(string text)
    {
        ImGui.Bullet();
        ImGui.SameLine();
        ImGui.PushTextWrapPos(0f);
        ImGui.TextWrapped(text);
        ImGui.PopTextWrapPos();
    }

}
