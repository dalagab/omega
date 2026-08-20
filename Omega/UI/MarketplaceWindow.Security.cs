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
            ImGui.SetTooltip("Check for new Omega Definitions and refresh your added plugin sources.");

        ImGui.Spacing();
        if (selfUpdates.UpdateAvailable)
        {
            ImGui.TextColored(new Vector4(0.35f, 0.64f, 0.92f, 1f), $"Omega {selfUpdates.AvailableDisplayVersion} is available — open Updates to install through Dalamud.");
        }
        if (updates.DefinitionsUpdateAvailable)
        {
            ImGui.TextColored(new Vector4(0.35f, 0.86f, 0.75f, 1f), "Definitions update available — open Updates to apply it.");
        }
        else if (!string.IsNullOrWhiteSpace(updates.LastOnlineError))
        {
            ImGui.TextDisabled("The online Definitions check failed; your current local Definitions remain active.");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(updates.LastOnlineError);
        }
    }

    private void DrawSettingsBehaviorTab()
    {
        ImGui.TextUnformatted("Plugin behavior");
        ImGui.Spacing();

        DrawBehaviorSetting(
            "Minimize Omega as a bar",
            "Use the compact bar when minimized.",
            "behavior-minimize-bar",
            configuration.MinimizeAsBar,
            value => configuration.MinimizeAsBar = value);
        DrawBehaviorSetting(
            "Show Omega in the ESC / System menu",
            "Show Omega in the ESC/System menu.",
            "behavior-system-menu",
            configuration.ShowInSystemMenu,
            value => configuration.ShowInSystemMenu = value);
        DrawBehaviorSetting(
            "Show Omega before login",
            "Show Omega on the title screen.",
            "behavior-title-menu",
            configuration.ShowInTitleScreenMenu,
            value => configuration.ShowInTitleScreenMenu = value);
    }

    private void DrawBehaviorSetting(string label, string description, string id, bool value, Action<bool> apply)
    {
        var start = ImGui.GetCursorPos();
        ImGui.TextUnformatted(label);
        ImGui.TextDisabled(description);
        var toggleWidth = Ui(44f);
        ImGui.SetCursorPos(new Vector2(Math.Max(start.X, ImGui.GetWindowWidth() - toggleWidth - Ui(34f)), start.Y));
        if (DrawToggleSwitch(id, value))
        {
            apply(!value);
            configuration.Save();
            behaviorConfigurationChanged();
        }
        ImGui.SetCursorPosY(Math.Max(ImGui.GetCursorPosY(), start.Y + Ui(52f)));
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
        operationMessage = "Checking for Omega, plugin and Definitions updates…";
        _ = CheckForUpdatesFromUiAsync();
    }

    private async Task CheckForUpdatesFromUiAsync()
    {
        await Task.WhenAll(updates.CheckForUpdatesAsync(), selfUpdates.CheckNowAsync()).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(updates.LastOnlineError))
            operationMessage = $"Update check completed with an online Definitions error: {updates.LastOnlineError}";
        else if (!string.IsNullOrWhiteSpace(selfUpdates.LastError))
            operationMessage = $"Omega update check failed: {selfUpdates.LastError}";
        else
            operationMessage = string.Empty;
    }

    private async Task ApplyDefinitionsUpdateFromUiAsync()
    {
        await updates.ApplyDefinitionsUpdateAsync().ConfigureAwait(false);
        operationMessage = !string.IsNullOrWhiteSpace(updates.LastOnlineError)
            ? $"Definitions update failed: {updates.LastOnlineError}"
            : updates.DefinitionsUpdateAvailable
                ? "Definitions update is still pending."
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

        if (DrawOmegaModalHeader("About Omega", "about"))
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
        ImGui.TextColored(new Vector4(0.35f, 0.86f, 0.75f, 1f), BuildInfo.Version);

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
