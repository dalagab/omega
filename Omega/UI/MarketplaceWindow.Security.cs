using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

/// <summary>
/// Keeps Settings operational and owns Omega's concise product/about surface.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private const string AboutPopupId = "About Omega###DalagabOmegaAbout";

    private bool DrawSettingsHeader()
    {
        if (ImGui.Button(updates.IsRefreshing ? "Checking for updates…" : "Check for updates") && !updates.IsRefreshing)
            CheckForUpdates();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Check for new Omega Definitions and refresh your added plugin sources.");

        ImGui.SameLine();
        DrawSettingsEulaShortcut();

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

        ImGui.Separator();
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
        ImGui.SetNextWindowSize(new Vector2(620f, 420f), ImGuiCond.Appearing);
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
        DrawAboutProductPitch();

        aboutOpen = keepOpen && aboutOpen;
        ImGui.EndPopup();
    }


    private void DrawAboutIdentityHero()
    {
        const float iconSize = 112f;
        var available = ImGui.GetContentRegionAvail().X;
        var heroWidth = Math.Min(470f, available);
        var startX = ImGui.GetCursorPosX() + Math.Max(0f, (available - heroWidth) * 0.5f);
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
                16f);
            const string glyph = "Ω";
            var glyphSize = ImGui.CalcTextSize(glyph);
            ImGui.GetWindowDrawList().AddText(
                iconMin + new Vector2((iconSize - glyphSize.X) * 0.5f, (iconSize - glyphSize.Y) * 0.5f),
                ImGui.GetColorU32(ImGuiCol.Text),
                glyph);
        }

        ImGui.SetCursorPos(new Vector2(startX + iconSize + 24f, startY + 12f));
        ImGui.BeginGroup();
        ImGui.TextUnformatted("Omega");
        ImGui.TextDisabled($"Version {BuildInfo.Version} · Dalagab Group");
        ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.35f, 0.86f, 0.75f, 1f), "Every plugin. One orbit.");
        ImGui.PushTextWrapPos(startX + heroWidth);
        ImGui.TextWrapped("Discover the wider Dalamud plugin ecosystem in one marketplace — then choose the source you trust.");
        ImGui.PopTextWrapPos();
        ImGui.EndGroup();

        ImGui.SetCursorPosY(startY + iconSize);
    }

    private static void DrawAboutProductPitch()
    {
        ImGui.TextUnformatted("Open Omega");
        ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.35f, 0.86f, 0.75f, 1f), "/omega   /omg");
        ImGui.TextDisabled("Either command opens the marketplace from chat.");

        ImGui.Spacing();
        ImGui.Spacing();
        ImGui.TextUnformatted("Find more. Know more. Install with confidence.");
        ImGui.Spacing();
        ImGui.BulletText("Spotlight and Discover bring official and community plugins into one searchable storefront.");
        ImGui.BulletText("Compare repositories, compatibility, packages and security findings before you choose a source.");
        ImGui.BulletText("Keep installed plugins, collections and available updates together in Library.");
        ImGui.BulletText("When you install, update or remove something, Dalamud remains in control of the plugin lifecycle.");
    }

}
