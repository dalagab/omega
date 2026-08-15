using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

/// <summary>
/// Keeps Settings operational. Version/revision identity belongs to the About popup opened from
/// the version number in the application rail.
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
        operationMessage = "Checking for plugin and Definitions updates…";
        _ = CheckForUpdatesFromUiAsync();
    }

    private async Task CheckForUpdatesFromUiAsync()
    {
        await updates.CheckForUpdatesAsync().ConfigureAwait(false);
        operationMessage = updates.DefinitionsUpdateAvailable
            ? "Definitions update available. Open Updates to review it."
            : string.IsNullOrWhiteSpace(updates.LastOnlineError)
                ? "Update check complete."
                : $"Update check completed with an online Definitions error: {updates.LastOnlineError}";
    }

    private async Task ApplyDefinitionsUpdateFromUiAsync()
    {
        await updates.ApplyDefinitionsUpdateAsync().ConfigureAwait(false);
        operationMessage = !updates.DefinitionsUpdateAvailable && string.IsNullOrWhiteSpace(updates.LastOnlineError)
            ? "Definitions updated."
            : string.IsNullOrWhiteSpace(updates.LastOnlineError)
                ? "Definitions update is still pending."
                : $"Definitions update failed: {updates.LastOnlineError}";
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
        DrawDefinitionsIdentity();

        aboutOpen = keepOpen && aboutOpen;
        ImGui.EndPopup();
    }


    private void DrawAboutIdentityHero()
    {
        const float iconSize = 112f;
        var available = ImGui.GetContentRegionAvail().X;
        var heroWidth = Math.Min(420f, available);
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

        ImGui.SetCursorPos(new Vector2(startX + iconSize + 24f, startY + 24f));
        ImGui.BeginGroup();
        ImGui.TextUnformatted("Omega");
        ImGui.TextDisabled($"Version {BuildInfo.Version}");
        ImGui.Spacing();
        ImGui.TextDisabled("Dalagab Group");
        ImGui.EndGroup();

        ImGui.SetCursorPosY(startY + iconSize);
    }

    private void DrawDefinitionsIdentity()
    {
        ImGui.TextDisabled("Definitions identity");
        ImGui.TextUnformatted($"Definitions Revision: {DisplayRevision(catalog.CatalogRevision)}");
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Identifies the logical marketplace Definitions plus current security state.");
        ImGui.TextUnformatted($"Security Revision: {DisplayRevision(catalog.SecurityRevision)}");
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Identifies the current static-analysis state. Re-check timestamps alone do not change this revision.");
        ImGui.TextUnformatted($"Evidence Revision: {DisplayRevision(catalog.EvidenceRevision)}");
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Identifies the detailed server-side evidence that produced the security summary. Omega does not download the evidence database.");
        ImGui.TextDisabled($"Definitions changelog entries: {catalog.CatalogChangelogEntryCount}");
        if (catalog.RevisionUpdatedAtUtc is not null)
            ImGui.TextDisabled($"Definitions updated: {catalog.RevisionUpdatedAtUtc.Value.ToLocalTime():g}");

        if (updates.DefinitionsUpdateAvailable)
        {
            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.35f, 0.86f, 0.75f, 1f), "A newer Definitions revision is available.");
            if (!string.IsNullOrWhiteSpace(updates.AvailableDefinitionsRevision))
                ImGui.TextDisabled($"Available: {updates.AvailableDefinitionsRevision}");
        }
    }

    private static string DisplayRevision(string value)
        => string.IsNullOrWhiteSpace(value) ? "Not available" : value;
}
