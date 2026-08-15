using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

/// <summary>
/// Draws the user-facing Settings header. Repository and scanner implementation details stay out of
/// the in-game settings surface; per-plugin security intelligence is presented on plugin pages.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private bool DrawSettingsHeader()
    {
        ImGui.Text("Settings");
        DrawSettingsEulaShortcut();
        ImGui.Separator();
        DrawCatalogIdentity();
        ImGui.Separator();
        return eulaReviewOpen;
    }

    private void DrawCatalogIdentity()
    {
        ImGui.TextDisabled("Catalog identity");
        ImGui.TextUnformatted($"Omega: {BuildInfo.Version}");
        ImGui.TextUnformatted($"Catalog Revision: {DisplayRevision(catalog.CatalogRevision)}");
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Identifies the logical marketplace + security state. Use this value when troubleshooting a catalog mismatch.");
        ImGui.TextUnformatted($"Security Revision: {DisplayRevision(catalog.SecurityRevision)}");
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Identifies the current static-analysis state. Re-check timestamps alone do not change this revision.");
        ImGui.TextUnformatted($"Evidence Revision: {DisplayRevision(catalog.EvidenceRevision)}");
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Identifies the detailed server-side analysis evidence that produced the security summary. Omega does not download the evidence database.");
        ImGui.TextDisabled($"Changelog entries: {catalog.CatalogChangelogEntryCount}");
        if (catalog.RevisionUpdatedAtUtc is not null)
            ImGui.TextDisabled($"Revision updated: {catalog.RevisionUpdatedAtUtc.Value.ToLocalTime():g}");
    }

    private static string DisplayRevision(string value)
        => string.IsNullOrWhiteSpace(value) ? "Not available" : value;
}
