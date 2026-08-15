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
        return eulaReviewOpen;
    }
}
