using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Plugin;

namespace Dalagab.Omega;

/// <summary>
/// Keeps unavailable marketplace entries readable but visually subordinate. Installed plugins stay
/// full-strength even when their source no longer offers a compatible package, because Library is
/// describing software the user already has rather than an install candidate.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private bool IsListingCurrentlyAvailable(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
        => installedPlugin is not null ||
           HasInstallableVariant(plugin.InternalName, currentApi, currentDalamudVersion);

    private static bool PushUnavailableListingStyle(bool available)
    {
        if (available)
            return false;

        ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.42f, 0.44f, 0.47f, 1f));
        ImGui.PushStyleColor(ImGuiCol.TextDisabled, new Vector4(0.32f, 0.34f, 0.37f, 1f));
        ImGui.PushStyleVar(ImGuiStyleVar.Alpha, 0.76f);
        return true;
    }

    /// <summary>
    /// Tooltips must remain readable even when the hovered listing is intentionally dimmed because
    /// its package targets another Dalamud API. ImGui inherits the current text/alpha style into
    /// tooltips, so temporarily restore normal tooltip contrast.
    /// </summary>
    private static void SetReadableTooltip(string text)
    {
        ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.94f, 0.95f, 0.97f, 1f));
        ImGui.PushStyleColor(ImGuiCol.TextDisabled, new Vector4(0.70f, 0.73f, 0.78f, 1f));
        ImGui.PushStyleVar(ImGuiStyleVar.Alpha, 1f);
        ImGui.SetTooltip(text);
        ImGui.PopStyleVar();
        ImGui.PopStyleColor(2);
    }

    private static void PopUnavailableListingStyle(bool pushed)
    {
        if (!pushed)
            return;
        ImGui.PopStyleVar();
        ImGui.PopStyleColor(2);
    }
}
