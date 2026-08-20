using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private const string UpdateChangelogPopupId = "Update changes###DalagabOmegaUpdateChangelog";
    private MarketplacePlugin? updateChangelogPlugin;
    private Version? updateChangelogInstalledVersion;
    private bool updateChangelogPopupOpen;

    private IReadOnlyList<MarketplaceChangelogEntry> BuildUpdateChangelogEntries(
        MarketplacePlugin plugin,
        Version? installedVersion)
    {
        var entries = BuildChangelogEntries(plugin);
        if (installedVersion is null)
            return entries;

        var newer = entries.Where(entry =>
            !Version.TryParse(entry.VersionText, out var version) || version > installedVersion).ToArray();
        return newer.Length > 0 ? newer : entries;
    }

    private void OpenUpdateChangelogPanel(MarketplacePlugin plugin, Version? installedVersion)
    {
        updateChangelogPlugin = plugin;
        updateChangelogInstalledVersion = installedVersion;
        updateChangelogPopupOpen = true;
        requestUpdateChangelogPopup = true;
    }

    private void DrawUpdateChangelogModal()
    {
        if (!updateChangelogPopupOpen || updateChangelogPlugin is null)
            return;

        var keepOpen = updateChangelogPopupOpen;
        ImGui.SetNextWindowSize(UiModalSize(650f, 460f), ImGuiCond.Appearing);
        ImGui.SetNextWindowSizeConstraints(UiModalSize(480f, 300f), UiModalSize(820f, 680f));
        if (!ImGui.BeginPopupModal(UpdateChangelogPopupId, ref keepOpen, ImGuiWindowFlags.NoTitleBar))
        {
            updateChangelogPopupOpen = keepOpen;
            return;
        }

        var plugin = updateChangelogPlugin;
        if (DrawOmegaModalHeader("Update changes", "update-changelog"))
        {
            CloseUpdateChangelogPanel();
            ImGui.EndPopup();
            return;
        }

        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        ImGui.TextColored(new Vector4(0.26f, 0.76f, 0.78f, 1f), FontAwesomeIcon.List.ToIconString());
        ImGui.PopFont();
        ImGui.SameLine(0f, Ui(9f));
        ImGui.TextUnformatted(plugin.Name);

        var installedText = updateChangelogInstalledVersion?.ToString() ?? "unknown";
        var targetText = plugin.AssemblyVersionText;
        ImGui.TextDisabled($"Installed v{installedText}  →  v{targetText}");
        ImGui.TextDisabled($"Repository: {SourceLabel(plugin)}");
        if (ImGui.IsItemHovered() && !string.IsNullOrWhiteSpace(plugin.SourceUrl))
            ImGui.SetTooltip(plugin.SourceUrl);

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        var entries = BuildUpdateChangelogEntries(plugin, updateChangelogInstalledVersion);
        ImGui.BeginChild("update-changelog-content", new Vector2(0f, -Ui(44f)), false);
        if (entries.Count == 0)
            ImGui.TextDisabled("No changelog published for this update.");
        else
            DrawChangelogEntries(entries, maximumEntries: 12);
        ImGui.EndChild();

        ImGui.Separator();
        if (ImGui.Button("Close", Ui(92f, 30f)))
        {
            CloseUpdateChangelogPanel();
            ImGui.EndPopup();
            return;
        }

        updateChangelogPopupOpen = keepOpen;
        ImGui.EndPopup();
        if (!keepOpen)
            CloseUpdateChangelogPanel(closePopup: false);
    }

    private void CloseUpdateChangelogPanel(bool closePopup = true)
    {
        updateChangelogPlugin = null;
        updateChangelogInstalledVersion = null;
        updateChangelogPopupOpen = false;
        if (closePopup)
            ImGui.CloseCurrentPopup();
    }
}
