using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private string productUsageCacheKey = string.Empty;
    private string productUsageCacheValue = string.Empty;

    private string ResolveProductUsage(MarketplacePresentationContent content)
    {
        var key = $"{content.Variant.InternalName}\u001f{content.Variant.SourceUrl}\u001f{content.Variant.AssemblyVersionText}\u001f{content.Description.GetHashCode()}\u001f{content.Readme.GetHashCode()}";
        if (key.Equals(productUsageCacheKey, StringComparison.Ordinal))
            return productUsageCacheValue;
        productUsageCacheKey = key;
        productUsageCacheValue = MarketplaceUsageRules.Extract(content).Trim();
        return productUsageCacheValue;
    }

    private void DrawProductUsage(MarketplacePresentationContent content)
    {
        var usage = ResolveProductUsage(content);
        if (string.IsNullOrWhiteSpace(usage))
            return;

        DrawProductSectionHeading("How to use");
        ImGui.Indent(14f);
        ImGui.TextDisabled("Commands, controls and usage information collected from the plugin's own metadata or public project README.");
        ImGui.Dummy(new Vector2(Ui(1f), Ui(5f)));
        ImGui.PushTextWrapPos(ImGui.GetCursorPosX() + Math.Max(Ui(320f), Math.Min(Ui(940f), ImGui.GetContentRegionAvail().X)));
        ImGui.TextWrapped(usage);
        ImGui.PopTextWrapPos();
        ImGui.Unindent(14f);
    }

    private void DrawProductChangelog(MarketplacePlugin plugin)
    {
        var entries = BuildChangelogEntries(plugin);
        if (entries.Count == 0)
            return;

        DrawProductSectionHeading("Changelog");
        ImGui.Indent(14f);
        DrawChangelogEntries(entries, maximumEntries: 8);
        ImGui.Unindent(14f);
    }

    private IReadOnlyList<MarketplaceChangelogEntry> BuildChangelogEntries(MarketplacePlugin plugin)
    {
        var history = catalog.GetChangelogHistory(plugin.InternalName, plugin.SourceUrl).ToList();
        var currentText = (plugin.Changelog ?? string.Empty).Trim();
        if (!string.IsNullOrWhiteSpace(currentText) && !history.Any(entry =>
                entry.VersionText.Equals(plugin.AssemblyVersionText, StringComparison.OrdinalIgnoreCase) &&
                entry.Changelog.Equals(currentText, StringComparison.Ordinal)))
        {
            history.Insert(0, new MarketplaceChangelogEntry(
                plugin.InternalName,
                plugin.SourceName,
                plugin.SourceUrl,
                plugin.AssemblyVersionText,
                plugin.LastUpdate,
                currentText,
                true));
        }
        return history;
    }

    private static void DrawChangelogEntries(IReadOnlyList<MarketplaceChangelogEntry> entries, int maximumEntries)
    {
        foreach (var entry in entries.Take(maximumEntries))
        {
            var date = PluginUpdateRules.NormalizeUnix(entry.LastUpdate) > 0
                ? DateTimeOffset.FromUnixTimeSeconds(PluginUpdateRules.NormalizeUnix(entry.LastUpdate)).ToLocalTime().ToString("yyyy-MM-dd")
                : string.Empty;
            var heading = string.IsNullOrWhiteSpace(date)
                ? $"v{entry.VersionText}"
                : $"v{entry.VersionText}  •  {date}";
            ImGui.TextUnformatted(heading);
            if (!string.IsNullOrWhiteSpace(entry.SourceName))
            {
                ImGui.SameLine(0f, 8f);
                ImGui.TextDisabled(entry.SourceName);
            }
            ImGui.PushTextWrapPos(ImGui.GetCursorPosX() + Math.Max(Ui(300f), Math.Min(Ui(900f), ImGui.GetContentRegionAvail().X)));
            ImGui.TextWrapped(entry.Changelog);
            ImGui.PopTextWrapPos();
            ImGui.Dummy(new Vector2(Ui(1f), Ui(7f)));
        }
        if (entries.Count > maximumEntries)
            ImGui.TextDisabled($"{entries.Count - maximumEntries} older changelog entr{(entries.Count - maximumEntries == 1 ? "y" : "ies")} retained in Definitions.");
    }

    private bool DrawInlineChangelogButton(MarketplacePlugin plugin, string id)
    {
        var entries = BuildChangelogEntries(plugin);
        if (entries.Count == 0)
            return false;

        var size = Ui(20f);
        if (ImGui.InvisibleButton($"##{id}", new Vector2(size, size)))
            ImGui.OpenPopup($"{id}-popup");
        var min = ImGui.GetItemRectMin();
        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = FontAwesomeIcon.List.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        ImGui.GetWindowDrawList().AddText(min + (new Vector2(size, size) - glyphSize) * 0.5f, ImGui.GetColorU32(ImGuiCol.TextDisabled), glyph);
        ImGui.PopFont();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("View update changelog");

        ImGui.SetNextWindowSizeConstraints(UiModalSize(420f, 180f), UiModalSize(760f, 620f));
        if (ImGui.BeginPopup($"{id}-popup"))
        {
            ImGui.TextUnformatted($"{plugin.Name} changelog");
            ImGui.Separator();
            DrawChangelogEntries(entries, maximumEntries: 12);
            ImGui.EndPopup();
        }
        return true;
    }
}
