using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private long popularityCatalogRevision = -1;
    private int popularityCurrentApi;
    private MarketplacePopularitySnapshot popularitySnapshot = new(0, 0, 0d, 0d);

    private MarketplacePopularitySnapshot GetPopularitySnapshot(int currentApi)
    {
        if (popularityCatalogRevision == catalog.Revision && popularityCurrentApi == currentApi)
            return popularitySnapshot;

        popularityCatalogRevision = catalog.Revision;
        popularityCurrentApi = currentApi;
        popularitySnapshot = catalog.GetDailyPopularitySnapshot(currentApi);
        return popularitySnapshot;
    }

    private void DrawProductPopularityMetadataRow(MarketplacePlugin plugin, int currentApi)
    {
        var snapshot = GetPopularitySnapshot(currentApi);
        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        ImGui.TextDisabled("Popularity");
        ImGui.TableSetColumnIndex(1);

        if (!snapshot.HasData)
        {
            ImGui.TextDisabled("—");
            return;
        }

        var percent = snapshot.RelativePercentFor(plugin.DownloadCount);
        DrawPopularityBar(percent);
        var hovered = ImGui.IsItemHovered();
        ImGui.SameLine(0f, Ui(10f));
        ImGui.TextUnformatted(MarketplacePopularityRules.FormatPercent(percent));
        hovered |= ImGui.IsItemHovered();
        if (hovered)
            SetReadableTooltip(MarketplacePopularityRules.Describe(plugin.DownloadCount, snapshot));
    }
    private static void DrawPopularityBar(double percent)
    {
        var normalized = (float)Math.Clamp(percent / 100d, 0d, 1d);
        var size = Ui(210f, 12f);
        var min = ImGui.GetCursorScreenPos();
        var max = min + size;
        ImGui.InvisibleButton("##omega-product-popularity-bar", size);

        var draw = ImGui.GetWindowDrawList();
        var track = ImGui.GetColorU32(ImGuiCol.FrameBg);
        var active = ImGui.GetColorU32(ImGuiCol.PlotHistogram);
        var marker = ImGui.GetColorU32(ImGuiCol.Text);
        var rounding = Ui(5f);
        draw.AddRectFilled(min, max, track, rounding);

        var markerX = min.X + size.X * normalized;
        if (normalized > 0f)
            draw.AddRectFilled(min, new Vector2(markerX, max.Y), active, rounding);

        var markerHalfWidth = Ui(1.5f);
        draw.AddRectFilled(
            new Vector2(markerX - markerHalfWidth, min.Y - Ui(2f)),
            new Vector2(markerX + markerHalfWidth, max.Y + Ui(2f)),
            marker,
            Ui(1f));
    }

}
