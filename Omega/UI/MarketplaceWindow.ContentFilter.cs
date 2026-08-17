using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private IEnumerable<MarketplacePlugin> ApplyContentRatingFilter(IEnumerable<MarketplacePlugin> plugins)
        => contentFilter switch
        {
            MarketplaceContentFilter.ExcludeAdult => plugins.Where(plugin => !IsNsfwPlugin(plugin)),
            MarketplaceContentFilter.AdultOnly => plugins.Where(IsNsfwPlugin),
            _ => plugins,
        };

    private void DrawInlineContentRatingField()
    {
        ImGui.SetNextItemWidth(Math.Min(Ui(168f), ImGui.GetContentRegionAvail().X));
        if (!ImGui.BeginCombo("##filter-content-rating", ContentFilterLabel(contentFilter)))
            return;

        foreach (var value in Enum.GetValues<MarketplaceContentFilter>())
        {
            if (!ImGui.Selectable(ContentFilterLabel(value), contentFilter == value))
                continue;
            contentFilter = value;
            resetStorefrontScroll = true;
        }

        ImGui.EndCombo();
    }

    private static string ContentFilterLabel(MarketplaceContentFilter value) => value switch
    {
        MarketplaceContentFilter.ExcludeAdult => "Content: Exclude 18+",
        MarketplaceContentFilter.AdultOnly => "Content: 18+ only",
        _ => "Content: All",
    };
}
