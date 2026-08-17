using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private IEnumerable<MarketplacePlugin> ApplySecurityFilter(IEnumerable<MarketplacePlugin> plugins)
        => securityFilter switch
        {
            MarketplaceSecurityFilter.Scanned => plugins.Where(x => x.HasCompletedSecurityScan),
            MarketplaceSecurityFilter.NotScanned => plugins.Where(x => !x.HasCompletedSecurityScan),
            MarketplaceSecurityFilter.CautionOrHigher => plugins.Where(x =>
                x.SecurityHighestSeverity is "caution" or "high" or "critical"),
            MarketplaceSecurityFilter.HighOrCritical => plugins.Where(x =>
                x.SecurityHighestSeverity is "high" or "critical"),
            _ => plugins,
        };

    private void DrawInlineSecurityField()
    {
        ImGui.SetNextItemWidth(Math.Min(Ui(190f), ImGui.GetContentRegionAvail().X));
        if (!ImGui.BeginCombo("##filter-security", SecurityFilterLabel(securityFilter)))
            return;
        foreach (var value in Enum.GetValues<MarketplaceSecurityFilter>())
        {
            if (!ImGui.Selectable(SecurityFilterLabel(value), securityFilter == value))
                continue;
            securityFilter = value;
            resetStorefrontScroll = true;
        }
        ImGui.EndCombo();
    }

    private static string SecurityFilterLabel(MarketplaceSecurityFilter value) => value switch
    {
        MarketplaceSecurityFilter.Scanned => "Security: Scanned",
        MarketplaceSecurityFilter.NotScanned => "Security: Not scanned",
        MarketplaceSecurityFilter.CautionOrHigher => "Security: Caution+",
        MarketplaceSecurityFilter.HighOrCritical => "Security: High/Critical",
        _ => "Security: Any",
    };
}
