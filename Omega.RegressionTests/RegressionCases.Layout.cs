namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestMarketplaceLayoutGeometryContract()
    {
        Equal(6f, MarketplaceLayoutRules.ControlCornerRadius, "normal controls use a compact rounded rectangle rather than capsule geometry");
        Equal(88f, MarketplaceLayoutRules.LibraryRowHeight, "Library rows retain enough vertical room for three metadata lines");
        Equal(88f, MarketplaceLayoutRules.CollectionRowHeight, "collection rows retain enough vertical room for three metadata lines");
        Equal(36f, MarketplaceLayoutRules.ProductCollectionRowHeight, "Discover collection management rows stay compact and aligned");
        Equal(21f, MarketplaceLayoutRules.ProductCollectionImpactLineHeight, "expanded collection impact lists use predictable line spacing");
        Equal(98f, MarketplaceLayoutRules.InstallSourceRowHeight, "install repository rows retain room for four aligned metadata lines");
        Equal(17f, MarketplaceLayoutRules.CenterY(88f, 54f), "54px Library artwork is vertically centered");
        Equal(20f, MarketplaceLayoutRules.CenterY(88f, 48f), "48px collection artwork is vertically centered");
        Equal(28f, MarketplaceLayoutRules.CenterY(88f, 32f), "32px row actions are vertically centered");
        Equal(33f, MarketplaceLayoutRules.CenterY(88f, 22f), "22px switches are vertically centered");
        True(MarketplaceLayoutRules.FitsTextLines(88f, 10f, 19f, 3), "88px rows must fit three typical UI text lines with padding");
        False(MarketplaceLayoutRules.FitsTextLines(76f, 10f, 19f, 3), "the old 76px collection row is too short and must not return");
        Equal(788f, MarketplaceLayoutRules.RightAlignedX(900f, 100f), "row actions align from the right edge with standard padding");

        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));
        var collections = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Collections.cs"));
        var product = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductPage.cs"));
        var chrome = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Chrome.cs"));
        var install = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Install.cs"));

        Contains(library, "MarketplaceLayoutRules.CenterY", "Library row content uses deterministic vertical centering");
        Contains(collections, "MarketplaceLayoutRules.CenterY", "collection rows use deterministic vertical centering");
        Contains(collections, "MarketplaceLayoutRules.CollectionRowHeight", "collection rows use the tested height contract");
        Contains(chrome, "MarketplaceLayoutRules.ControlCornerRadius", "rounded rectangle controls use the tested radius contract");
        Contains(chrome, "DrawToggleSwitch", "binary state controls use a switch instead of status pills");
        Contains(install, "MarketplaceLayoutRules.InstallSourceRowHeight", "install source rows consume the tested fixed-height contract");
        Contains(install, "Shorten(candidate.SourceUrl, 88)", "repository URLs remain one bounded line instead of wrapping into adjacent rows");
        Contains(product, "private static void DrawProductSectionHeading(string title)", "product sections use a single header line");
        DoesNotContain(product, "ImGui.TextDisabled(subtitle)", "product section headings do not repeat explanatory subtitles");
        DoesNotContain(collections, "DrawPillButton(\n                entry.WantsEnabled", "collection plugin state must not regress to capsule buttons");
        Contains(product, "Managed by collection", "Discover identifies collection-managed plugins without redundant direct-toggle copy");
        DoesNotContain(product, "Direct toggle unavailable", "Discover does not repeat the unavailable-direct-toggle label");
        DoesNotContain(product, "ImGui.TextWrapped(control.Reason)", "Discover does not add a redundant collection-management explanation paragraph");
        Contains(product, "FontAwesomeIcon.CaretRight", "Discover collection impact rows default to a closed expand affordance");
        Contains(product, "StartCollectionToggle(collection, !collection.IsEnabled)", "Discover can change collection state from the membership row");
        Contains(product, "collection.Plugins", "expanded Discover collection rows enumerate all plugins affected by that collection state");
        Contains(product, "OpenCollectionView(collection)", "Discover collection names navigate to the selected collection");
    }
}
