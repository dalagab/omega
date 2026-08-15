namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestMarketplaceLayoutGeometryContract()
    {
        Equal(6f, MarketplaceLayoutRules.ControlCornerRadius, "normal controls use a compact rounded rectangle rather than capsule geometry");
        Equal(88f, MarketplaceLayoutRules.LibraryRowHeight, "Library rows retain enough vertical room for three metadata lines");
        Equal(88f, MarketplaceLayoutRules.CollectionRowHeight, "collection rows retain enough vertical room for three metadata lines");
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

        Contains(library, "MarketplaceLayoutRules.CenterY", "Library row content uses deterministic vertical centering");
        Contains(collections, "MarketplaceLayoutRules.CenterY", "collection rows use deterministic vertical centering");
        Contains(collections, "MarketplaceLayoutRules.CollectionRowHeight", "collection rows use the tested height contract");
        Contains(chrome, "MarketplaceLayoutRules.ControlCornerRadius", "rounded rectangle controls use the tested radius contract");
        Contains(chrome, "DrawToggleSwitch", "binary state controls use a switch instead of status pills");
        DoesNotContain(collections, "DrawPillButton(\n                entry.WantsEnabled", "collection plugin state must not regress to capsule buttons");
        Contains(product, "Direct toggle unavailable", "Discover explains when collection membership prevents direct plugin control");
        Contains(product, "OpenCollectionView(membership.Collection)", "Discover collection buttons navigate to the selected collection");
    }
}
