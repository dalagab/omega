namespace Dalagab.Omega;

internal sealed record MarketplacePresentationContent(
    MarketplacePlugin Variant,
    IReadOnlyList<string> Images,
    string Summary,
    string Description,
    string Readme,
    bool IsEnhanced,
    int RichnessScore);

/// <summary>
/// Chooses presentation-only metadata from the exact package baseline selected by Omega.
/// Metadata, security state and the green preferred package therefore describe one source/artifact.
/// </summary>
internal static class MarketplacePresentationRules
{
    public static MarketplacePresentationContent Choose(
        MarketplacePlugin plugin,
        IEnumerable<MarketplacePlugin> variants)
    {
        // The selected/default variant is Omega's package baseline. Product metadata must come
        // from that same package source so the green package row, security summary and product
        // identity cannot silently describe different repository artifacts.
        _ = variants;
        var images = PresentationImages(plugin);
        var summary = ChooseSummary(plugin);
        var description = ChooseDescription(plugin);
        var readme = plugin.OmegaWebsiteReadmeExcerpt.Trim();
        return new MarketplacePresentationContent(
            plugin,
            images,
            summary,
            description,
            readme,
            plugin.OmegaEnriched,
            RichnessScore(plugin));
    }

    public static IReadOnlyList<string> PresentationImages(MarketplacePlugin plugin)
        => plugin.ImageUrls
            .Concat(plugin.OmegaWebsiteImageUrls)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .ToArray();

    public static int RichnessScore(MarketplacePlugin plugin)
    {
        var images = PresentationImages(plugin).Count;
        var description = Math.Min(1200, (plugin.Description?.Length ?? 0) + (plugin.OmegaWebsiteDescription?.Length ?? 0));
        var punchline = Math.Min(300, plugin.Punchline?.Length ?? 0);
        return (images * 10_000)
               + description
               + punchline
               + (plugin.OmegaEnriched ? 800 : 0)
               + (!string.IsNullOrWhiteSpace(plugin.IconUrl) ? 100 : 0)
               + (!string.IsNullOrWhiteSpace(plugin.RepoUrl) ? 50 : 0);
    }

    private static string ChooseSummary(MarketplacePlugin plugin)
    {
        if (!string.IsNullOrWhiteSpace(plugin.Punchline))
            return MarketplaceReadmeMarkup.ToInlineText(plugin.Punchline);
        if (!string.IsNullOrWhiteSpace(plugin.Description))
            return MarketplaceReadmeMarkup.ToInlineText(plugin.Description);
        return MarketplaceReadmeMarkup.ToInlineText(plugin.OmegaWebsiteDescription);
    }

    private static string ChooseDescription(MarketplacePlugin plugin)
    {
        var native = plugin.Description?.Trim() ?? string.Empty;
        var website = plugin.OmegaWebsiteDescription?.Trim() ?? string.Empty;
        if (native.Length >= 120 || website.Length == 0)
            return native;
        return website.Length > native.Length ? website : native;
    }

    private static string Identity(MarketplacePlugin plugin)
        => $"{plugin.SourceUrl}\u001f{plugin.AssemblyVersionText}\u001f{plugin.DalamudApiLevel}";
}
