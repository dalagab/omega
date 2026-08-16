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
/// Chooses presentation-only metadata with official-source precedence. When Dalamud official
/// metadata exists it owns the product presentation as well as installation identity; richer
/// community presentation is used only when no official variant exists.
/// </summary>
internal static class MarketplacePresentationRules
{
    public static MarketplacePresentationContent Choose(
        MarketplacePlugin plugin,
        IEnumerable<MarketplacePlugin> variants)
    {
        var candidates = new[] { plugin }
            .Concat(variants)
            .Where(x => x.InternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase))
            .GroupBy(Identity, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.OrderByDescending(RichnessScore).First())
            .ToArray();

        var officialCandidates = candidates.Where(x => x.SourceIsOfficial).ToArray();
        var presentationPool = officialCandidates.Length > 0 ? officialCandidates : candidates;
        var richest = presentationPool
            .OrderByDescending(x => PresentationImages(x).Count)
            .ThenByDescending(RichnessScore)
            .ThenByDescending(x => x.AssemblyVersion)
            .FirstOrDefault() ?? plugin;

        var images = PresentationImages(richest);
        var summary = ChooseSummary(richest);
        var description = ChooseDescription(richest);
        var readme = richest.OmegaWebsiteReadmeExcerpt.Trim();
        var enhanced = candidates.Any(x => x.OmegaEnriched);
        return new MarketplacePresentationContent(
            richest,
            images,
            summary,
            description,
            readme,
            enhanced,
            RichnessScore(richest));
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
            return plugin.Punchline.Trim();
        if (!string.IsNullOrWhiteSpace(plugin.Description))
            return plugin.Description.Trim();
        return plugin.OmegaWebsiteDescription.Trim();
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
