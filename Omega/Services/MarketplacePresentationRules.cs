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
    {
        var iconIdentity = NormalizeImageIdentity(plugin.IconUrl);
        var bannerIdentity = NormalizeImageIdentity(plugin.OmegaBannerUrl);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();

        foreach (var candidate in plugin.ImageUrls.Concat(plugin.OmegaWebsiteImageUrls))
        {
            if (!TryNormalizePresentableImage(candidate, out var identity))
                continue;

            // The product hero already owns the package icon and Omega banner. Showing either of
            // them again as a project screenshot makes the screenshot strip look like duplicate
            // artwork rather than actual project imagery.
            if ((!string.IsNullOrWhiteSpace(iconIdentity) && identity.Equals(iconIdentity, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrWhiteSpace(bannerIdentity) && identity.Equals(bannerIdentity, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (!seen.Add(identity))
                continue;

            result.Add(candidate.Trim());
            if (result.Count >= 5)
                break;
        }

        return result;
    }

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

    private static bool TryNormalizePresentableImage(string? value, out string identity)
    {
        identity = NormalizeImageIdentity(value);
        if (string.IsNullOrWhiteSpace(identity))
            return false;

        return Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri) &&
               (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase));
    }

    private static string NormalizeImageIdentity(string? value)
    {
        if (!Uri.TryCreate((value ?? string.Empty).Trim(), UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            return string.Empty;
        }

        var host = uri.Host.ToLowerInvariant();
        var path = uri.AbsolutePath;
        if (host.Equals("github.com", StringComparison.OrdinalIgnoreCase))
        {
            var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 5 && parts[2].Equals("blob", StringComparison.OrdinalIgnoreCase))
            {
                host = "raw.githubusercontent.com";
                path = $"/{parts[0]}/{parts[1]}/{parts[3]}/{string.Join("/", parts.Skip(4))}";
            }
        }

        if (host.Equals("raw.githubusercontent.com", StringComparison.OrdinalIgnoreCase))
            path = path.Replace("/refs/heads/", "/", StringComparison.OrdinalIgnoreCase);

        return $"{host}{Uri.UnescapeDataString(path).TrimEnd('/')}";
    }

    private static string Identity(MarketplacePlugin plugin)
        => $"{plugin.SourceUrl}\u001f{plugin.AssemblyVersionText}\u001f{plugin.DalamudApiLevel}";
}
