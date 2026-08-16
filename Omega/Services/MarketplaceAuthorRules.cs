using System.Text.RegularExpressions;

namespace Dalagab.Omega;

/// <summary>
/// Normalizes manifest author strings into individual identities so one contributor can be used as
/// a marketplace navigation/filter target even when a repository publishes several names together.
/// Generic contributor labels remain presentation text but are not emitted as clickable identities.
/// </summary>
internal static class MarketplaceAuthorRules
{
    private static readonly string[] GenericAuthorLabels =
    [
        "contributors",
        "various contributors",
        "and contributors",
        "team",
        "community",
        "unknown",
        "unknown author",
    ];

    public static IReadOnlyList<string> Split(string? authorText)
    {
        if (string.IsNullOrWhiteSpace(authorText))
            return [];

        var normalized = Regex.Replace(
            authorText.Trim(),
            @"\s+and\s+",
            ",",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return normalized
            .Split([',', ';', '&'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(Clean)
            .Where(value => value.Length > 0 && !GenericAuthorLabels.Contains(value, StringComparer.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string Clean(string value)
        => value.Trim().Trim('.', '•', '-', '–', '—').Trim();
}
