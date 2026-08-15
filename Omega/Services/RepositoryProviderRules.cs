namespace Dalagab.Omega;

internal enum RepositoryProviderKind
{
    Dalamud,
    PuniSh,
    NightmareXiv,
    CombatReborn,
    LargeRepository,
    Other,
}

internal sealed record RepositoryProviderPresentation(
    RepositoryProviderKind Kind,
    string Label,
    int Priority,
    string IconUrl);

/// <summary>
/// Gives repositories a stable provider tier for ordering and presentation. Explicitly recognized
/// publishers are preferred first; broad community repositories are then promoted by current
/// catalog size without exposing a "large list" label in the UI. Provider preference is a source
/// selection heuristic only and is intentionally separate from Omega's security scan results.
/// </summary>
internal static class RepositoryProviderRules
{
    public const int LargeRepositoryPluginThreshold = 20;

    public const string DalamudIconUrl = "https://avatars.githubusercontent.com/u/64093182?v=4";
    public const string PuniShIconUrl = "https://puni.sh/favicon.png";
    public const string NightmareXivIconUrl = "https://avatars.githubusercontent.com/u/111540168?v=4";
    public const string CombatRebornIconUrl = "https://avatars.githubusercontent.com/u/165236076?v=4";

    public static RepositoryProviderPresentation Classify(
        string? sourceName,
        string? sourceUrl,
        bool official,
        int pluginCount = 0)
    {
        var name = (sourceName ?? string.Empty).Trim();
        var url = (sourceUrl ?? string.Empty).Trim();
        var identity = $"{name}\n{url}";

        if (official ||
            Contains(identity, "dalamud official") ||
            Contains(identity, "goatcorp/dalamudplugins"))
        {
            return new RepositoryProviderPresentation(
                RepositoryProviderKind.Dalamud,
                "Dalamud",
                0,
                DalamudIconUrl);
        }

        if (Contains(identity, "puni.sh") ||
            Contains(identity, "puni-sh") ||
            Contains(identity, "punish"))
        {
            return new RepositoryProviderPresentation(
                RepositoryProviderKind.PuniSh,
                "Puni.sh",
                1,
                PuniShIconUrl);
        }

        if (Contains(identity, "nightmarexiv"))
        {
            return new RepositoryProviderPresentation(
                RepositoryProviderKind.NightmareXiv,
                "NightmareXIV",
                2,
                NightmareXivIconUrl);
        }

        if (Contains(identity, "ffxiv-combatreborn") ||
            Contains(identity, "combatrebornrepo") ||
            Contains(identity, "combat reborn"))
        {
            return new RepositoryProviderPresentation(
                RepositoryProviderKind.CombatReborn,
                "Combat Reborn",
                3,
                CombatRebornIconUrl);
        }

        if (pluginCount >= LargeRepositoryPluginThreshold)
        {
            return new RepositoryProviderPresentation(
                RepositoryProviderKind.LargeRepository,
                "Community",
                4,
                string.Empty);
        }

        return new RepositoryProviderPresentation(
            RepositoryProviderKind.Other,
            "Community",
            5,
            string.Empty);
    }

    public static int SortPriority(string? sourceName, string? sourceUrl, bool official, int pluginCount = 0)
        => Classify(sourceName, sourceUrl, official, pluginCount).Priority;

    private static bool Contains(string haystack, string needle)
        => haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
}
