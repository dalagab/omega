namespace Dalagab.Omega;

internal enum RepositoryProviderKind
{
    Dalamud,
    PuniSh,
    NightmareXiv,
    CombatReborn,
    SeaOfStars,
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
/// catalog size without exposing a "large list" label in the UI. Dalamud, Puni.sh, NightmareXIV,
/// Combat Reborn and Sea of Stars may establish the canonical package/security baseline. This provenance tier
/// never lowers, hides, or overrides findings produced for the selected artifact.
/// </summary>
internal static class RepositoryProviderRules
{
    public const int LargeRepositoryPluginThreshold = 20;

    public const string DalamudIconUrl = "https://avatars.githubusercontent.com/u/64093182?v=4";
    public const string PuniShIconUrl = "https://puni.sh/favicon.png";
    public const string NightmareXivIconUrl = "https://avatars.githubusercontent.com/u/111540168?v=4";
    public const string CombatRebornIconUrl = "https://avatars.githubusercontent.com/u/165236076?v=4";
    public const string SeaOfStarsIconUrl = "https://avatars.githubusercontent.com/u/70807659?v=4";

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


        if (Contains(identity, "sea of stars") ||
            Contains(identity, "seaofstars") ||
            Contains(identity, "ottermandias/seaofstars"))
        {
            return new RepositoryProviderPresentation(
                RepositoryProviderKind.SeaOfStars,
                "Sea of Stars",
                4,
                SeaOfStarsIconUrl);
        }

        if (pluginCount >= LargeRepositoryPluginThreshold)
        {
            return new RepositoryProviderPresentation(
                RepositoryProviderKind.LargeRepository,
                "Community",
                5,
                string.Empty);
        }

        return new RepositoryProviderPresentation(
            RepositoryProviderKind.Other,
            "Community",
            6,
            string.Empty);
    }

    public static int SortPriority(string? sourceName, string? sourceUrl, bool official, int pluginCount = 0)
        => Classify(sourceName, sourceUrl, official, pluginCount).Priority;

    /// <summary>
    /// Returns whether this repository may establish Omega's canonical package/security baseline.
    /// This is provenance stability only; it does not lower or override static-analysis findings.
    /// </summary>
    public static bool IsStableProvider(string? sourceName, string? sourceUrl, bool official)
        => Classify(sourceName, sourceUrl, official).Kind is
            RepositoryProviderKind.Dalamud or
            RepositoryProviderKind.PuniSh or
            RepositoryProviderKind.NightmareXiv or
            RepositoryProviderKind.CombatReborn or
            RepositoryProviderKind.SeaOfStars;

    public static int SecurityBaselinePriority(string? sourceName, string? sourceUrl, bool official)
    {
        var provider = Classify(sourceName, sourceUrl, official);
        return IsStableProvider(sourceName, sourceUrl, official) ? provider.Priority : int.MaxValue;
    }

    /// <summary>
    /// Returns whether Omega requires explicit consent before installing from this source.
    /// Recognized stable providers are not automatically "safe"; this only distinguishes sources
    /// whose publishing identity Omega already recognizes from other community repositories.
    /// Sigmascope findings and package-divergence review remain independent gates.
    /// </summary>
    public static bool RequiresExplicitInstallAcknowledgement(string? sourceName, string? sourceUrl, bool official)
        => !official && !IsStableProvider(sourceName, sourceUrl, official);

    public static string TrustLabel(string? sourceName, string? sourceUrl, bool official)
        => official
            ? "Dalamud official"
            : IsStableProvider(sourceName, sourceUrl, official)
                ? "Recognized community"
                : "Unrecognized community";

    private static bool Contains(string haystack, string needle)
        => haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
}
