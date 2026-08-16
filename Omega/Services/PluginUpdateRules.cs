namespace Dalagab.Omega;

/// <summary>
/// Determines whether a package from Omega's preferred (green) package baseline is a real update
/// for an installed plugin. Assembly versions are only comparable within one publishing lineage;
/// cross-repository candidates therefore require manifest chronology as well as a version increase.
/// </summary>
internal static class PluginUpdateRules
{
    public static bool IsUpdateCandidate(
        Version installedVersion,
        string? installedSourceUrl,
        long installedLastUpdate,
        MarketplacePlugin candidate,
        bool useTesting)
    {
        var offered = useTesting
            ? candidate.TestingAssemblyVersion ?? candidate.AssemblyVersion
            : candidate.AssemblyVersion;
        if (offered.CompareTo(installedVersion) <= 0)
            return false;

        var sameSource = IsSamePublishingSource(installedSourceUrl, candidate.SourceUrl, candidate.SourceIsOfficial);
        var installedDate = NormalizeUnix(installedLastUpdate);
        var offeredDate = NormalizeUnix(candidate.LastUpdate);

        // A repository is authoritative for its own monotonically increasing assembly versions.
        // If both timestamps exist, still reject an obvious chronology rollback.
        if (sameSource)
            return installedDate <= 0 || offeredDate <= 0 || offeredDate >= installedDate;

        // AssemblyVersion values from different repositories/forks are not a shared sequence.
        // Only call it an update when both manifests establish that the preferred artifact is newer.
        return installedDate > 0 && offeredDate > installedDate;
    }

    public static long NormalizeUnix(long value)
    {
        if (value <= 0)
            return 0;
        return value > 100_000_000_000L ? value / 1000L : value;
    }

    public static bool IsSamePublishingSource(string? installedSourceUrl, string? candidateSourceUrl, bool candidateOfficial)
    {
        var installed = NormalizeSource(installedSourceUrl);
        if (candidateOfficial &&
            (string.IsNullOrWhiteSpace(installed) || installed.Equals("OFFICIAL", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(installed))
            return false;
        return installed.Equals(NormalizeSource(candidateSourceUrl), StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeSource(string? value)
        => (value ?? string.Empty).Trim().TrimEnd('/');
}
