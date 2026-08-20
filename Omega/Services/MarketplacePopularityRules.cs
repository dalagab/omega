namespace Dalagab.Omega;

internal sealed record MarketplacePopularitySnapshot(
    int PluginCount,
    long TotalDownloads,
    double AverageDownloads,
    double HighestMultiple)
{
    public bool HasData => PluginCount > 0 && TotalDownloads > 0 && AverageDownloads > 0d && HighestMultiple > 0d;

    public double MultipleFor(long downloadCount)
        => AverageDownloads > 0d ? Math.Max(0L, downloadCount) / AverageDownloads : 0d;

    public double RelativePercentFor(long downloadCount)
    {
        if (!HasData)
            return 0d;
        return Math.Clamp(MultipleFor(downloadCount) / HighestMultiple * 100d, 0d, 100d);
    }
}

/// <summary>
/// Normalizes manifest-reported download/install counts against the current logical catalog.
/// The 1.0x point is the catalog-wide mean: total reported downloads divided by logical plugins.
/// This is a relative popularity/reach signal, not a unique-user or active-install estimate.
/// </summary>
internal static class MarketplacePopularityRules
{
    public static MarketplacePopularitySnapshot Build(IEnumerable<MarketplacePlugin> logicalPlugins)
    {
        var plugins = logicalPlugins
            .Where(plugin => !plugin.IsHide && !string.IsNullOrWhiteSpace(plugin.InternalName))
            .GroupBy(plugin => plugin.InternalName, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToArray();
        var totalDownloads = plugins.Sum(plugin => Math.Max(0L, plugin.DownloadCount));
        var average = plugins.Length > 0 ? totalDownloads / (double)plugins.Length : 0d;
        var highestDownloads = plugins.Length > 0 ? plugins.Max(plugin => Math.Max(0L, plugin.DownloadCount)) : 0L;
        var highestMultiple = average > 0d ? highestDownloads / average : 0d;
        return new MarketplacePopularitySnapshot(plugins.Length, totalDownloads, average, highestMultiple);
    }

    public static string FormatMultiple(double multiple)
    {
        multiple = Math.Max(0d, multiple);
        if (multiple >= 100d)
            return multiple.ToString("0", System.Globalization.CultureInfo.InvariantCulture) + "×";
        if (multiple >= 10d)
            return multiple.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + "×";
        return multiple.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture) + "×";
    }

    public static string FormatAverage(double average)
    {
        average = Math.Max(0d, average);
        return average >= 100d
            ? average.ToString("N0", System.Globalization.CultureInfo.InvariantCulture)
            : average.ToString("N1", System.Globalization.CultureInfo.InvariantCulture);
    }

    public static string Describe(long downloadCount, MarketplacePopularitySnapshot snapshot)
    {
        if (!snapshot.HasData)
            return "The current catalog does not contain enough reported download data to calculate relative popularity.";

        var downloads = Math.Max(0L, downloadCount);
        var multiple = snapshot.MultipleFor(downloads);
        var percent = snapshot.RelativePercentFor(downloads);
        return $"{downloads.ToString("N0", System.Globalization.CultureInfo.InvariantCulture)} reported downloads / installations. " +
               $"This plugin is {FormatMultiple(multiple)} the catalog average. " +
               $"The current popularity leader is {FormatMultiple(snapshot.HighestMultiple)} the catalog average and defines 100%. " +
               $"This plugin is {FormatPercent(percent)} of that leader.";
    }

    public static string FormatPercent(double percent)
    {
        percent = Math.Clamp(percent, 0d, 100d);
        return percent >= 10d
            ? percent.ToString("0", System.Globalization.CultureInfo.InvariantCulture) + "%"
            : percent.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + "%";
    }
}