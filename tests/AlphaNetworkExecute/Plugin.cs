using Dalamud.Plugin;

namespace AlphaNetworkExecute;

/// <summary>Static-only Alpha subject. It does not start processes and does not make network requests.</summary>
public sealed class Plugin : IDalamudPlugin
{
    private static readonly string[] ReviewedMarkers =
    [
        "System.Net.Http.HttpClient",
        "DownloadString",
        "System.Diagnostics.Process",
        "Process.Start",
        "ProcessStartInfo"
    ];

    public Plugin() => GC.KeepAlive(ReviewedMarkers);
    public void Dispose() { }
}
