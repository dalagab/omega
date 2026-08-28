using Dalamud.Plugin;

namespace AlphaCredentialNetwork;

/// <summary>Static-only Alpha subject. Suspicious tokens are inert string data.</summary>
public sealed class Plugin : IDalamudPlugin
{
    private static readonly string[] ReviewedMarkers =
    [
        "ProtectedData.Unprotect",
        "CryptUnprotectData",
        "CredentialManager",
        "System.Net.Http.HttpClient",
        "WebRequest"
    ];

    public Plugin() => GC.KeepAlive(ReviewedMarkers);
    public void Dispose() { }
}
