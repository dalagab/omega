namespace Dalagab.Omega;

internal sealed record RepositoryCatalogStatus(
    string SourceName,
    string SourceUrl,
    int PluginCount,
    int HighestKnownApiLevel,
    bool IsStale);
