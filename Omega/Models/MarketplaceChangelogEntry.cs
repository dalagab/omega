namespace Dalagab.Omega;

/// <summary>
/// A bounded historical changelog entry retained from a plugin repository manifest.
/// Historical variants stay in the client Definitions database so Omega can explain updates
/// without querying repositories from the game process.
/// </summary>
public sealed record MarketplaceChangelogEntry(
    string InternalName,
    string SourceName,
    string SourceUrl,
    string VersionText,
    long LastUpdate,
    string Changelog,
    bool IsActive);
