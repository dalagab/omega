namespace Dalagab.Omega;

/// <summary>
/// A bounded, classified project action derived from public project metadata.
/// Unknown/raw scraped URLs remain server-side context and are not promoted to the client UI.
/// </summary>
public sealed record MarketplaceProjectLink(string Kind, string Label, string Url);
