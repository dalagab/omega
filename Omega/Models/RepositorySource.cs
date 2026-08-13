namespace Dalagab.Omega;

[Serializable]
public sealed class RepositorySource
{
    public string Name { get; set; } = "Repository";
    public string Url { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public bool IsOfficial { get; set; }
    public bool IsExperimental { get; set; } = true;

    // Curated entries are shipped by Omega and merged into configuration on startup.
    // Their identity/name/url are maintained by the bundled curated source catalog.
    public bool IsCurated { get; set; }
    public string CuratedId { get; set; } = string.Empty;
    public string CuratedDescription { get; set; } = string.Empty;

    // Desired state in Omega. This does not mean Omega owns an already-existing Dalamud entry.
    public bool IntegrateWithDalamud { get; set; }

    // True only when Omega itself created the matching Dalamud ThirdRepoList entry.
    // Omega may modify/remove only entries with this flag.
    public bool DalamudManagedByOmega { get; set; }

    public override string ToString() => string.IsNullOrWhiteSpace(Name) ? Url : Name;
}
