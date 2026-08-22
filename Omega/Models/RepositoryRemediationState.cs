namespace Dalagab.Omega;

[Serializable]
public sealed class RepositoryRemediationState
{
    public string SourceUrl { get; set; } = string.Empty;
    public DateTimeOffset DisabledAtUtc { get; set; }
    public bool OmegaManaged { get; set; }
}
