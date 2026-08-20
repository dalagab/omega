namespace Dalagab.Omega;

[Serializable]
public sealed class PersistedUpdateFailure
{
    public string Message { get; set; } = string.Empty;
    public string PreviousSourceUrl { get; set; } = string.Empty;
    public string NewSourceUrl { get; set; } = string.Empty;
    public string FailureKind { get; set; } = string.Empty;
    public string FailureCode { get; set; } = string.Empty;
    public string FailureDetail { get; set; } = string.Empty;
    public string InstalledVersion { get; set; } = string.Empty;
    public string TargetVersion { get; set; } = string.Empty;
    public DateTimeOffset RecordedAtUtc { get; set; }
}
