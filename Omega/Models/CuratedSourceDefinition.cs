namespace Dalagab.Omega;

internal sealed class CuratedSourceDefinition
{
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Url { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public bool IsOfficial { get; init; }
    public bool EnabledByDefault { get; init; } = true;
    public bool IntegrateWithDalamudByDefault { get; init; }
}
