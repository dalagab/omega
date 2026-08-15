namespace Dalagab.Omega;

public sealed class MarketplaceAutomationCapability
{
    public string CapabilityId { get; init; } = string.Empty;
    public string Label { get; init; } = string.Empty;
    public string AutomationLevel { get; init; } = "none";
    public string Confidence { get; init; } = string.Empty;
    public bool Reachable { get; init; }
    public bool Indirect { get; init; }
    public string Reason { get; init; } = string.Empty;
    public IReadOnlyList<string> Evidence { get; init; } = [];
}
