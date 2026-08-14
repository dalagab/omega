namespace Dalagab.Omega;

public sealed class MarketplaceSecurityFinding
{
    public string RuleId { get; init; } = string.Empty;
    public string Severity { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public IReadOnlyList<string> Evidence { get; init; } = [];
}
