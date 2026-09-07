namespace Dalagab.Omega;

/// <summary>
/// Bounded dependency summary projected from Omega's server-side evidence database.
/// Detailed dependency evidence remains server-side; this model contains only fields
/// needed to explain dependency relationships in the in-game Definitions UI.
/// </summary>
public sealed class MarketplaceDependency
{
    public string Name { get; init; } = string.Empty;
    public string Kind { get; init; } = string.Empty;
    public string Type { get; init; } = string.Empty;
    public string Requirement { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
    public string VersionRequirement { get; init; } = string.Empty;
    public string ResolvedVersion { get; init; } = string.Empty;
    public string ResolutionStatus { get; init; } = string.Empty;
    public string VersionStatus { get; init; } = string.Empty;
    public string TargetInternalName { get; init; } = string.Empty;
    public string TargetVersion { get; init; } = string.Empty;
    public string Relationship { get; init; } = string.Empty;
    public string RelationshipConfidence { get; init; } = string.Empty;
    public string RelationshipReason { get; init; } = string.Empty;
    public bool IsFramework { get; init; }
    public string WarningSeverity { get; init; } = string.Empty;
    public int WarningCount { get; init; }
    public int AdvisoryCount { get; init; }

    // Security/presentation classification only. IPC remains a separate integration observation
    // and is never promoted to package-manager authority by this model.
    public bool IsPluginDependency => !string.IsNullOrWhiteSpace(TargetInternalName) ||
                                      Type is "hard" or "soft" or "optional" or "plugin";
    public bool IsIpcIntegration => Type.Equals("ipc", StringComparison.OrdinalIgnoreCase) ||
                                    Kind.Equals("ipc", StringComparison.OrdinalIgnoreCase);
    public bool HasWarning => WarningCount > 0 || AdvisoryCount > 0 ||
                              !string.IsNullOrWhiteSpace(WarningSeverity);
}
