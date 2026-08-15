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
    public bool IsFramework { get; init; }
    public string WarningSeverity { get; init; } = string.Empty;
    public int WarningCount { get; init; }
    public int AdvisoryCount { get; init; }

    public bool IsPluginDependency => !string.IsNullOrWhiteSpace(TargetInternalName) ||
                                      Type is "hard" or "soft" or "optional" or "plugin" or "ipc";
    public bool HasWarning => WarningCount > 0 || AdvisoryCount > 0 ||
                              !string.IsNullOrWhiteSpace(WarningSeverity);
}
