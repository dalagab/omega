namespace Dalagab.Omega;

internal enum PluginDependencyRelationship
{
    Required,
    Recommended,
    Optional,
    Observed,
}

/// <summary>
/// Normalized package-manager dependency edge published by the Omega catalog.
/// This is distinct from MarketplaceDependency, which remains presentation-only
/// security/observation evidence and may include IPC or non-plugin components.
/// </summary>
internal sealed record PluginDependencyEdge(
    long ConsumerVariantId,
    long ConsumerPluginId,
    string ConsumerInternalName,
    string ConsumerVersion,
    long ProviderPluginId,
    string ProviderInternalName,
    PluginDependencyRelationship Relationship,
    string VersionConstraint,
    string ResolvedVersion,
    string ResolutionStatus,
    string VersionStatus,
    string Confidence,
    string SourceKind,
    IReadOnlyList<string> Origins,
    bool InstallEligible)
{
    public bool IsRequiredInstallDependency =>
        Relationship == PluginDependencyRelationship.Required && InstallEligible;
}

/// <summary>
/// Aggregate reverse-dependency summary for a stable plugin identity.
/// </summary>
internal sealed record PluginDependencyProvider(
    long ProviderPluginId,
    string ProviderInternalName,
    int RequiredByCount,
    int RecommendedByCount,
    int OptionalByCount,
    int TotalDependentPlugins);
