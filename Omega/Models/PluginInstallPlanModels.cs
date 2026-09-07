namespace Dalagab.Omega;

internal enum PluginInstallAction
{
    Keep,
    Install,
    Update,
    MigrateSource,
}

internal enum PluginInstallReason
{
    Requested,
    RequiredDependency,
    ExplicitRecommendedDependency,
    ExplicitOptionalDependency,
    DependencyVersionConstraint,
}

internal enum PluginInstallConflictKind
{
    RootUnavailable,
    MissingProvider,
    InvalidVersionConstraint,
    UnsatisfiableVersionConstraint,
    IncompatibleProvider,
    DowngradeRequired,
    DeveloperPluginBlocked,
    RequiredDependencyCycle,
}

internal enum PluginInstallWarningKind
{
    SuggestedDependency,
    NonInstallableRelationship,
    SourceReviewRequired,
}

internal sealed record PluginInstalledState(
    string InternalName,
    Version Version,
    string SourceUrl,
    bool IsDev = false);

internal sealed record PluginInstallRequest(
    long PluginId,
    long SelectedVariantId,
    string InternalName,
    MarketplacePlugin SelectedVariant,
    PluginInstallReason Reason);

internal sealed record PluginInstallOperation(
    long PluginId,
    string InternalName,
    MarketplacePlugin SelectedVariant,
    long SelectedVariantId,
    PluginInstallAction Action,
    PluginInstallReason Reason,
    IReadOnlyList<string> RequiredBy,
    string EffectiveVersionConstraint,
    Version? InstalledVersion,
    Version TargetVersion,
    int ExecutionOrder)
{
    public bool Mutates => Action is PluginInstallAction.Install or PluginInstallAction.Update or PluginInstallAction.MigrateSource;
}

internal sealed record PluginInstallConflict(
    PluginInstallConflictKind Kind,
    long PluginId,
    string InternalName,
    string Message,
    IReadOnlyList<string> Consumers,
    IReadOnlyList<string> Constraints);

internal sealed record PluginInstallWarning(
    PluginInstallWarningKind Kind,
    string Message,
    string InternalName = "");

internal sealed record PluginInstallSuggestion(
    long ProviderPluginId,
    string ProviderInternalName,
    PluginDependencyRelationship Relationship,
    string VersionConstraint,
    IReadOnlyList<string> SuggestedBy,
    bool InstallEligible,
    bool Selected);

internal sealed record PluginInstallPlan(
    string PlanId,
    string CatalogRevision,
    string DependencyGraphRevision,
    IReadOnlyList<PluginInstallRequest> RootRequests,
    IReadOnlyList<PluginInstallOperation> Operations,
    IReadOnlyList<PluginInstallConflict> Conflicts,
    IReadOnlyList<PluginInstallWarning> Warnings,
    IReadOnlyList<PluginInstallSuggestion> Suggestions,
    bool IsValid,
    bool IsStale)
{
    public int ChangeCount => Operations.Count(x => x.Mutates);
    public int InstallCount => Operations.Count(x => x.Action == PluginInstallAction.Install);
    public int UpdateCount => Operations.Count(x => x.Action == PluginInstallAction.Update);
    public int MigrateCount => Operations.Count(x => x.Action == PluginInstallAction.MigrateSource);
    public int KeepCount => Operations.Count(x => x.Action == PluginInstallAction.Keep);
    public bool HasDependencyClosure => Operations.Any(x => x.Reason != PluginInstallReason.Requested);

    public bool MatchesRevisions(string catalogRevision, string dependencyGraphRevision)
        => string.Equals(CatalogRevision, catalogRevision ?? string.Empty, StringComparison.Ordinal) &&
           string.Equals(DependencyGraphRevision, dependencyGraphRevision ?? string.Empty, StringComparison.Ordinal);

    public PluginInstallPlan MarkStaleIfRevisionsChanged(string catalogRevision, string dependencyGraphRevision)
        => MatchesRevisions(catalogRevision, dependencyGraphRevision)
            ? this with { IsStale = false, IsValid = Conflicts.Count == 0 }
            : this with { IsStale = true, IsValid = false };
}

internal sealed class PluginDependencyResolutionContext
{
    public required MarketplacePlugin RootVariant { get; init; }
    public long RootCatalogPluginId { get; init; }
    public long RootCatalogVariantId { get; init; }
    public required int CurrentApiLevel { get; init; }
    public required Version CurrentDalamudVersion { get; init; }
    public required bool PreferTestingBuilds { get; init; }
    public required string CatalogRevision { get; init; }
    public required string DependencyGraphRevision { get; init; }
    public required IReadOnlyDictionary<string, PluginInstalledState> InstalledPlugins { get; init; }
    public IReadOnlyDictionary<string, string> PreferredSourceUrls { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    public IReadOnlySet<string> ExplicitDependencyInternalNames { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    public required Func<string, IReadOnlyList<MarketplacePlugin>> GetVariants { get; init; }
    public required Func<long, IReadOnlyList<PluginDependencyEdge>> GetDependenciesForVariant { get; init; }
    public required Func<long, IReadOnlyList<PluginDependencyEdge>> GetDependenciesForPlugin { get; init; }
}
