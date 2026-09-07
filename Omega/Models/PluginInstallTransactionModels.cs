namespace Dalagab.Omega;

internal enum PluginInstallTransactionOutcome
{
    Succeeded,
    StalePlan,
    InvalidPlan,
    SourcePreparationFailed,
    OperationFailed,
    Cancelled,
}

internal sealed record PluginInstallTransactionStepResult(
    string InternalName,
    PluginInstallAction Action,
    bool Success,
    string Message,
    bool RolledBack = false);

internal sealed record PluginInstallTransactionResult(
    PluginInstallTransactionOutcome Outcome,
    string Message,
    IReadOnlyList<PluginInstallTransactionStepResult> Steps,
    IReadOnlyList<string> RollbackMessages,
    IReadOnlyList<string> OrphanedDependencies)
{
    public bool Success => Outcome == PluginInstallTransactionOutcome.Succeeded;
}

internal sealed record PluginDependencyAutoremoveResult(
    int Requested,
    int Removed,
    IReadOnlyList<string> Skipped,
    IReadOnlyList<string> Messages)
{
    public bool Success => Removed == Requested && Skipped.Count == 0;
}
