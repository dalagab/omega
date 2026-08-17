namespace Dalagab.Omega;

/// <summary>
/// Canonical product identity for Omega's evidence-gathering analysis engine.
/// The persisted evidence schema keeps its historical scanner-version field names for
/// backward compatibility, but user-facing and operational code calls the engine Sigmascope.
/// </summary>
internal static class SigmascopeInfo
{
    public const string Name = "Sigmascope";
    public const string Tagline = "Examine closely. Keep the evidence.";
    public const string Description = "Omega's static evidence-gathering analysis engine.";
    public const string Lore = "A small twist on Sigmascape: Omega's data-driven test world for studying unexpected results and gathering evidence. A scope examines closely; Sigmascope reports evidence, not a final judgement.";
}
