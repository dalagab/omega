using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;

namespace InterdimensionalRift.Stubs;

public sealed class StubTextureSubstitution : InstrumentedStub, ITextureSubstitution
{
    public StubTextureSubstitution(AccessTracker tracker) : base(nameof(ITextureSubstitution), tracker) { }

    public bool Substituted
    {
        get { Touch("get_Substituted", Reporting.FindingSeverity.Info); return false; }
    }

    public void Enable() => Touch("Enable", Reporting.FindingSeverity.Low);
    public void Disable() => Touch("Disable", Reporting.FindingSeverity.Low);

    public void RedirectPath(string originalPath, string newPath) =>
        Touch("RedirectPath", Reporting.FindingSeverity.Low,
            new Dictionary<string, string?> { ["originalPath"] = originalPath, ["newPath"] = newPath });
}
