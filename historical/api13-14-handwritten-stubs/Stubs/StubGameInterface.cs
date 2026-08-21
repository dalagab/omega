using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;

namespace InterdimensionalRift.Stubs;

public sealed class StubGameInterface : InstrumentedStub, IGameInterface
{
    public StubGameInterface(AccessTracker tracker) : base(nameof(IGameInterface), tracker) { }

    public nint GetUiObject(string name, int index = 1)
    {
        Touch("GetUiObject", Reporting.FindingSeverity.Info,
            new System.Collections.Generic.Dictionary<string, string?> { ["name"] = name, ["index"] = index.ToString() });
        return nint.Zero;
    }

    public nint FindAgentInterface(string name)
    {
        Touch("FindAgentInterface", Reporting.FindingSeverity.Info,
            new System.Collections.Generic.Dictionary<string, string?> { ["name"] = name });
        return nint.Zero;
    }

    public bool IsUiReady
    {
        get { Touch("get_IsUiReady", Reporting.FindingSeverity.Info); return false; }
    }

    public string? CurrentPlayerName
    {
        get { Touch("get_CurrentPlayerName", Reporting.FindingSeverity.Info); return null; }
    }
}
