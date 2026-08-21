using System.Collections.Generic;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;

namespace InterdimensionalRift.Stubs;

public sealed class StubGameGui : InstrumentedStub, IGameGui
{
    public StubGameGui(AccessTracker tracker) : base(nameof(IGameGui), tracker) { }

    public bool IsValidXivUiElement(nint element)
    {
        Touch("IsValidXivUiElement", Reporting.FindingSeverity.Info,
            new Dictionary<string, string?> { ["element"] = element.ToString() });
        return false;
    }

    public nint GetAddonByName(string name, int index = 1)
    {
        Touch("GetAddonByName", Reporting.FindingSeverity.Info,
            new Dictionary<string, string?> { ["name"] = name, ["index"] = index.ToString() });
        return nint.Zero;
    }

    public IEnumerable<nint> GetAddonNodes(string name)
    {
        Touch("GetAddonNodes", Reporting.FindingSeverity.Info,
            new Dictionary<string, string?> { ["name"] = name });
        return System.Array.Empty<nint>();
    }

    public bool IsScreenReady()
    {
        Touch("IsScreenReady", Reporting.FindingSeverity.Info);
        return false;
    }
}
