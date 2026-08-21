using System;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Stubs;

public sealed class StubFramework : InstrumentedStub, IFramework
{
    private event Action? _update;

    public StubFramework(AccessTracker tracker) : base(nameof(IFramework), tracker) { }

    public event Action? Update
    {
        add { Touch("add_Update", FindingSeverity.Low, new Dictionary<string, string?> { ["phase"] = "subscribe" }); _update += value; }
        remove { Touch("remove_Update", FindingSeverity.Low); _update -= value; }
    }

    public void RunOnce()
    {
        Touch("RunOnce", FindingSeverity.Low);
        _update?.Invoke();
    }

    public bool IsFrameworkRunning
    {
        get { Touch("get_IsFrameworkRunning"); return true; }
    }
}
