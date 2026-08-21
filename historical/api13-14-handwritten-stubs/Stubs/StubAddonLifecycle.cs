using System;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Stubs;

public sealed class StubAddonLifecycle : InstrumentedStub, IAddonLifecycle
{
    public StubAddonLifecycle(AccessTracker tracker) : base(nameof(IAddonLifecycle), tracker) { }

    public void RegisterEvent(nint addon, string eventName, AddonUpdateDelegate handler)
    {
        Touch("RegisterEvent", FindingSeverity.Low,
            new Dictionary<string, string?> { ["addon"] = addon.ToString(), ["eventName"] = eventName });
    }

    public void UnregisterEvent(nint addon, string eventName) =>
        Touch("UnregisterEvent", FindingSeverity.Low,
            new Dictionary<string, string?> { ["addon"] = addon.ToString(), ["eventName"] = eventName });

    public void RegisterListener(AddonUpdateDelegate handler) =>
        Touch("RegisterListener", FindingSeverity.Low);

    public void UnregisterListener(AddonUpdateDelegate handler) =>
        Touch("UnregisterListener", FindingSeverity.Low);
}
