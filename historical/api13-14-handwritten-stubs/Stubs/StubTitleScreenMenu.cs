using System;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Stubs;

public sealed class StubTitleScreenMenu : InstrumentedStub, ITitleScreenMenu
{
    public StubTitleScreenMenu(AccessTracker tracker) : base(nameof(ITitleScreenMenu), tracker) { }

    public nint AddEntry(string text, Action onClicked)
    {
        Touch("AddEntry", FindingSeverity.Low, new Dictionary<string, string?> { ["text"] = text });
        return nint.Zero;
    }

    public void RemoveEntry(nint handle) =>
        Touch("RemoveEntry", FindingSeverity.Low, new Dictionary<string, string?> { ["handle"] = handle.ToString() });
}
