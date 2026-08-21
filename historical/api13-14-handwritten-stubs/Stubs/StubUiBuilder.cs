using System;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;

namespace InterdimensionalRift.Stubs;

/// <summary>
/// No-op IUiBuilder stub. The sandbox has no ImGui context. We still
/// record subscription events so the report shows the plugin would
/// have drawn, but everything else is intentionally silent.
/// </summary>
public sealed class StubUiBuilder : InstrumentedStub, IUiBuilder
{
    public StubUiBuilder(AccessTracker tracker) : base(nameof(IUiBuilder), tracker) { }

    public event Action? Draw
    {
        add { Touch("add_Draw", Reporting.FindingSeverity.Low); }
        remove { Touch("remove_Draw", Reporting.FindingSeverity.Low); }
    }

    public event Action? OpenConfigUi
    {
        add { Touch("add_OpenConfigUi", Reporting.FindingSeverity.Low); }
        remove { Touch("remove_OpenConfigUi", Reporting.FindingSeverity.Low); }
    }

    public event Action? OpenMainUi
    {
        add { Touch("add_OpenMainUi", Reporting.FindingSeverity.Low); }
        remove { Touch("remove_OpenMainUi", Reporting.FindingSeverity.Low); }
    }

    public void Cut() => Touch("Cut", Reporting.FindingSeverity.Info);

    public bool IsReady
    {
        get { Touch("get_IsReady", Reporting.FindingSeverity.Info); return false; }
    }

    public IntPtr Handle
    {
        get { Touch("get_Handle", Reporting.FindingSeverity.Info); return IntPtr.Zero; }
    }
}
