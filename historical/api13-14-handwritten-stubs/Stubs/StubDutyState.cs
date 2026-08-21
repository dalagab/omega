using System;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Stubs;

#pragma warning disable CS0067 // events are raised by the real Dalamud, not the sandbox
public sealed class StubDutyState : InstrumentedStub, IDutyState
{
    private event Action? _started;
    private event Action? _wiped;
    private event Action? _recommenced;
    private event Action? _finished;

    public StubDutyState(AccessTracker tracker) : base(nameof(IDutyState), tracker) { }

    public bool IsDutyStarted
    {
        get { Touch("get_IsDutyStarted", FindingSeverity.Info); return false; }
    }

    public bool IsDutyFinished
    {
        get { Touch("get_IsDutyFinished", FindingSeverity.Info); return false; }
    }

    public ushort TerritoryId
    {
        get { Touch("get_TerritoryId", FindingSeverity.Info); return 0; }
    }

    public int ContentFinderConditionId
    {
        get { Touch("get_ContentFinderConditionId", FindingSeverity.Info); return 0; }
    }

    public event Action? DutyStarted
    {
        add { Touch("add_DutyStarted", FindingSeverity.Info); _started += value; }
        remove { Touch("remove_DutyStarted", FindingSeverity.Info); _started -= value; }
    }

    public event Action? DutyWiped
    {
        add { Touch("add_DutyWiped", FindingSeverity.Info); _wiped += value; }
        remove { Touch("remove_DutyWiped", FindingSeverity.Info); _wiped -= value; }
    }

    public event Action? DutyRecommenced
    {
        add { Touch("add_DutyRecommenced", FindingSeverity.Info); _recommenced += value; }
        remove { Touch("remove_DutyRecommenced", FindingSeverity.Info); _recommenced -= value; }
    }

    public event Action? DutyFinished
    {
        add { Touch("add_DutyFinished", FindingSeverity.Info); _finished += value; }
        remove { Touch("remove_DutyFinished", FindingSeverity.Info); _finished -= value; }
    }
}
#pragma warning restore CS0067
