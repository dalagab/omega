using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;

namespace InterdimensionalRift.Stubs;

public sealed class StubCondition : InstrumentedStub, ICondition
{
    public StubCondition(AccessTracker tracker) : base(nameof(ICondition), tracker) { }

    public bool this[ConditionFlag flag]
    {
        get
        {
            Touch("this[]", Reporting.FindingSeverity.Info,
                new Dictionary<string, string?> { ["flag"] = flag.ToString() });
            return false;
        }
    }

    public ConditionFlag CurrentConditionFlags
    {
        get { Touch("get_CurrentConditionFlags", Reporting.FindingSeverity.Info); return ConditionFlag.None; }
    }
}
