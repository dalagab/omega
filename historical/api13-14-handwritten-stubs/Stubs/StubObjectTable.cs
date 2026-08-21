using System.Collections.Generic;
using System.Linq;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;

namespace InterdimensionalRift.Stubs;

public sealed class StubObjectTable : InstrumentedStub, IObjectTable
{
    public StubObjectTable(AccessTracker tracker) : base(nameof(IObjectTable), tracker) { }

    public int Length
    {
        get { Touch("get_Length"); return 0; }
    }

    public nint this[int index]
    {
        get { Touch("this[]", Reporting.FindingSeverity.Info, new Dictionary<string, string?> { ["index"] = index.ToString() }); return nint.Zero; }
    }

    public IEnumerable<nint> LocalPlayers
    {
        get { Touch("get_LocalPlayers"); return Enumerable.Empty<nint>(); }
    }

    public IEnumerable<nint> PartyMembers
    {
        get { Touch("get_PartyMembers"); return Enumerable.Empty<nint>(); }
    }

    public IEnumerable<nint> BattleNpcs
    {
        get { Touch("get_BattleNpcs"); return Enumerable.Empty<nint>(); }
    }

    public IEnumerable<nint> EventNpcs
    {
        get { Touch("get_EventNpcs"); return Enumerable.Empty<nint>(); }
    }

    public IEnumerable<nint> FriendlyNpcs
    {
        get { Touch("get_FriendlyNpcs"); return Enumerable.Empty<nint>(); }
    }
}
