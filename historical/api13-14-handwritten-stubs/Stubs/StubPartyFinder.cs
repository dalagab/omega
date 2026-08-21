using System.Collections.Generic;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;

namespace InterdimensionalRift.Stubs;

public sealed class StubPartyFinder : InstrumentedStub, IPartyFinder
{
    public StubPartyFinder(AccessTracker tracker) : base(nameof(IPartyFinder), tracker) { }

    public int LatestListingId
    {
        get { Touch("get_LatestListingId", Reporting.FindingSeverity.Info); return 0; }
    }

    public IReadOnlyList<int> GetActiveListingIds()
    {
        Touch("GetActiveListingIds", Reporting.FindingSeverity.Info);
        return System.Array.Empty<int>();
    }

    public string? GetListingDescription(int id)
    {
        Touch("GetListingDescription", Reporting.FindingSeverity.Info,
            new Dictionary<string, string?> { ["id"] = id.ToString() });
        return null;
    }

    public bool IsListingFull(int id)
    {
        Touch("IsListingFull", Reporting.FindingSeverity.Info,
            new Dictionary<string, string?> { ["id"] = id.ToString() });
        return false;
    }
}
