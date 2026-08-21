using System.Collections.Generic;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Stubs;

public sealed class StubDataManager : InstrumentedStub, IDataManager
{
    public StubDataManager(AccessTracker tracker) : base(nameof(IDataManager), tracker) { }

    public bool HasGameData
    {
        get { Touch("get_HasGameData", FindingSeverity.Low); return false; }
    }

    public nint GetExcelSheet<T>() where T : class
    {
        Touch("GetExcelSheet", FindingSeverity.Low,
            new Dictionary<string, string?> { ["type"] = typeof(T).FullName });
        return nint.Zero;
    }

    public IReadOnlyList<uint> GetTerritoryTypeIds()
    {
        Touch("GetTerritoryTypeIds", FindingSeverity.Low);
        return System.Array.Empty<uint>();
    }

    public string? GetExcelSheetName<T>() where T : class
    {
        Touch("GetExcelSheetName", FindingSeverity.Low,
            new Dictionary<string, string?> { ["type"] = typeof(T).FullName });
        return null;
    }
}
