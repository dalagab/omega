using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;

namespace InterdimensionalRift.Stubs;

public sealed class StubTextureProvider : InstrumentedStub, ITextureProvider
{
    public StubTextureProvider(AccessTracker tracker) : base(nameof(ITextureProvider), tracker) { }

    public nint GetTexture(string path)
    {
        Touch("GetTexture", Reporting.FindingSeverity.Info, new Dictionary<string, string?> { ["path"] = path });
        return nint.Zero;
    }

    public nint GetIcon(int iconId)
    {
        Touch("GetIcon", Reporting.FindingSeverity.Info, new Dictionary<string, string?> { ["iconId"] = iconId.ToString() });
        return nint.Zero;
    }

    public bool TryGetIcon(int iconId, out nint texture)
    {
        Touch("TryGetIcon", Reporting.FindingSeverity.Info, new Dictionary<string, string?> { ["iconId"] = iconId.ToString() });
        texture = nint.Zero;
        return false;
    }

    public void Invalidate(string path) => Touch("Invalidate", Reporting.FindingSeverity.Info,
        new Dictionary<string, string?> { ["path"] = path });
}
