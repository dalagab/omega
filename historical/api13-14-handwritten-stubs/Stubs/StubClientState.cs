using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;

namespace InterdimensionalRift.Stubs;

public sealed class StubClientState : InstrumentedStub, IClientState
{
    public StubClientState(AccessTracker tracker) : base(nameof(IClientState), tracker) { }

    public nint LocalPlayer
    {
        get { Touch("get_LocalPlayer"); return nint.Zero; }
    }

    public ulong LocalContentId
    {
        get { Touch("get_LocalContentId"); return 0; }
    }

    public ulong LocalPlayerEntityId
    {
        get { Touch("get_LocalPlayerEntityId"); return 0; }
    }

    public bool IsLoggedIn
    {
        get { Touch("get_IsLoggedIn"); return false; }
    }

    public string? PlayerName
    {
        get { Touch("get_PlayerName"); return null; }
    }

    public uint HomeWorldId
    {
        get { Touch("get_HomeWorldId"); return 0; }
    }

    public uint CurrentWorldId
    {
        get { Touch("get_CurrentWorldId"); return 0; }
    }

    public int TerritoryType
    {
        get { Touch("get_TerritoryType"); return 0; }
    }
}
