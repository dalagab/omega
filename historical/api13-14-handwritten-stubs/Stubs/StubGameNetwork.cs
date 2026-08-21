using System;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Stubs;

#pragma warning disable CS0067
public sealed class StubGameNetwork : InstrumentedStub, IGameNetwork
{
    private event Action<nint>? _message;

    public StubGameNetwork(AccessTracker tracker) : base(nameof(IGameNetwork), tracker) { }

    public event Action<nint>? NetworkMessage
    {
        add
        {
            Touch("add_NetworkMessage", FindingSeverity.Low);
            _message += value;
        }
        remove
        {
            Touch("remove_NetworkMessage", FindingSeverity.Low);
            _message -= value;
        }
    }

    public void InjectMessage(nint messagePtr) =>
        Touch("InjectMessage", FindingSeverity.Low,
            new Dictionary<string, string?> { ["ptr"] = messagePtr.ToString() });

    public bool IsConnected
    {
        get { Touch("get_IsConnected", FindingSeverity.Low); return false; }
    }
}
#pragma warning restore CS0067
