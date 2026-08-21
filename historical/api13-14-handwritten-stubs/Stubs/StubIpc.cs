using System;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Stubs;

public sealed class StubAddonIpcManager : InstrumentedStub, IAddonIpcManager
{
    public StubAddonIpcManager(AccessTracker tracker) : base(nameof(IAddonIpcManager), tracker) { }

    public nint GetAddon(string name)
    {
        Touch("GetAddon", FindingSeverity.Info, new Dictionary<string, string?> { ["name"] = name });
        return nint.Zero;
    }

    public void PostMessage(nint addon, string messageName) =>
        Touch("PostMessage", FindingSeverity.Info,
            new Dictionary<string, string?> { ["addon"] = addon.ToString(), ["messageName"] = messageName });

    public void Subscribe(string channel, Action<string> handler) =>
        Touch("Subscribe", FindingSeverity.Info, new Dictionary<string, string?> { ["channel"] = channel });
}

public sealed class StubIpcManager : InstrumentedStub, IIpcManager
{
    public StubIpcManager(AccessTracker tracker) : base(nameof(IIpcManager), tracker) { }

    public Guid RegisterAction(string actionName, Action<nint> action) =>
        EmitReturn("RegisterAction(action)", actionName);

    public Guid RegisterAction<T1>(string actionName, Action<T1> action) =>
        EmitReturn("RegisterAction<T1>", actionName);

    public Guid RegisterAction<T1, T2>(string actionName, Action<T1, T2> action) =>
        EmitReturn("RegisterAction<T1,T2>", actionName);

    public Guid RegisterFunc<TRet>(string funcName, Func<TRet> func) =>
        EmitReturn("RegisterFunc<TRet>", funcName);

    public void UnregisterAction(Guid handle) =>
        Touch("UnregisterAction", FindingSeverity.Low, new Dictionary<string, string?> { ["handle"] = handle.ToString() });

    public void UnregisterFunc(Guid handle) =>
        Touch("UnregisterFunc", FindingSeverity.Low, new Dictionary<string, string?> { ["handle"] = handle.ToString() });

    public nint CallAction(string actionName, nint payload)
    {
        Touch("CallAction", FindingSeverity.Low,
            new Dictionary<string, string?> { ["actionName"] = actionName, ["payload"] = payload.ToString() });
        return nint.Zero;
    }

    private Guid EmitReturn(string method, string name)
    {
        Touch(method, FindingSeverity.Low, new Dictionary<string, string?> { ["name"] = name });
        return Guid.Empty;
    }
}
