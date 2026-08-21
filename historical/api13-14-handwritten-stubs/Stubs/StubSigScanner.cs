using System;
using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Stubs;

public sealed class StubSigScanner : InstrumentedStub, ISigScanner
{
    public StubSigScanner(AccessTracker tracker) : base(nameof(ISigScanner), tracker) { }

    public nint ScanText(string text)
    {
        Touch("ScanText", FindingSeverity.Low, new Dictionary<string, string?> { ["text"] = text });
        return nint.Zero;
    }

    public nint ScanModule(string pattern)
    {
        Touch("ScanModule", FindingSeverity.Low, new Dictionary<string, string?> { ["pattern"] = pattern });
        return nint.Zero;
    }

    public nint GetStaticAddressFromSig(string pattern)
    {
        Touch("GetStaticAddressFromSig", FindingSeverity.Low,
            new Dictionary<string, string?> { ["pattern"] = pattern });
        return nint.Zero;
    }

    public IntPtr TextSection
    {
        get { Touch("get_TextSection", FindingSeverity.Low); return IntPtr.Zero; }
    }

    public IntPtr DataSection
    {
        get { Touch("get_DataSection", FindingSeverity.Low); return IntPtr.Zero; }
    }

    public int TextSectionLength
    {
        get { Touch("get_TextSectionLength", FindingSeverity.Low); return 0; }
    }

    public int DataSectionLength
    {
        get { Touch("get_DataSectionLength", FindingSeverity.Low); return 0; }
    }
}
