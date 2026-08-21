using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Stubs;

public sealed class StubChatGui : InstrumentedStub, IChatGui
{
    public StubChatGui(AccessTracker tracker) : base(nameof(IChatGui), tracker) { }

    public void Print(string message) =>
        Touch("Print", FindingSeverity.Low, new Dictionary<string, string?> { ["message"] = message });

    public void Print(XivChatType type, string message) =>
        Touch("Print", FindingSeverity.Low,
            new Dictionary<string, string?> { ["type"] = type.ToString(), ["message"] = message });

    public void Print(string channel, string message) =>
        Touch("Print", FindingSeverity.Low,
            new Dictionary<string, string?> { ["channel"] = channel, ["message"] = message });

    public void PrintError(string message) =>
        Touch("PrintError", FindingSeverity.Medium, new Dictionary<string, string?> { ["message"] = message });

    public void PrintChatLink(string linkText, object? linkData, string? message = null) =>
        Touch("PrintChatLink", FindingSeverity.Low,
            new Dictionary<string, string?>
            {
                ["linkText"] = linkText,
                ["linkData"] = linkData?.ToString(),
                ["message"] = message,
            });
}
