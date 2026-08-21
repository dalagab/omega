using Dalamud.Plugin.Services;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Stubs;

public sealed class StubPluginLog : InstrumentedStub, IPluginLog
{
    public StubPluginLog(AccessTracker tracker) : base(nameof(IPluginLog), tracker) { }

    public void Verbose(string message) => Tracker.Log(nameof(Verbose), message);
    public void Debug(string message) => Tracker.Log(nameof(Debug), message);
    public void Info(string message) => Tracker.Log(nameof(Info), message);
    public void Warning(string message) => Tracker.Log(nameof(Warning), message);

    public void Error(string message) => Tracker.Log(nameof(Error), message);

    public void Error(string message, System.Exception exception) =>
        Tracker.Log(nameof(Error), $"{message} :: {exception.GetType().Name}: {exception.Message}");

    public void Verbose(System.Exception exception, string message) => Verbose(message);
    public void Debug(System.Exception exception, string message) => Debug(message);
    public void Info(System.Exception exception, string message) => Info(message);
    public void Warning(System.Exception exception, string message) => Warning(message);
}
