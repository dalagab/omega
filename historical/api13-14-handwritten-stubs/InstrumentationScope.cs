using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Stubs;

namespace InterdimensionalRift.Host;

/// <summary>
/// Bundle of state the sandbox hands to a single plugin run: an
/// <see cref="AccessTracker"/> and a fully-wired <see cref="StubServiceContainer"/>.
/// The same <see cref="AccessTracker"/> is used end-to-end so the static
/// <see cref="HttpReferenceScanner"/> and the dynamic
/// <see cref="ReflectionHook"/> produce comparable timestamps.
/// </summary>
public sealed class InstrumentationScope
{
    public InstrumentationScope(AccessTracker tracker, StubServiceContainer services, StubPluginInterface pluginInterface)
    {
        Tracker = tracker;
        Services = services;
        PluginInterface = pluginInterface;
    }

    public AccessTracker Tracker { get; }
    public StubServiceContainer Services { get; }
    public StubPluginInterface PluginInterface { get; }
}
