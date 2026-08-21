using Dalamud.Plugin;
using IServiceProvider = Dalamud.Plugin.IServiceProvider;

namespace InterdimensionalRift.Stubs;

public sealed class StubPluginInterface : IDalamudPluginInterface
{
    public StubPluginInterface(IServiceProvider services, string internalName, System.IO.DirectoryInfo location)
    {
        Services = services;
        InternalName = internalName;
        AssemblyLocation = location;
    }

    public IServiceProvider Services { get; }
    public string InternalName { get; }
    public System.IO.DirectoryInfo AssemblyLocation { get; }
}
