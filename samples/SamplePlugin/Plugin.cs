using System.Net.Http;
using System.Reflection;
using System.Runtime.Loader;
using Dalamud.IoC;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;

namespace SamplePlugin;

/// <summary>
/// API-15 synchronous positive fixture. Synchronous Dalamud plugins initialize
/// in their constructor after Dalamud has populated [PluginService] members.
/// </summary>
public sealed class Plugin : IDalamudPlugin
{
    [PluginService] private static IPluginLog Log { get; set; } = null!;
    [PluginService] private static IClientState ClientState { get; set; } = null!;
    [PluginService] private static IFramework Framework { get; set; } = null!;
    [PluginService] private static IDalamudPluginInterface PluginInterface { get; set; } = null!;

    public Plugin()
    {
        Log.Info("Starting up");
        Log.Warning("Fixture endpoint https://evil.example.com");

        _ = ClientState.IsLoggedIn;
        Framework.Update += OnFrameworkUpdate;

        try
        {
            var alc = AssemblyLoadContext.GetLoadContext(typeof(Plugin).Assembly)!;
            _ = alc.LoadFromAssemblyName(new AssemblyName("SomeOther"));
        }
        catch { }

        // Keep durable metadata references for the transitional static layer.
        _ = typeof(HttpClient);
        _ = typeof(System.Net.Sockets.UdpClient);

        // Exercise an API-15 plugin-interface call that returns an instrumented
        // interface proxy without requiring a live Dalamud IPC broker.
        _ = PluginInterface.GetIpcProvider<object?>("sample.provider");
    }

    private static void OnFrameworkUpdate(IFramework framework)
    {
        Log.Debug("framework tick");
    }

    public void Dispose()
    {
        Framework.Update -= OnFrameworkUpdate;
        Log.Info("Shutting down");
    }
}
