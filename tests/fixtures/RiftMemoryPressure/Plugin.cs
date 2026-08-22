using Dalamud.IoC;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;

namespace RiftMemoryPressure;

public sealed class Plugin : IDalamudPlugin
{
    [PluginService] internal static IPluginLog Log { get; private set; } = null!;

    public Plugin()
    {
        if (!InsideRift())
        {
            Log.Information("RIFT_STRESS memory inert outside Rift");
            return;
        }

        Log.Warning("RIFT_STRESS memory begin");
        var blocks = new List<byte[]>();
        try
        {
            while (true)
            {
                var block = new byte[4 * 1024 * 1024];
                for (var i = 0; i < block.Length; i += 4096)
                    block[i] = 0xA5;
                blocks.Add(block);
            }
        }
        catch (OutOfMemoryException)
        {
            Log.Warning($"stress.memory_pressure bounded:OutOfMemoryException blocks={blocks.Count}");
        }
        finally
        {
            GC.KeepAlive(blocks);
        }
    }

    public void Dispose() => Log.Information("RIFT_STRESS memory dispose");

    private static bool InsideRift()
        => string.Equals(Environment.GetEnvironmentVariable("RIFT_EXECUTOR"), "bubblewrap-v2", StringComparison.Ordinal);
}
