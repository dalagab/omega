using System.Diagnostics;
using Dalamud.IoC;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;

namespace RiftHangTree;

public sealed class Plugin : IDalamudPlugin
{
    [PluginService] internal static IPluginLog Log { get; private set; } = null!;

    public Plugin()
    {
        if (!InsideRift())
        {
            Log.Information("RIFT_STRESS hangtree inert outside Rift");
            return;
        }

        Log.Warning("RIFT_STRESS hangtree begin");
        using var child = Process.Start(new ProcessStartInfo
        {
            FileName = "/input/rift-hang-child",
            UseShellExecute = false,
        });

        if (child is null)
            throw new InvalidOperationException("Rift hang-tree helper did not start.");

        Log.Warning($"stress.hangtree child_started pid={child.Id}");
        Thread.Sleep(Timeout.Infinite);
    }

    public void Dispose()
    {
        // Constructor never returns in the stress scenario. The outer supervisor,
        // not plugin cleanup, owns process-tree termination.
    }

    private static bool InsideRift()
        => string.Equals(Environment.GetEnvironmentVariable("RIFT_EXECUTOR"), "bubblewrap-v2", StringComparison.Ordinal);
}
