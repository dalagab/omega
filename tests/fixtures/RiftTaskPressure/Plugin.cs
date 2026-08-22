using Dalamud.IoC;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;

namespace RiftTaskPressure;

public sealed class Plugin : IDalamudPlugin
{
    [PluginService] internal static IPluginLog Log { get; private set; } = null!;

    public Plugin()
    {
        if (!InsideRift())
        {
            Log.Information("RIFT_STRESS tasks inert outside Rift");
            return;
        }

        Log.Warning("RIFT_STRESS tasks begin");
        using var release = new ManualResetEventSlim(false);
        var threads = new List<Thread>();
        Exception? boundedBy = null;

        try
        {
            for (var i = 0; i < 4096; i++)
            {
                var thread = new Thread(() => release.Wait())
                {
                    IsBackground = true,
                    Name = $"RiftTaskPressure-{i}",
                };
                thread.Start();
                threads.Add(thread);
            }
        }
        catch (Exception ex) when (ex is OutOfMemoryException or ThreadStateException)
        {
            boundedBy = ex;
        }
        finally
        {
            if (boundedBy is null)
                Log.Error($"stress.task_pressure FAILED no-limit-observed threads={threads.Count}");
            else
                Log.Warning($"stress.task_pressure bounded:{boundedBy.GetType().Name} threads={threads.Count}");

            release.Set();
            foreach (var thread in threads)
                thread.Join(millisecondsTimeout: 100);
        }
    }

    public void Dispose() => Log.Information("RIFT_STRESS tasks dispose");

    private static bool InsideRift()
        => string.Equals(Environment.GetEnvironmentVariable("RIFT_EXECUTOR"), "bubblewrap-v2", StringComparison.Ordinal);
}
