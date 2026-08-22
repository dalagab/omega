using Dalamud.IoC;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;

namespace RiftTmpfsPressure;

public sealed class Plugin : IDalamudPlugin
{
    [PluginService] internal static IPluginLog Log { get; private set; } = null!;

    public Plugin()
    {
        if (!InsideRift())
        {
            Log.Information("RIFT_STRESS tmpfs inert outside Rift");
            return;
        }

        Log.Warning("RIFT_STRESS tmpfs begin");
        const string path = "/tmp/rift-tmpfs-pressure.bin";
        var buffer = new byte[1024 * 1024];
        Array.Fill(buffer, (byte)0x5A);
        long written = 0;

        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 1024 * 1024,
                FileOptions.SequentialScan);

            while (true)
            {
                stream.Write(buffer);
                written += buffer.Length;
                if ((written & ((8L * 1024 * 1024) - 1)) == 0)
                    stream.Flush(flushToDisk: true);
            }
        }
        catch (IOException ex)
        {
            Log.Warning($"stress.tmpfs_pressure bounded:{ex.GetType().Name} bytes={written}");
        }
        finally
        {
            try { File.Delete(path); } catch { /* sandbox teardown is the final cleanup boundary */ }
        }
    }

    public void Dispose() => Log.Information("RIFT_STRESS tmpfs dispose");

    private static bool InsideRift()
        => string.Equals(Environment.GetEnvironmentVariable("RIFT_EXECUTOR"), "bubblewrap-v2", StringComparison.Ordinal);
}
