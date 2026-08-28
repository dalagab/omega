using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Omega.Alpha;

/// <summary>
/// Harmless active probes for Alpha runtime calibration. Every target is sandbox-local,
/// deliberately missing, read-only, or process-self metadata. These helpers intentionally
/// do not expose arbitrary target/path/command parameters.
/// </summary>
public static class AlphaSafeProbes
{
    public static void RunDefault(IAlphaReporter reporter)
    {
        AlphaGuard.RequireRiftAlphaSandbox();
        Probe(reporter, "runtime.filesystem.tmpfs", TemporaryFile);
        Probe(reporter, "runtime.network.loopback", Loopback);
        Probe(reporter, "runtime.process.missing", MissingProcess);
        Probe(reporter, "runtime.assembly.missing", MissingAssembly);
        Probe(reporter, "runtime.native-load.missing", MissingNativeLibrary);
        Probe(reporter, "runtime.registry.readonly", ReadOnlyRegistry);
        Probe(reporter, "runtime.pinvoke.getpid", HarmlessNative);
    }

    private static void Probe(IAlphaReporter reporter, string id, Action action)
    {
        reporter.Attempt(id);
        try
        {
            action();
            reporter.Observed(id, "completed");
        }
        catch (Exception ex)
        {
            reporter.Observed(id, "attempted:" + ex.GetType().Name);
        }
    }

    private static void TemporaryFile()
    {
        const string directory = "/tmp/omega-alpha";
        var path = Path.Combine(directory, "sentinel.txt");
        Directory.CreateDirectory(directory);
        File.WriteAllText(path, "Omega Alpha sandbox sentinel only\n");
        File.Delete(path);
        Directory.Delete(directory, recursive: false);
    }

    private static void Loopback()
    {
        try
        {
            using var tcp = new TcpClient();
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
            tcp.ConnectAsync(IPAddress.Loopback, 9, cts.Token).GetAwaiter().GetResult();
        }
        catch { }
        using var http = new HttpClient { Timeout = TimeSpan.FromMilliseconds(250) };
        try { _ = http.GetAsync("http://127.0.0.1:9/omega-alpha").GetAwaiter().GetResult(); }
        catch { }
    }

    private static void MissingProcess()
    {
        using var process = Process.Start(new ProcessStartInfo("/rift/OMEGA_ALPHA_DOES_NOT_EXIST") { UseShellExecute = false });
        process?.WaitForExit(250);
    }

    private static void MissingAssembly() => _ = Assembly.Load("Omega.Alpha.Does.Not.Exist");

    private static void MissingNativeLibrary()
    {
        if (NativeLibrary.TryLoad("omega_alpha_does_not_exist.so", out var handle))
            NativeLibrary.Free(handle);
    }

    private static void ReadOnlyRegistry()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The registry sentinel is Windows-only; Rift Alpha runtime normally executes inside Linux/WSL.");

        using var key = Registry.CurrentUser.OpenSubKey(@"Software\OmegaAlpha\Sentinel", writable: false);
        GC.KeepAlive(key);
    }

    private static void HarmlessNative() => _ = getpid();

    [DllImport("libc", EntryPoint = "getpid")]
    private static extern int getpid();
}
