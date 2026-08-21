using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using Dalamud.IoC;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;
using Microsoft.Win32;

namespace RiftHostileCanary;

/// <summary>
/// Deliberately suspicious regression fixture for SigmaScope + Interdimensional Rift.
///
/// This assembly is NOT a distributable Dalamud plugin:
/// - it has no Dalamud manifest JSON;
/// - the fixture packaging gate rejects every .json file;
/// - its runtime probes are inert unless Rift's bubblewrap-v2 executor is present;
/// - all active targets are sandbox-local, temporary, missing, or read-only.
///
/// The frightening vocabulary below is intentional static canary material. It exists so
/// reviewed SigmaScope/YARA rules can prove they fire on high-signal combinations without
/// the fixture ever performing credential theft, injection, persistence, tampering, or
/// exfiltration.
/// </summary>
public sealed class Plugin : IDalamudPlugin
{
    [PluginService] private static IPluginLog Log { get; set; } = null!;
    [PluginService] private static IFramework Framework { get; set; } = null!;
    [PluginService] private static IClientState ClientState { get; set; } = null!;
    [PluginService] private static IDalamudPluginInterface PluginInterface { get; set; } = null!;

    // Keep exact reviewed static markers in the compiled assembly. These are DATA ONLY.
    // No code below interprets these strings as commands, paths, credentials, or targets.
    private static readonly string[][] AlarmVocabulary =
    [
        // Credential/browser + exfiltration compounds.
        ["Login Data", "Local State", "Cookies", "CryptUnprotectData", "ProtectedData.Unprotect", "discord.com/api/webhooks/", "PostAsync", "UploadData"],
        ["Local Storage\\leveldb", "discord", "CryptUnprotectData", "ProtectedData.Unprotect", "discord.com/api/webhooks/", "PostAsync"],
        ["CredRead", "PasswordVault", "Windows.Security.Credentials", "discord.com/api/webhooks/", "PostAsync", "UploadString"],

        // Classic/Nt process injection compounds. Never invoked.
        ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx"],

        // Encoded PowerShell/download/execute. Never invoked.
        ["powershell.exe", "pwsh.exe", "-EncodedCommand", " -enc ", "Invoke-WebRequest", "DownloadString", "DownloadFile", "Process.Start", "ShellExecute"],

        // Defender tamper. Never invoked.
        ["Add-MpPreference", "Set-MpPreference", "-ExclusionPath", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring"],

        // Embedded PE/dynamic loading markers. No embedded executable exists.
        ["TVqQAAMAAAAEAAAA", "FromBase64String", "Assembly.Load", "Assembly.LoadFrom", "WriteAllBytes", "Process.Start"],

        // AMSI memory patch markers. Never invoked.
        ["AmsiScanBuffer", "amsi.dll", "VirtualProtect", "GetProcAddress"],

        // Persistence markers. Never invoked.
        ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RegSetValue", "RegistryKey.SetValue", "WriteAllBytes", "FileStream", "Process.Start", "CreateProcess"],
        ["schtasks.exe", "/create", "/tn", "/tr", "Process.Start", "ShellExecute"],
        ["OpenSCManager", "CreateService", "StartService"],

        // Anti-analysis clusters. Never invoked.
        ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString"],
        ["VBoxGuest", "VBoxService", "VMware Tools", "vmtoolsd", "QEMU", "VIRTUALBOX"],

        // Legacy/static primitive vocabulary expected to project into facts.
        ["System.Net.Http.HttpClient", "WebRequest", "HttpWebRequest", "System.Net.Sockets", "TcpClient", "UdpClient", "Socket.Connect", "System.Diagnostics.Process", "ProcessStartInfo", "System.Management.Automation"]
    ];

    public Plugin()
    {
        // Prevent accidental manual side-loading from exercising even the harmless probes.
        if (!string.Equals(Environment.GetEnvironmentVariable("RIFT_EXECUTOR"), "bubblewrap-v2", StringComparison.Ordinal))
        {
            Log.Warning("RIFT_CANARY inert: hostile-behavior probes require Rift bubblewrap-v2.");
            return;
        }

        Log.Warning("RIFT_CANARY armed inside Rift; all active targets are harmless sentinels.");

        // Exercise instrumented Dalamud service paths.
        _ = ClientState.IsLoggedIn;
        Framework.Update += OnFrameworkUpdate;
        _ = PluginInterface.GetIpcProvider<object?>("rift.hostile-canary.sentinel");

        // Keep the static vocabulary rooted in runtime metadata without interpreting it.
        GC.KeepAlive(AlarmVocabulary);

        ExerciseTemporaryFileProbe();
        ExerciseLoopbackNetworkProbe();
        ExerciseMissingProcessProbe();
        ExerciseMissingAssemblyProbe();
        ExerciseMissingNativeLibraryProbe();
        ExerciseReadOnlyRegistryProbe();
        ExerciseHarmlessNativeProbe();
    }

    private static void ExerciseTemporaryFileProbe()
    {
        try
        {
            const string directory = "/tmp/rift-hostile-canary";
            var path = Path.Combine(directory, "sentinel.txt");
            Directory.CreateDirectory(directory);
            File.WriteAllText(path, "RIFT_CANARY temporary sandbox sentinel only\n");
            File.Delete(path);
            Directory.Delete(directory, recursive: false);
            Log.Warning("RIFT_CANARY runtime.filesystem.tmpfs completed");
        }
        catch (Exception ex)
        {
            Log.Warning($"RIFT_CANARY runtime.filesystem.tmpfs blocked:{ex.GetType().Name}");
        }
    }

    private static void ExerciseLoopbackNetworkProbe()
    {
        // The bwrap network namespace has no route to the host/Internet. We connect only
        // to loopback discard port 9 and expect refusal/timeout; no data leaves the sandbox.
        try
        {
            using var tcp = new TcpClient();
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
            tcp.ConnectAsync(IPAddress.Loopback, 9, cts.Token).GetAwaiter().GetResult();
            Log.Warning("RIFT_CANARY runtime.network.loopback unexpectedly-connected");
        }
        catch (Exception ex)
        {
            Log.Warning($"RIFT_CANARY runtime.network.loopback attempted:{ex.GetType().Name}");
        }

        // Exercise the HTTP client path against the same isolated loopback namespace.
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromMilliseconds(250) };
            _ = http.GetAsync("http://127.0.0.1:9/rift-canary").GetAwaiter().GetResult();
            Log.Warning("RIFT_CANARY runtime.http.loopback unexpectedly-connected");
        }
        catch (Exception ex)
        {
            Log.Warning($"RIFT_CANARY runtime.http.loopback attempted:{ex.GetType().Name}");
        }
    }

    private static void ExerciseMissingProcessProbe()
    {
        // Deliberately missing inside the read-only /rift mount: Process.Start is exercised,
        // but no child executable can start.
        try
        {
            using var child = Process.Start(new ProcessStartInfo
            {
                FileName = "/rift/RIFT_CANARY_DOES_NOT_EXIST",
                UseShellExecute = false,
            });
            child?.WaitForExit(100);
            Log.Warning("RIFT_CANARY runtime.process.missing unexpectedly-started");
        }
        catch (Exception ex)
        {
            Log.Warning($"RIFT_CANARY runtime.process.missing attempted:{ex.GetType().Name}");
        }
    }

    private static void ExerciseMissingAssemblyProbe()
    {
        try
        {
            _ = Assembly.Load("RiftHostileCanary.Does.Not.Exist");
            Log.Warning("RIFT_CANARY runtime.assembly.missing unexpectedly-loaded");
        }
        catch (Exception ex)
        {
            Log.Warning($"RIFT_CANARY runtime.assembly.missing attempted:{ex.GetType().Name}");
        }
    }

    private static void ExerciseMissingNativeLibraryProbe()
    {
        try
        {
            if (NativeLibrary.TryLoad("rift_hostile_canary_does_not_exist.so", out var handle))
            {
                NativeLibrary.Free(handle);
                Log.Warning("RIFT_CANARY runtime.native-load.missing unexpectedly-loaded");
            }
            else
            {
                Log.Warning("RIFT_CANARY runtime.native-load.missing attempted:not-found");
            }
        }
        catch (Exception ex)
        {
            Log.Warning($"RIFT_CANARY runtime.native-load.missing attempted:{ex.GetType().Name}");
        }
    }

    private static void ExerciseReadOnlyRegistryProbe()
    {
        // Read-only and intentionally non-existent. On Linux this is normally unsupported;
        // on Windows it still does not create or modify a key.
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\RiftHostileCanary\Sentinel", writable: false);
            Log.Warning($"RIFT_CANARY runtime.registry.readonly attempted:{(key is null ? "not-found" : "opened")}");
        }
        catch (Exception ex)
        {
            Log.Warning($"RIFT_CANARY runtime.registry.readonly attempted:{ex.GetType().Name}");
        }
    }

    private static void ExerciseHarmlessNativeProbe()
    {
        try
        {
            var pid = getpid();
            Log.Warning($"RIFT_CANARY runtime.pinvoke.getpid completed:{pid > 0}");
        }
        catch (Exception ex)
        {
            Log.Warning($"RIFT_CANARY runtime.pinvoke.getpid blocked:{ex.GetType().Name}");
        }
    }

    private static void OnFrameworkUpdate(IFramework framework)
    {
        Log.Debug("RIFT_CANARY runtime.framework.tick");
    }

    public void Dispose()
    {
        if (string.Equals(Environment.GetEnvironmentVariable("RIFT_EXECUTOR"), "bubblewrap-v2", StringComparison.Ordinal))
            Framework.Update -= OnFrameworkUpdate;

        Log.Info("RIFT_CANARY disposed");
    }

    [DllImport("libc", EntryPoint = "getpid")]
    private static extern int getpid();
}
