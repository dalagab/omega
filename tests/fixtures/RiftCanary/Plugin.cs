using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using Dalamud.IoC;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;

namespace RiftCanary;

/// <summary>
/// Environmental sentinel for Interdimensional Rift.
///
/// Canary asks one question: "is the mine still safe?"
/// It performs finite, non-destructive checks of the sandbox boundary and is inert
/// unless the trusted Bubblewrap executor stamped RIFT_EXECUTOR=bubblewrap-v2.
/// </summary>
public sealed class Plugin : IDalamudPlugin
{
    private const int AF_PACKET = 17;
    private const int SOCK_RAW = 3;
    private const int CLONE_NEWUSER = 0x10000000;
    private const int PTRACE_TRACEME = 0;

    [PluginService] internal static IPluginLog Log { get; private set; } = null!;

    public Plugin()
    {
        if (!InsideRift())
        {
            Log.Information("RIFT_CANARY inert outside Rift");
            return;
        }

        ProbeReadOnlyArtifact();
        ProbeReadOnlyRuntime();
        ProbeReadOnlyContracts();
        ProbeHostSecretsAbsent();
        ProbeNoNewPrivileges();
        ProbeCapabilitiesDropped();
        ProbeNetworkNamespaceIsolated();
        ProbeNestedUserNamespaceDenied();
        ProbePtraceDenied();
        ProbeRawPacketSocketDenied();
        ProbeTmpfsBounds();
        ProbeExpectedHostname();

        Log.Information("RIFT_CANARY completed");
    }

    private static bool InsideRift()
        => string.Equals(
            Environment.GetEnvironmentVariable("RIFT_EXECUTOR"),
            "bubblewrap-v2",
            StringComparison.Ordinal);

    private static void ProbeReadOnlyArtifact()
    {
        var directory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
        ProbeWriteDenied(
            Path.Combine(directory, "rift-canary-write-sentinel.txt"),
            "boundary.artifact_readonly");
    }

    private static void ProbeReadOnlyRuntime()
        => ProbeWriteDenied("/rift/rift-canary-write-sentinel.txt", "boundary.runtime_readonly");

    private static void ProbeReadOnlyContracts()
        => ProbeWriteDenied("/contracts/rift-canary-write-sentinel.txt", "boundary.contracts_readonly");

    private static void ProbeWriteDenied(string path, string marker)
    {
        try
        {
            File.WriteAllText(path, "this must never be writable");
            Log.Error($"{marker} FAILED writable={path}");
            try { File.Delete(path); } catch { /* boundary already failed; best-effort cleanup only */ }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            Log.Information($"{marker} PASS exception={ex.GetType().Name}");
        }
    }

    private static void ProbeHostSecretsAbsent()
    {
        var secretVariables = new[]
        {
            "GITHUB_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AZURE_CLIENT_SECRET",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "RIFT_SHOULD_NOT_LEAK",
        };

        var leakedNames = secretVariables
            .Where(name => !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(name)))
            .ToArray();

        var hostPaths = new[]
        {
            "/home/runner",
            "/github/workspace",
            "/root/.ssh",
            "/var/run/docker.sock",
            "/run/docker.sock",
        };
        var visiblePaths = hostPaths.Where(path => File.Exists(path) || Directory.Exists(path)).ToArray();

        if (leakedNames.Length == 0 && visiblePaths.Length == 0)
        {
            Log.Information("boundary.host_secrets_absent PASS");
            return;
        }

        Log.Error(
            $"boundary.host_secrets_absent FAILED env={string.Join(",", leakedNames)} paths={string.Join(",", visiblePaths)}");
    }

    private static void ProbeNoNewPrivileges()
    {
        var status = ReadProcStatus();
        var pass = status.TryGetValue("NoNewPrivs", out var value) && value == "1";
        Log.Information(pass
            ? "boundary.no_new_privileges PASS"
            : $"boundary.no_new_privileges FAILED value={value ?? "missing"}");
    }

    private static void ProbeCapabilitiesDropped()
    {
        var status = ReadProcStatus();
        var value = status.GetValueOrDefault("CapEff");
        var pass = ulong.TryParse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var caps) && caps == 0;
        Log.Information(pass
            ? "boundary.capabilities_dropped PASS"
            : $"boundary.capabilities_dropped FAILED value={value ?? "missing"}");
    }

    private static Dictionary<string, string> ReadProcStatus()
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in File.ReadLines("/proc/self/status"))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0)
                continue;
            result[line[..separator]] = line[(separator + 1)..].Trim();
        }
        return result;
    }

    private static void ProbeNetworkNamespaceIsolated()
    {
        try
        {
            var routes = File.ReadAllLines("/proc/net/route").Skip(1);
            var defaultRoute = routes.Any(line =>
            {
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                return parts.Length >= 2 &&
                       !parts[0].Equals("lo", StringComparison.Ordinal) &&
                       parts[1].Equals("00000000", StringComparison.Ordinal);
            });

            Log.Information(defaultRoute
                ? "boundary.network_isolated FAILED default-route-present"
                : "boundary.network_isolated PASS no-default-route");
        }
        catch (Exception ex)
        {
            Log.Error($"boundary.network_isolated FAILED exception={ex.GetType().Name}");
        }
    }

    private static void ProbeNestedUserNamespaceDenied()
    {
        Marshal.SetLastPInvokeError(0);
        var rc = unshare(CLONE_NEWUSER);
        var errno = Marshal.GetLastPInvokeError();
        Log.Information(rc == -1
            ? $"boundary.nested_userns_denied PASS errno={errno}"
            : $"boundary.nested_userns_denied FAILED rc={rc}");
    }

    private static void ProbePtraceDenied()
    {
        Marshal.SetLastPInvokeError(0);
        var rc = ptrace(PTRACE_TRACEME, 0, IntPtr.Zero, IntPtr.Zero);
        var errno = Marshal.GetLastPInvokeError();
        Log.Information(rc == -1
            ? $"boundary.ptrace_denied PASS errno={errno}"
            : $"boundary.ptrace_denied FAILED rc={rc}");
    }

    private static void ProbeRawPacketSocketDenied()
    {
        Marshal.SetLastPInvokeError(0);
        var fd = socket(AF_PACKET, SOCK_RAW, 0);
        var errno = Marshal.GetLastPInvokeError();
        if (fd >= 0)
        {
            close(fd);
            Log.Error($"boundary.raw_packet_socket_denied FAILED fd={fd}");
            return;
        }

        Log.Information($"boundary.raw_packet_socket_denied PASS errno={errno}");
    }

    private static void ProbeTmpfsBounds()
    {
        ProbeTmpfsBound("/tmp", "RIFT_TMPFS_TMP_BYTES", "boundary.tmpfs_tmp_bounded");
        ProbeTmpfsBound("/home", "RIFT_TMPFS_HOME_BYTES", "boundary.tmpfs_home_bounded");
        ProbeTmpfsBound("/work", "RIFT_TMPFS_WORK_BYTES", "boundary.tmpfs_work_bounded");
    }

    private static void ProbeTmpfsBound(string path, string envName, string marker)
    {
        var expectedText = Environment.GetEnvironmentVariable(envName);
        if (!ulong.TryParse(expectedText, out var expected) || expected == 0)
        {
            Log.Error($"{marker} FAILED expected-size-missing");
            return;
        }

        if (statvfs(path, out var stats) != 0)
        {
            Log.Error($"{marker} FAILED statvfs-errno={Marshal.GetLastPInvokeError()}");
            return;
        }

        var blockSize = stats.f_frsize == 0 ? stats.f_bsize : stats.f_frsize;
        var actual = checked(blockSize * stats.f_blocks);
        // tmpfs sizes are page rounded; one MiB tolerance is ample and does not
        // allow an accidentally unbounded host filesystem to pass.
        var pass = actual <= expected + 1024UL * 1024UL;
        Log.Information(pass
            ? $"{marker} PASS actual={actual} expected={expected}"
            : $"{marker} FAILED actual={actual} expected={expected}");
    }

    private static void ProbeExpectedHostname()
    {
        Log.Information(
            Environment.MachineName.Equals("interdimensional-rift", StringComparison.Ordinal)
                ? "boundary.hostname_isolated PASS"
                : $"boundary.hostname_isolated FAILED hostname={Environment.MachineName}");
    }

    public void Dispose() => Log.Information("RIFT_CANARY dispose");

    [DllImport("libc", SetLastError = true)]
    private static extern int unshare(int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern long ptrace(int request, int pid, IntPtr addr, IntPtr data);

    [DllImport("libc", SetLastError = true)]
    private static extern int socket(int domain, int type, int protocol);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", SetLastError = true)]
    private static extern int statvfs(string path, out Statvfs buffer);

    [StructLayout(LayoutKind.Sequential)]
    private struct Statvfs
    {
        public ulong f_bsize;
        public ulong f_frsize;
        public ulong f_blocks;
        public ulong f_bfree;
        public ulong f_bavail;
        public ulong f_files;
        public ulong f_ffree;
        public ulong f_favail;
        public ulong f_fsid;
        public ulong f_flag;
        public ulong f_namemax;
        public int f_spare0;
        public int f_spare1;
        public int f_spare2;
        public int f_spare3;
        public int f_spare4;
        public int f_spare5;
    }
}
