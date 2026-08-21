using System.Linq;
using InterdimensionalRift.Reporting;
using Xunit;

namespace InterdimensionalRift.Tests;

public class SmokeTest
{
    [Fact]
    public void Api15SyncPlugin_MustActuallyExecute()
    {
        var sampleDll = LocateFixture("SamplePlugin");
        Assert.True(File.Exists(sampleDll), $"Sample DLL not found at {sampleDll}");

        var host = new InterdimensionalRift.Host.SandboxHost();
        var report = host.Run(sampleDll, TimeSpan.FromSeconds(10));

        Assert.Equal("ok", report.Plugin.LoadOutcome);
        Assert.DoesNotContain(report.Findings, f => f.Kind == FindingKind.Timeout);

        Assert.Contains(report.Findings,
            f => f.Kind == FindingKind.ServiceInjection && f.Service == "Dalamud.Plugin.Services.IPluginLog");
        Assert.Contains(report.Findings,
            f => f.Kind == FindingKind.Lifecycle && f.Method == "constructor" && f.Message == "completed");
        Assert.Contains(report.Findings,
            f => f.Kind == FindingKind.Log && (f.Message ?? "").Contains("Starting up", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Findings,
            f => f.Kind == FindingKind.ServiceAccess && f.Service == "IClientState" && f.Method == "get_LocalPlayer");
        Assert.Contains(report.Findings,
            f => f.Kind == FindingKind.ReflectiveLoad && (f.Message ?? "").Contains("SomeOther", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Findings,
            f => f.Kind == FindingKind.ServiceAccess && f.Service == "IDalamudPluginInterface" && f.Method.StartsWith("GetIpcProvider", StringComparison.Ordinal));
        Assert.Contains(report.Findings,
            f => f.Kind == FindingKind.Log && (f.Message ?? "").Contains("framework tick", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Findings,
            f => f.Kind == FindingKind.Log && (f.Message ?? "").Contains("Shutting down", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Api15AsyncPlugin_UsesLoadAsyncAndDisposeAsync()
    {
        var sampleDll = LocateFixture("AsyncSamplePlugin");
        Assert.True(File.Exists(sampleDll), $"Async sample DLL not found at {sampleDll}");

        var host = new InterdimensionalRift.Host.SandboxHost();
        var report = host.Run(sampleDll, TimeSpan.FromSeconds(10), frameworkTicks: 0);

        Assert.Equal("ok", report.Plugin.LoadOutcome);
        Assert.Equal("ok", report.Plugin.DisposeOutcome);
        Assert.Contains(report.Findings,
            f => f.Kind == FindingKind.Lifecycle && f.Method == "LoadAsync" && f.Message == "completed");
        Assert.Contains(report.Findings,
            f => f.Kind == FindingKind.Log && (f.Message ?? "").Contains("async load completed", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Findings,
            f => f.Kind == FindingKind.Log && (f.Message ?? "").Contains("async dispose completed", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PositiveFixture_CannotPassAsNotAPluginOrLoadFailure()
    {
        var sampleDll = LocateFixture("SamplePlugin");
        var report = new InterdimensionalRift.Host.SandboxHost().Run(sampleDll, TimeSpan.FromSeconds(10));
        Assert.DoesNotContain(report.Plugin.LoadOutcome, new[] { "not_a_plugin", "load_failed", "init_timeout" });
    }


    [Fact]
    public void OmegaApi15Fixture_WhenProvided_MustReachDynamicInjection()
    {
        var omega = Environment.GetEnvironmentVariable("RIFT_OMEGA_FIXTURE");
        if (string.IsNullOrWhiteSpace(omega))
            return; // Dedicated corpus/CI job supplies the compiled artifact.

        omega = Path.GetFullPath(omega);
        Assert.True(File.Exists(omega), $"RIFT_OMEGA_FIXTURE does not exist: {omega}");

        var report = new InterdimensionalRift.Host.SandboxHost().Run(omega, TimeSpan.FromSeconds(15), frameworkTicks: 0);
        Assert.DoesNotContain(report.Plugin.LoadOutcome, new[] { "not_a_plugin", "load_failed", "init_timeout" });

        var injected = report.Findings
            .Where(f => f.Kind == FindingKind.ServiceInjection)
            .Select(f => f.Service ?? string.Empty)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var expected in new[]
        {
            "Dalamud.Plugin.IDalamudPluginInterface",
            "Dalamud.Plugin.Services.ICommandManager",
            "Dalamud.Plugin.Services.IPluginLog",
            "Dalamud.Plugin.Services.ITextureProvider",
            "Dalamud.Storage.Assets.IDalamudAssetManager",
            "Dalamud.Plugin.Services.ITitleScreenMenu",
            "Dalamud.Plugin.Services.IGameInteropProvider",
            "Dalamud.Plugin.Services.INotificationManager",
        })
        {
            Assert.Contains(expected, injected);
        }

        // Omega carries a Windows native SQLite payload today, so a Linux Rift
        // run may legitimately end in init_threw after dynamic execution. The
        // regression gate is that it was identified, injected and entered.
        Assert.Contains(report.Findings,
            f => f.Kind == FindingKind.Lifecycle && f.Method == "constructor" &&
                 (f.Message == "completed" || f.Message == "threw"));
    }

    private static string LocateFixture(string assemblyName)
    {
        var testBin = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.Combine(testBin, assemblyName + ".dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "..", "samples", assemblyName, "bin", "Debug", "net10.0", assemblyName + ".dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "..", "samples", assemblyName, "bin", "Release", "net10.0", assemblyName + ".dll"),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists) ?? Path.GetFullPath(candidates[0]);
    }
}

public class HostileCanaryTest
{
    [Fact]
    public void HostileCanary_IsInertOutsideRiftBoundary()
    {
        var previous = Environment.GetEnvironmentVariable("RIFT_EXECUTOR");
        try
        {
            Environment.SetEnvironmentVariable("RIFT_EXECUTOR", null);
            var canaryDll = LocateCanary();
            var report = new InterdimensionalRift.Host.SandboxHost().Run(canaryDll, TimeSpan.FromSeconds(10), frameworkTicks: 0);

            Assert.Equal("ok", report.Plugin.LoadOutcome);
            Assert.Contains(report.Findings,
                f => f.Kind == FindingKind.Log && (f.Message ?? "").Contains("RIFT_CANARY inert", StringComparison.Ordinal));
            Assert.DoesNotContain(report.Findings,
                f => f.Kind == FindingKind.Log && (f.Message ?? "").Contains("runtime.network.loopback", StringComparison.Ordinal));
            Assert.DoesNotContain(report.Findings,
                f => f.Kind == FindingKind.Log && (f.Message ?? "").Contains("runtime.process.missing", StringComparison.Ordinal));
        }
        finally
        {
            Environment.SetEnvironmentVariable("RIFT_EXECUTOR", previous);
        }
    }

    [Fact]
    public void HostileCanary_ArmedModeExercisesOnlySentinelRuntimeBranches()
    {
        var previous = Environment.GetEnvironmentVariable("RIFT_EXECUTOR");
        try
        {
            Environment.SetEnvironmentVariable("RIFT_EXECUTOR", "bubblewrap-v2");
            var canaryDll = LocateCanary();
            var report = new InterdimensionalRift.Host.SandboxHost().Run(canaryDll, TimeSpan.FromSeconds(10), frameworkTicks: 1);

            Assert.Equal("ok", report.Plugin.LoadOutcome);
            foreach (var marker in new[]
            {
                "RIFT_CANARY armed inside Rift",
                "runtime.filesystem.tmpfs",
                "runtime.network.loopback",
                "runtime.http.loopback",
                "runtime.process.missing",
                "runtime.assembly.missing",
                "runtime.native-load.missing",
                "runtime.registry.readonly",
                "runtime.pinvoke.getpid",
                "runtime.framework.tick",
            })
            {
                Assert.Contains(report.Findings,
                    f => f.Kind == FindingKind.Log && (f.Message ?? "").Contains(marker, StringComparison.Ordinal));
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("RIFT_EXECUTOR", previous);
        }
    }

    private static string LocateCanary()
    {
        var testBin = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.Combine(testBin, "RiftHostileCanary.dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", "RiftHostileCanary", "bin", "Debug", "net10.0", "RiftHostileCanary.dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", "RiftHostileCanary", "bin", "Release", "net10.0", "RiftHostileCanary.dll"),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists) ?? Path.GetFullPath(candidates[0]);
    }
}
