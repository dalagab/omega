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
        Assert.DoesNotContain(report.Observations, f => f.Kind == RuntimeObservationKind.Timeout);

        Assert.Contains(report.Observations,
            f => f.Kind == RuntimeObservationKind.ServiceInjection && f.Component == "Dalamud.Plugin.Services.IPluginLog");
        Assert.Contains(report.Observations,
            f => f.Kind == RuntimeObservationKind.Lifecycle && f.Operation == "constructor" && f.Outcome == "completed");
        Assert.Contains(report.Observations,
            f => f.Kind == RuntimeObservationKind.Log && (f.Message ?? "").Contains("Starting up", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Observations,
            f => f.Kind == RuntimeObservationKind.ServiceAccess && f.Component == "IClientState" && f.Operation == "get_IsLoggedIn");
        Assert.Contains(report.Observations,
            f => f.Kind == RuntimeObservationKind.AssemblyLoad && (f.Message ?? "").Contains("SomeOther", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Observations,
            f => f.Kind == RuntimeObservationKind.ServiceAccess && f.Component == "IDalamudPluginInterface" && f.Operation!.StartsWith("GetIpcProvider", StringComparison.Ordinal));
        Assert.Contains(report.Observations,
            f => f.Kind == RuntimeObservationKind.Log && (f.Message ?? "").Contains("framework tick", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Observations,
            f => f.Kind == RuntimeObservationKind.Log && (f.Message ?? "").Contains("Shutting down", StringComparison.OrdinalIgnoreCase));
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
        Assert.Contains(report.Observations,
            f => f.Kind == RuntimeObservationKind.Lifecycle && f.Operation == "LoadAsync" && f.Outcome == "completed");
        Assert.Contains(report.Observations,
            f => f.Kind == RuntimeObservationKind.Log && (f.Message ?? "").Contains("async load completed", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Observations,
            f => f.Kind == RuntimeObservationKind.Log && (f.Message ?? "").Contains("async dispose completed", StringComparison.OrdinalIgnoreCase));
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

        var injected = report.Observations
            .Where(f => f.Kind == RuntimeObservationKind.ServiceInjection)
            .Select(f => f.Component ?? string.Empty)
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

        // Rift now resolves RID-native dependencies from the exact plugin
        // artifact. A plugin may still throw because the synthetic Dalamud host
        // cannot reproduce every game/runtime condition, but it must not deadlock
        // waiting for Dalamud's real internal Service<T> graph.
        Assert.Contains(report.Observations,
            f => f.Kind == RuntimeObservationKind.Lifecycle && f.Operation == "constructor" &&
                 (f.Outcome == "completed" || f.Outcome == "threw"));
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

public class AlphaTest
{
    [Fact]
    public void Alpha_IsInertOutsideRiftBoundary()
    {
        var previous = Environment.GetEnvironmentVariable("RIFT_EXECUTOR");
        try
        {
            Environment.SetEnvironmentVariable("RIFT_EXECUTOR", null);
            var alphaDll = LocateAlpha();
            var report = new InterdimensionalRift.Host.SandboxHost().Run(alphaDll, TimeSpan.FromSeconds(10), frameworkTicks: 0);

            Assert.Equal("ok", report.Plugin.LoadOutcome);
            Assert.Contains(report.Observations,
                o => o.Kind == RuntimeObservationKind.Log &&
                     (o.Message ?? string.Empty).Contains("RIFT_ALPHA inert", StringComparison.Ordinal));
            Assert.DoesNotContain(report.Observations,
                o => o.Kind == RuntimeObservationKind.Log &&
                     (o.Message ?? string.Empty).Contains("runtime.network.loopback", StringComparison.Ordinal));
        }
        finally
        {
            Environment.SetEnvironmentVariable("RIFT_EXECUTOR", previous);
        }
    }

    [Fact]
    public void Alpha_ArmedModeExercisesHarmlessReferenceBranches()
    {
        var previous = Environment.GetEnvironmentVariable("RIFT_EXECUTOR");
        try
        {
            Environment.SetEnvironmentVariable("RIFT_EXECUTOR", "bubblewrap-v2");
            var alphaDll = LocateAlpha();
            var report = new InterdimensionalRift.Host.SandboxHost().Run(alphaDll, TimeSpan.FromSeconds(10), frameworkTicks: 1);

            Assert.Equal("ok", report.Plugin.LoadOutcome);
            foreach (var marker in new[]
            {
                "RIFT_ALPHA armed inside Rift",
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
                Assert.Contains(report.Observations,
                    o => o.Kind == RuntimeObservationKind.Log &&
                         (o.Message ?? string.Empty).Contains(marker, StringComparison.Ordinal));
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("RIFT_EXECUTOR", previous);
        }
    }

    private static string LocateAlpha()
    {
        var testBin = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.Combine(testBin, "RiftAlpha.dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", "RiftAlpha", "bin", "Debug", "net10.0", "RiftAlpha.dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", "RiftAlpha", "bin", "Release", "net10.0", "RiftAlpha.dll"),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists) ?? Path.GetFullPath(candidates[0]);
    }
}

public class CanaryTest
{
    [Fact]
    public void Canary_IsInertOutsideRiftBoundary()
    {
        var previous = Environment.GetEnvironmentVariable("RIFT_EXECUTOR");
        try
        {
            Environment.SetEnvironmentVariable("RIFT_EXECUTOR", null);
            var dll = LocateCanary();
            var report = new InterdimensionalRift.Host.SandboxHost().Run(dll, TimeSpan.FromSeconds(10), frameworkTicks: 0);

            Assert.Equal("ok", report.Plugin.LoadOutcome);
            Assert.Contains(report.Observations,
                o => o.Kind == RuntimeObservationKind.Log &&
                     (o.Message ?? string.Empty).Contains("RIFT_CANARY inert outside Rift", StringComparison.Ordinal));
            Assert.DoesNotContain(report.Observations,
                o => o.Kind == RuntimeObservationKind.Log &&
                     (o.Message ?? string.Empty).Contains("boundary.artifact_readonly", StringComparison.Ordinal));
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
            Path.Combine(testBin, "RiftCanary.dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", "RiftCanary", "bin", "Debug", "net10.0", "RiftCanary.dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", "RiftCanary", "bin", "Release", "net10.0", "RiftCanary.dll"),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists) ?? Path.GetFullPath(candidates[0]);
    }
}

public class StressFixtureSafetyTest
{
    [Theory]
    [InlineData("RiftMemoryPressure", "RIFT_STRESS memory inert outside Rift")]
    [InlineData("RiftTaskPressure", "RIFT_STRESS tasks inert outside Rift")]
    [InlineData("RiftTmpfsPressure", "RIFT_STRESS tmpfs inert outside Rift")]
    [InlineData("RiftHangTree", "RIFT_STRESS hangtree inert outside Rift")]
    public void ContainmentStressFixtures_AreInertOutsideRift(string assemblyName, string inertMarker)
    {
        var previous = Environment.GetEnvironmentVariable("RIFT_EXECUTOR");
        try
        {
            Environment.SetEnvironmentVariable("RIFT_EXECUTOR", null);
            var dll = LocateFixture(assemblyName);
            var report = new InterdimensionalRift.Host.SandboxHost().Run(dll, TimeSpan.FromSeconds(5), frameworkTicks: 0);

            Assert.Equal("ok", report.Plugin.LoadOutcome);
            Assert.Contains(report.Observations,
                o => o.Kind == RuntimeObservationKind.Log &&
                     (o.Message ?? string.Empty).Contains(inertMarker, StringComparison.Ordinal));
        }
        finally
        {
            Environment.SetEnvironmentVariable("RIFT_EXECUTOR", previous);
        }
    }

    private static string LocateFixture(string assemblyName)
    {
        var testBin = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.Combine(testBin, assemblyName + ".dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", assemblyName, "bin", "Debug", "net10.0", assemblyName + ".dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", assemblyName, "bin", "Release", "net10.0", assemblyName + ".dll"),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists) ?? Path.GetFullPath(candidates[0]);
    }
}

public class CreateSemanticsTest
{
    [Fact]
    public void PluginInterface_CreateAndCreateAsync_InjectServicesAndScopedObjects()
    {
        var dll = LocateFixture("RiftCreateSemantics");
        var report = new InterdimensionalRift.Host.SandboxHost().Run(dll, TimeSpan.FromSeconds(10), frameworkTicks: 0);

        Assert.Equal("ok", report.Plugin.LoadOutcome);
        Assert.Contains(report.Observations, o =>
            o.Kind == RuntimeObservationKind.ServiceAccess &&
            o.Component == "IDalamudPluginInterface" && o.Operation == "Create");
        Assert.Contains(report.Observations, o =>
            o.Kind == RuntimeObservationKind.ServiceAccess &&
            o.Component == "IDalamudPluginInterface" && o.Operation == "CreateAsync");
        Assert.Contains(report.Observations, o =>
            o.Kind == RuntimeObservationKind.ServiceInjection &&
            (o.Message ?? "").Contains("CreatedService.ClientState", StringComparison.Ordinal));
        Assert.Contains(report.Observations, o =>
            o.Kind == RuntimeObservationKind.Log &&
            (o.Message ?? "").Contains("RIFT_CREATE semantics complete", StringComparison.Ordinal));
    }

    private static string LocateFixture(string assemblyName)
    {
        var testBin = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.Combine(testBin, assemblyName + ".dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", assemblyName, "bin", "Debug", "net10.0", assemblyName + ".dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", assemblyName, "bin", "Release", "net10.0", assemblyName + ".dll"),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists) ?? Path.GetFullPath(candidates[0]);
    }
}
