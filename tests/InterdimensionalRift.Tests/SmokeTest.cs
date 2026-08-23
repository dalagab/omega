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

public class GameInteropSemanticsTest
{
    [Fact]
    public void GenericHookConstraints_ArePreservedAndHooksRemainInert()
    {
        var dll = LocateFixture();
        Assert.True(File.Exists(dll), $"Game interop fixture missing: {dll}");

        var report = new InterdimensionalRift.Host.SandboxHost().Run(dll, TimeSpan.FromSeconds(10), frameworkTicks: 0);

        var initException = report.Observations.FirstOrDefault(o => o.Kind == RuntimeObservationKind.Exception);
        Assert.True(report.Plugin.LoadOutcome == "ok",
            $"Expected game-interop fixture to initialize, got {report.Plugin.LoadOutcome}: {report.Plugin.LoadError}\n{initException?.ExceptionDetail}");
        Assert.Contains(report.Observations,
            o => o.Kind == RuntimeObservationKind.SignatureScan && o.Operation == "GetStaticAddressFromSig");
        Assert.Contains(report.Observations,
            o => o.Kind == RuntimeObservationKind.Hook && o.Operation == "HookFromSignature" && o.Outcome == "synthetic_created");
        Assert.Contains(report.Observations,
            o => o.Kind == RuntimeObservationKind.Hook && o.Operation == "Enable" && o.Outcome == "observed_inert");
        Assert.Contains(report.Observations,
            o => o.Kind == RuntimeObservationKind.Hook && o.Operation == "get_Original" && o.Outcome == "synthetic_noop");
        Assert.Contains(report.Observations,
            o => o.Kind == RuntimeObservationKind.Log && (o.Message ?? string.Empty).Contains("RIFT_GAME_INTEROP semantics complete"));
    }

    private static string LocateFixture()
    {
        var testBin = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.Combine(testBin, "RiftGameInteropSemantics.dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", "RiftGameInteropSemantics", "bin", "Debug", "net10.0", "RiftGameInteropSemantics.dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", "RiftGameInteropSemantics", "bin", "Release", "net10.0", "RiftGameInteropSemantics.dll"),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists) ?? Path.GetFullPath(candidates[0]);
    }
}


public class GameDataSemanticsTest
{
    [Fact]
    public void ConstrainedExcelSheet_IsEmptyEnumerableAndDoesNotLoadGameFiles()
    {
        var dll = LocateFixture();
        Assert.True(File.Exists(dll), $"Game-data fixture missing: {dll}");

        var report = new InterdimensionalRift.Host.SandboxHost().Run(dll, TimeSpan.FromSeconds(10), frameworkTicks: 0);

        var initException = report.Observations.FirstOrDefault(o => o.Kind == RuntimeObservationKind.Exception);
        Assert.True(report.Plugin.LoadOutcome == "ok",
            $"Expected game-data fixture to initialize, got {report.Plugin.LoadOutcome}: {report.Plugin.LoadError}\n{initException?.ExceptionDetail}");
        Assert.Contains(report.Observations,
            o => o.Kind == RuntimeObservationKind.ServiceAccess &&
                 o.Component == "IDataManager" &&
                 o.Operation == "GetExcelSheet" &&
                 o.Outcome == "synthetic_empty" &&
                 o.Parameters != null &&
                 o.Parameters.TryGetValue("real_game_data", out var value) &&
                 value == "false");
        Assert.Contains(report.Observations,
            o => o.Kind == RuntimeObservationKind.Log &&
                 (o.Message ?? string.Empty).Contains("RIFT_GAME_DATA empty sheet semantics complete"));
    }

    private static string LocateFixture()
    {
        var testBin = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.Combine(testBin, "RiftGameDataSemantics.dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", "RiftGameDataSemantics", "bin", "Debug", "net10.0", "RiftGameDataSemantics.dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", "RiftGameDataSemantics", "bin", "Release", "net10.0", "RiftGameDataSemantics.dll"),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists) ?? Path.GetFullPath(candidates[0]);
    }
}

public class NativeGameStateSemanticsTest
{
    [Fact]
    public void FfxivClientStructs_FrameworkAgentChain_IsSyntheticAndNeverCallsGameMemory()
    {
        var dll = LocateFixture();
        Assert.True(File.Exists(dll), $"Native-game-state fixture missing: {dll}");

        // Run twice in one process. FFXIVClientStructs Address.Value is process-global,
        // so the second report exercises SyntheticNativeGameStateRuntime's reuse path.
        var firstReport = new InterdimensionalRift.Host.SandboxHost().Run(dll, TimeSpan.FromSeconds(10), frameworkTicks: 0);
        var secondReport = new InterdimensionalRift.Host.SandboxHost().Run(dll, TimeSpan.FromSeconds(10), frameworkTicks: 0);

        AssertNativeStateReport(firstReport);
        AssertNativeStateReport(secondReport);
        Assert.Contains(secondReport.Observations,
            o => o.Kind == RuntimeObservationKind.NativeGameState &&
                 o.Component == "native_state" &&
                 o.Operation == "reuse" &&
                 o.Outcome == "synthetic_ready");
    }

    private static void AssertNativeStateReport(InterdimensionalRift.Reporting.SandboxReport report)
    {
        var initException = report.Observations.FirstOrDefault(o => o.Kind == RuntimeObservationKind.Exception);
        Assert.True(report.Plugin.LoadOutcome == "ok",
            $"Expected native-state fixture to initialize, got {report.Plugin.LoadOutcome}: {report.Plugin.LoadError}\n{initException?.ExceptionDetail}");
        Assert.Contains(report.Observations,
            o => o.Kind == RuntimeObservationKind.NativeGameState &&
                 o.Operation == "Framework.Instance" &&
                 o.Outcome == "synthetic_singleton" &&
                 o.Parameters != null &&
                 o.Parameters.TryGetValue("real_game_memory", out var singletonMemory) && singletonMemory == "false" &&
                 o.Parameters.TryGetValue("artifact_mutated", out var artifactMutated) && artifactMutated == "false");
        Assert.Contains(report.Observations,
            o => o.Kind == RuntimeObservationKind.NativeGameState &&
                 o.Component == "UIModule" &&
                 o.Operation == "GetAgentModule" &&
                 o.Outcome == "synthetic_pointer");
        Assert.Contains(report.Observations,
            o => o.Kind == RuntimeObservationKind.NativeGameState &&
                 o.Component == "AgentModule" &&
                 o.Operation == "GetAgentByInternalId" &&
                 o.Outcome == "synthetic_absent" &&
                 o.Parameters != null &&
                 o.Parameters.TryGetValue("real_game_memory", out var gameMemory) && gameMemory == "false" &&
                 o.Parameters.TryGetValue("native_call", out var nativeCall) && nativeCall == "false");
        Assert.Contains(report.Observations,
            o => o.Kind == RuntimeObservationKind.Log &&
                 (o.Message ?? string.Empty).Contains("RIFT_NATIVE_GAME_STATE synthetic empty chain complete", StringComparison.Ordinal));
    }

    private static string LocateFixture()
    {
        var testBin = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.Combine(testBin, "RiftNativeGameStateSemantics.dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", "RiftNativeGameStateSemantics", "bin", "Debug", "net10.0", "RiftNativeGameStateSemantics.dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "fixtures", "RiftNativeGameStateSemantics", "bin", "Release", "net10.0", "RiftNativeGameStateSemantics.dll"),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists) ?? Path.GetFullPath(candidates[0]);
    }
}

public class ExceptionStackSemanticsTest
{
    [Fact]
    public void ConstructorException_PreservesOriginalPluginFrame()
    {
        var tracker = new InterdimensionalRift.Instrumentation.AccessTracker();
        var registry = new InterdimensionalRift.Runtime.RuntimeServiceRegistry(
            tracker,
            "RiftExceptionStackSemantics",
            typeof(ExceptionStackSemanticsTest).Assembly.Location);

        var ex = Assert.Throws<InvalidOperationException>(() => registry.CreatePluginInstance(typeof(ThrowingConstructor)));
        Assert.Contains(nameof(ThrowingConstructor.ThrowFromPluginHelper), ex.StackTrace ?? string.Empty, StringComparison.Ordinal);
    }

    public sealed class ThrowingConstructor
    {
        public ThrowingConstructor() => ThrowFromPluginHelper();

        public static void ThrowFromPluginHelper() =>
            throw new InvalidOperationException("RIFT_STACK original plugin frame");
    }
}
