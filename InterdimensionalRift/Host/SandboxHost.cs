using System.Diagnostics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using InterdimensionalRift.Artifacts;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;
using InterdimensionalRift.Runtime;

namespace InterdimensionalRift.Host;

/// <summary>
/// Drives one API-15 plugin from assembly load through constructor/LoadAsync,
/// deterministic framework ticks, and disposal. The external Bubblewrap
/// supervisor remains the hard timeout/security boundary.
/// </summary>
public sealed class SandboxHost
{
    public SandboxReport Run(string pluginPath, TimeSpan initTimeout, int frameworkTicks = 3, string? exerciseProfile = null)
    {
        // Freeze trusted supervisor provenance before any plugin-controlled code can run.
        var execution = ExecutionProvenance.Capture();
        var tracker = new AccessTracker();
        var uiProfile = Environment.GetEnvironmentVariable("RIFT_UI_PROFILE") ?? "none";
        if (uiProfile == "headless-ui-v1")
            tracker.Boundary("ui", "headless", "headless cimgui symbol shim is mounted; no rendering, frames, or draw callbacks are performed");
        ArtifactInventory? artifactInventory = null;
        var profile = exerciseProfile ?? PostInitExerciseEngine.SafeProfile;
        var exercise = ExerciseSummary.NotRun(profile, "startup not completed", frameworkTicks);

        BootstrapTrace.Record("contract.loading");
        DalamudContract.EnsureLoaded();
        BootstrapTrace.Record("contract.loaded");
        SyntheticDalamudHostRuntime.EnsureInstalled(tracker);
        DalamudContract.EnterSandboxFailFastHostMode();
        tracker.Boundary(
            "dalamud.internal_service_locator",
            "fail_fast",
            "real Dalamud host services intentionally unavailable in Rift");

        using var startupPhase = tracker.PushPhase("startup");

        if (!File.Exists(pluginPath))
        {
            return new SandboxReport
            {
                Plugin = new PluginInfo
                {
                    Path = pluginPath,
                    LoadOutcome = "load_failed",
                    LoadError = "plugin file not found",
                },
                Execution = execution,
                Exercise = exercise,
            };
        }

        artifactInventory = ArtifactInventory.Build(Path.GetDirectoryName(Path.GetFullPath(pluginPath))!);
        tracker.AttachArtifactInventory(artifactInventory);

        var internalName = Path.GetFileNameWithoutExtension(pluginPath);
        var info = new PluginInfo
        {
            Path = pluginPath,
            AssemblyName = internalName,
            InternalName = internalName,
        };

        using var loader = new PluginLoader(tracker, $"rift-{internalName}-{Guid.NewGuid():N}", pluginPath);
        using var hook = loader.InstallHook();

        Assembly assembly;
        try
        {
            BootstrapTrace.Record("plugin.loading");
            assembly = loader.Load(pluginPath);
            BootstrapTrace.Record("plugin.loaded");
            info.AssemblyName = loader.AssemblyName;
        }
        catch (Exception ex)
        {
            info.LoadOutcome = "load_failed";
            info.LoadError = $"{ex.GetType().Name}: {ex.Message}";
            tracker.Lifecycle("assembly_load", "threw", exception: ex);
            return Finalize(tracker, info, exercise, execution, artifactInventory);
        }

        BootstrapTrace.Record("plugin_type.resolving");
        var pluginType = loader.FindPluginType(assembly, out var notFoundReason);
        if (pluginType is null)
        {
            info.LoadOutcome = "not_a_plugin";
            info.LoadError = notFoundReason;
            return Finalize(tracker, info, exercise, execution, artifactInventory);
        }

        info.LoadOutcome = "loaded";
        BootstrapTrace.Record("registry.creating");
        var registry = new RuntimeServiceRegistry(tracker, internalName, pluginPath);
        BootstrapTrace.Record("registry.created");
        object? plugin = null;
        var initSw = Stopwatch.StartNew();
        var initOk = false;

        try
        {
            BootstrapTrace.Record("plugin_constructor.queued");
            var createTask = Task.Run(() => registry.CreatePluginInstance(pluginType));
            if (!createTask.Wait(initTimeout))
            {
                tracker.Timeout("constructor");
                info.LoadOutcome = "init_timeout";
                return FinalizeWithDuration(tracker, info, initSw, exercise, execution, artifactInventory);
            }

            plugin = createTask.GetAwaiter().GetResult();

            var (_, asyncContract, _) = loader.ResolvePluginContractTypes();
            if (asyncContract is not null && asyncContract.IsInstanceOfType(plugin))
            {
                initOk = InvokeAsyncLoad(plugin, asyncContract, initTimeout, tracker);
            }
            else
            {
                // API-15 synchronous IDalamudPlugin has no Initialize method.
                // Constructor completion after [PluginService]/constructor
                // injection is the synchronous initialization boundary.
                initOk = true;
            }
        }
        catch (Exception ex)
        {
            var actual = Unwrap(ex);
            tracker.InitException(actual);
            info.LoadOutcome = "init_threw";
            info.LoadError = $"{actual.GetType().Name}: {actual.Message}";
        }

        info.InitDurationMs = initSw.ElapsedMilliseconds;
        if (initOk)
            info.LoadOutcome = "ok";
        else if (info.LoadOutcome is "loaded")
            info.LoadOutcome = tracker.Snapshot().Any(f => f.Kind == RuntimeObservationKind.Timeout) ? "init_timeout" : "init_threw";

        if (initOk)
            exercise = PostInitExerciseEngine.Run(registry, tracker, profile, frameworkTicks);
        else
            exercise = ExerciseSummary.NotRun(profile, "plugin initialization did not complete", frameworkTicks);

        if (plugin is not null)
        {
            using var disposePhase = tracker.PushPhase("dispose");
            var callbackStillMayBeRunning = exercise.Registrations.Any(r =>
                r.Reason is "callback_timeout" or "returned_async_timeout");
            if (callbackStillMayBeRunning)
            {
                info.DisposeOutcome = "not_attempted_exercise_timeout";
                tracker.Lifecycle("Dispose", "skipped", plugin.GetType().FullName);
            }
            else
            {
                DisposePlugin(plugin, TimeSpan.FromSeconds(5), tracker, info);
            }
        }

        loader.Unload();
        return Finalize(tracker, info, exercise, execution, artifactInventory);
    }

    private static bool InvokeAsyncLoad(object plugin, Type asyncContract, TimeSpan timeout, AccessTracker tracker)
    {
        var load = asyncContract.GetMethod("LoadAsync", new[] { typeof(CancellationToken) })
            ?? throw new InvalidOperationException("API-15 IAsyncDalamudPlugin.LoadAsync(CancellationToken) was not found.");

        tracker.Lifecycle("LoadAsync", "begin", plugin.GetType().FullName);
        using var cts = new CancellationTokenSource(timeout);
        Task task;
        try
        {
            var result = load.Invoke(plugin, new object?[] { cts.Token });
            task = result as Task ?? throw new InvalidOperationException("LoadAsync did not return Task.");
        }
        catch (TargetInvocationException ex)
        {
            var actual = ex.InnerException ?? ex;
            ExceptionDispatchInfo.Capture(actual).Throw();
            throw; // unreachable
        }

        try
        {
            if (!task.Wait(timeout))
            {
                cts.Cancel();
                tracker.Timeout("LoadAsync");
                return false;
            }
            task.GetAwaiter().GetResult();
            tracker.Lifecycle("LoadAsync", "completed", plugin.GetType().FullName);
            return true;
        }
        catch (Exception ex)
        {
            var actual = Unwrap(ex);
            tracker.Lifecycle("LoadAsync", "threw", plugin.GetType().FullName, actual);
            tracker.InitException(actual);
            return false;
        }
    }

    private static void DisposePlugin(object plugin, TimeSpan timeout, AccessTracker tracker, PluginInfo info)
    {
        try
        {
            Task task;
            if (plugin is IAsyncDisposable asyncDisposable)
            {
                tracker.Lifecycle("DisposeAsync", "begin", plugin.GetType().FullName);
                task = asyncDisposable.DisposeAsync().AsTask();
            }
            else if (plugin is IDisposable disposable)
            {
                tracker.Lifecycle("Dispose", "begin", plugin.GetType().FullName);
                task = Task.Run(() =>
                {
                    using var dalamudMainThread = DalamudMainThreadRuntime.Enter(tracker);
                    disposable.Dispose();
                });
            }
            else
            {
                info.DisposeOutcome = "not_applicable";
                return;
            }

            if (!task.Wait(timeout))
            {
                tracker.Timeout("Dispose");
                info.DisposeOutcome = "timeout";
                return;
            }

            task.GetAwaiter().GetResult();
            info.DisposeOutcome = "ok";
            tracker.Lifecycle("Dispose", "completed", plugin.GetType().FullName);
        }
        catch (Exception ex)
        {
            var actual = Unwrap(ex);
            tracker.DisposeException(actual);
            info.DisposeOutcome = "threw";
            info.DisposeError = $"{actual.GetType().Name}: {actual.Message}";
        }
    }

    private static Exception Unwrap(Exception ex)
    {
        if (ex is AggregateException aggregate && aggregate.InnerExceptions.Count == 1)
            return Unwrap(aggregate.InnerExceptions[0]);
        if (ex is TargetInvocationException tie && tie.InnerException is not null)
            return Unwrap(tie.InnerException);
        return ex;
    }

    private static SandboxReport FinalizeWithDuration(AccessTracker tracker, PluginInfo info, Stopwatch sw, ExerciseSummary exercise, ExecutionProvenance execution, ArtifactInventory? artifactInventory)
    {
        info.InitDurationMs = sw.ElapsedMilliseconds;
        return Finalize(tracker, info, exercise, execution, artifactInventory);
    }

    private static SandboxReport Finalize(AccessTracker tracker, PluginInfo info, ExerciseSummary exercise, ExecutionProvenance execution, ArtifactInventory? artifactInventory) =>
        RuntimeObservationReporter.Finalize(tracker.Snapshot(), info, exercise, execution, artifactInventory);
}
