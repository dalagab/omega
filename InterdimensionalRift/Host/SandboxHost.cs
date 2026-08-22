using System.Diagnostics;
using System.Reflection;
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
    public SandboxReport Run(string pluginPath, TimeSpan initTimeout, int frameworkTicks = 3)
    {
        var tracker = new AccessTracker();

        DalamudContract.EnsureLoaded();
        DalamudContract.EnterSandboxFailFastHostMode();
        tracker.Lifecycle(
            "dalamud.internal_service_locator",
            "fail_fast",
            "real Dalamud host services intentionally unavailable in Rift");

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
            };
        }

        // Transitional compatibility only. Static scanning moves out of Rift in
        // the observation-schema pass; SigmaScope remains the authoritative
        // static producer.
        foreach (var f in HttpReferenceScanner.Scan(pluginPath, tracker))
            tracker.Record(f.Kind, f.Severity, f.Service, f.Method, f.Message, context: f.Context);

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
            assembly = loader.Load(pluginPath);
            info.AssemblyName = loader.AssemblyName;
        }
        catch (Exception ex)
        {
            info.LoadOutcome = "load_failed";
            info.LoadError = $"{ex.GetType().Name}: {ex.Message}";
            tracker.Lifecycle("assembly_load", "threw", exception: ex);
            return Finalize(tracker, info);
        }

        var pluginType = loader.FindPluginType(assembly, out var notFoundReason);
        if (pluginType is null)
        {
            info.LoadOutcome = "not_a_plugin";
            info.LoadError = notFoundReason;
            return Finalize(tracker, info);
        }

        info.LoadOutcome = "loaded";
        var registry = new RuntimeServiceRegistry(tracker, internalName, pluginPath);
        object? plugin = null;
        var initSw = Stopwatch.StartNew();
        var initOk = false;

        try
        {
            var createTask = Task.Run(() => registry.CreatePluginInstance(pluginType));
            if (!createTask.Wait(initTimeout))
            {
                tracker.Timeout("constructor");
                info.LoadOutcome = "init_timeout";
                return FinalizeWithDuration(tracker, info, initSw);
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
            info.LoadOutcome = tracker.Snapshot().Any(f => f.Kind == FindingKind.Timeout) ? "init_timeout" : "init_threw";

        if (initOk)
        {
            for (var i = 0; i < frameworkTicks; i++)
            {
                tracker.Lifecycle("scenario.framework_tick", "begin", $"tick={i + 1}");
                registry.FireFrameworkTick();
            }
        }

        if (plugin is not null)
            DisposePlugin(plugin, TimeSpan.FromSeconds(5), tracker, info);

        loader.Unload();
        return Finalize(tracker, info);
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
            throw ex.InnerException ?? ex;
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
                task = Task.Run(disposable.Dispose);
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

    private static SandboxReport FinalizeWithDuration(AccessTracker tracker, PluginInfo info, Stopwatch sw)
    {
        info.InitDurationMs = sw.ElapsedMilliseconds;
        return Finalize(tracker, info);
    }

    private static SandboxReport Finalize(AccessTracker tracker, PluginInfo info) =>
        FindingReporter.Finalize(tracker.Snapshot(), info);
}
