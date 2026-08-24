using System.Reflection;
using System.Runtime.CompilerServices;
using InterdimensionalRift.Host;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Runtime;

internal static class SyntheticDalamudHostRuntime
{
    private static readonly object Gate = new();
    private static bool installed;
    private static AccessTracker? tracker;

    public static void EnsureInstalled(AccessTracker accessTracker)
    {
        tracker = accessTracker;
        if (installed)
        {
            Observe("reuse", "synthetic_ready");
            return;
        }

        lock (Gate)
        {
            tracker = accessTracker;
            if (installed)
            {
                Observe("reuse", "synthetic_ready");
                return;
            }

            try
            {
                var dalamud = DalamudContract.TryResolveTrusted(new AssemblyName("Dalamud"))
                    ?? throw new InvalidOperationException("Dalamud assembly is not present in the frozen contract runtime.");
                var serviceType = RequireType(dalamud, "Dalamud.Service`1");
                var containerType = RequireType(dalamud, "Dalamud.IoC.Internal.ServiceContainer");
                var hostType = RequireType(dalamud, "Dalamud.Dalamud");

                var container = Activator.CreateInstance(containerType, nonPublic: true)
                    ?? throw new InvalidOperationException("Rift could not construct the synthetic Dalamud service container.");
                Provide(serviceType.MakeGenericType(containerType), container);

                var host = RuntimeHelpers.GetUninitializedObject(hostType);
                var startInfoProperty = hostType.GetProperty("StartInfo", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                    ?? throw new MissingMemberException(hostType.FullName, "StartInfo");
                var startInfo = RuntimeHelpers.GetUninitializedObject(startInfoProperty.PropertyType);
                startInfoProperty.SetValue(host, startInfo);
                Provide(serviceType.MakeGenericType(hostType), host);

                installed = true;
                BootstrapTrace.Record("dalamud_host.synthetic_ready");
                Observe("install", "synthetic_ready");
            }
            catch (Exception ex)
            {
                var detail = Describe(ex);
                BootstrapTrace.Record($"dalamud_host.unavailable exception={detail}");
                Observe("install", "unavailable", detail);
            }
        }
    }

    private static void Provide(Type serviceType, object instance)
    {
        var provide = serviceType.GetMethod("Provide", BindingFlags.Public | BindingFlags.Static)
            ?? throw new MissingMethodException(serviceType.FullName, "Provide");
        provide.Invoke(null, new[] { instance });
    }

    private static Type RequireType(Assembly assembly, string name) =>
        assembly.GetType(name, throwOnError: true)
        ?? throw new TypeLoadException(name);

    private static string Describe(Exception exception)
    {
        var details = new List<string>();
        for (var current = exception; current is not null; current = current.InnerException)
            details.Add($"{current.GetType().Name}:{current.Message}");
        return string.Join(" -> ", details);
    }

    private static void Observe(string operation, string outcome, string? reason = null) =>
        tracker?.Record(RuntimeObservationKind.NativeGameState, "dalamud_host", operation, outcome,
            message: reason,
            parameters: new Dictionary<string, string?>
            {
                ["platform"] = "synthetic_non_windows",
                ["real_dalamud_host"] = "false",
                ["game_loader"] = "not_initialized",
                ["game_memory"] = "not_initialized",
            });
}
