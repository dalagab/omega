using System.Reflection;
using System.Runtime.Loader;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Runtime;

namespace InterdimensionalRift.Host;

/// <summary>
/// Loads one plugin into a collectible context while keeping the frozen Dalamud
/// contract assembly shared with the Rift host. Sharing that single contract
/// identity is what makes injected service proxies assignable to plugin fields.
/// Plugin-local dependencies remain isolated in the collectible context.
/// </summary>
public sealed class PluginLoader : IDisposable
{
    private readonly AccessTracker tracker;
    private readonly PluginLoadContext context;
    private ReflectionHook? hook;
    private string assemblyName = string.Empty;

    public PluginLoader(AccessTracker tracker, string contextName, string pluginPath)
    {
        this.tracker = tracker;
        context = new PluginLoadContext(contextName, pluginPath, tracker);
    }

    public string AssemblyName => assemblyName;

    public ReflectionHook InstallHook()
    {
        hook ??= new ReflectionHook(tracker, context);
        return hook;
    }

    public Assembly Load(string pluginPath)
    {
        var asmName = AssemblyNameFromPath(pluginPath);
        assemblyName = asmName.Name ?? Path.GetFileNameWithoutExtension(pluginPath);
        return context.LoadFromAssemblyPath(Path.GetFullPath(pluginPath));
    }

    public (Type? idalamudPlugin, Type? asyncPlugin, Type? basePlugin) ResolvePluginContractTypes()
    {
        var shared = DalamudContract.Assembly;
        return (
            shared.GetType("Dalamud.Plugin.IDalamudPlugin", throwOnError: true),
            shared.GetType("Dalamud.Plugin.IAsyncDalamudPlugin"),
            shared.GetType("Dalamud.Plugin.BasePlugin"));
    }

    public Type? FindPluginType(Assembly assembly, out string? notFoundReason)
    {
        notFoundReason = null;
        Type? sync = null, async = null, basePlugin = null;
        var (idp, iap, bp) = ResolvePluginContractTypes();

        IEnumerable<Type?> types;
        try
        {
            types = assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            foreach (var le in ex.LoaderExceptions.Take(12))
                Console.Error.WriteLine($"  [type-load] {le.GetType().Name}: {le.Message}");
            types = ex.Types;
        }

        foreach (var type in types)
        {
            if (type is null || type.IsAbstract || type.IsInterface) continue;
            if (idp.IsAssignableFrom(type)) sync ??= type;
            else if (iap is not null && iap.IsAssignableFrom(type)) async ??= type;
            else if (bp is not null && bp.IsAssignableFrom(type)) basePlugin ??= type;
        }

        if (sync is not null) return sync;
        if (async is not null) return async;
        if (basePlugin is not null) return basePlugin;

        notFoundReason = "no type implementing the shared API-15 IDalamudPlugin/IAsyncDalamudPlugin contract was found";
        return null;
    }

    public void Unload()
    {
        try { context.Unload(); } catch { }
    }

    public void Dispose()
    {
        hook?.Dispose();
        hook = null;
    }

    private static System.Reflection.AssemblyName AssemblyNameFromPath(string pluginPath) => System.Reflection.AssemblyName.GetAssemblyName(pluginPath);

    private sealed class PluginLoadContext : AssemblyLoadContext
    {
        private readonly AssemblyDependencyResolver? resolver;
        private readonly string pluginDirectory;
        private readonly AccessTracker tracker;
        private readonly Assembly sharedDalamud = DalamudContract.Assembly;

        public PluginLoadContext(string name, string pluginPath, AccessTracker tracker)
            : base(name, isCollectible: true)
        {
            this.tracker = tracker;
            pluginDirectory = Path.GetDirectoryName(Path.GetFullPath(pluginPath)) ?? AppContext.BaseDirectory;
            try { resolver = new AssemblyDependencyResolver(Path.GetFullPath(pluginPath)); } catch { }
        }

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            if (string.Equals(assemblyName.Name, sharedDalamud.GetName().Name, StringComparison.OrdinalIgnoreCase))
                return sharedDalamud;

            var trusted = DalamudContract.TryResolveTrusted(assemblyName);
            if (trusted is not null)
                return trusted;

            var resolved = resolver?.ResolveAssemblyToPath(assemblyName);
            if (resolved is null && !string.IsNullOrWhiteSpace(assemblyName.Name))
            {
                var sibling = Path.Combine(pluginDirectory, assemblyName.Name + ".dll");
                if (File.Exists(sibling)) resolved = sibling;
            }

            if (resolved is null)
                return null; // framework/default-context resolution may satisfy it.

            tracker.ReflectiveLoad(assemblyName.FullName ?? assemblyName.Name ?? "unknown", resolved, resolved: true);
            return LoadFromAssemblyPath(resolved);
        }

        protected override nint LoadUnmanagedDll(string unmanagedDllName)
        {
            var resolved = resolver?.ResolveUnmanagedDllToPath(unmanagedDllName);
            if (resolved is null)
            {
                foreach (var name in new[] { unmanagedDllName, $"lib{unmanagedDllName}.so", $"{unmanagedDllName}.so" })
                {
                    var sibling = Path.Combine(pluginDirectory, name);
                    if (File.Exists(sibling)) { resolved = sibling; break; }
                }
            }

            if (resolved is null)
                return nint.Zero;

            tracker.ReflectiveLoad(unmanagedDllName, resolved, resolved: true);
            return LoadUnmanagedDllFromPath(resolved);
        }
    }
}
