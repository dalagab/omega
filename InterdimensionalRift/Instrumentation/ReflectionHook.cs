using System.Reflection;
using System.Runtime.Loader;

namespace InterdimensionalRift.Instrumentation;

/// <summary>
/// Captures every assembly resolution attempt that could plausibly be
/// caused by the plugin, regardless of which <see cref="AssemblyLoadContext"/>
/// the runtime picks:
///
/// <list type="bullet">
///   <item>plugin's own collectible ALC — covers <c>Assembly.Load(name)</c>,
///         <c>LoadFromAssemblyName</c>, transitive resolution, etc.</item>
///   <item>the default ALC — covers <c>Assembly.LoadFile(path)</c> /
///         <c>LoadFrom</c> which bypass the calling context and land
///         in the shared default context.</item>
/// </list>
/// <para>
/// .NET 10's <see cref="AssemblyLoadContext"/> only exposes the
/// <see cref="AssemblyLoadContext.Resolving"/> event publicly; the
/// <c>Loading</c> hook is internal. <c>Resolving</c> fires for every
/// resolution attempt, which is the more useful signal anyway because
/// it captures attempts even when they ultimately fail.
/// </para>
/// </summary>
public sealed class ReflectionHook : IDisposable
{
    private readonly AccessTracker _tracker;
    private readonly AssemblyLoadContext _pluginContext;
    private readonly AssemblyLoadContext _defaultContext = AssemblyLoadContext.Default;
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public ReflectionHook(AccessTracker tracker, AssemblyLoadContext pluginContext)
    {
        _tracker = tracker;
        _pluginContext = pluginContext;
        _pluginContext.Resolving += OnResolving;
        _defaultContext.Resolving += OnResolving;
        AppDomain.CurrentDomain.AssemblyLoad += OnAssemblyLoad;
    }

    private Assembly? OnResolving(AssemblyLoadContext ctx, AssemblyName name)
    {
        Emit(name.FullName, path: null);
        return null; // let the ALC's default resolver run
    }

    private void OnAssemblyLoad(object? sender, AssemblyLoadEventArgs args)
    {
        var assembly = args.LoadedAssembly;
        string? location;
        try { location = string.IsNullOrWhiteSpace(assembly.Location) ? null : assembly.Location; }
        catch { location = null; }
        Emit(assembly.FullName, location, resolved: true);
    }

    private void Emit(string? fullName, string? path, bool resolved = false)
    {
        if (string.IsNullOrEmpty(fullName))
        {
            return;
        }
        lock (_gate)
        {
            var key = $"{fullName}|{path}|{resolved}";
            if (!_seen.Add(key))
            {
                return;
            }
        }
        _tracker.AssemblyLoad(fullName, path, resolved);
    }

    public void Dispose()
    {
        _pluginContext.Resolving -= OnResolving;
        _defaultContext.Resolving -= OnResolving;
        AppDomain.CurrentDomain.AssemblyLoad -= OnAssemblyLoad;
    }
}
