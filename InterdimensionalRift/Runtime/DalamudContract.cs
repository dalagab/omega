using System.Reflection;
using System.Runtime.Loader;

namespace InterdimensionalRift.Runtime;

/// <summary>
/// Loads the frozen, trusted Dalamud runtime only as a CLR contract/type-identity source.
/// Rift never instantiates Dalamud's host/game services. Plugin-facing services are
/// instrumentation proxies created by RuntimeServiceRegistry.
/// </summary>
public static class DalamudContract
{
    private static readonly object Gate = new();
    private static Assembly? dalamud;
    private static string? contractDirectory;

    public static Assembly Assembly
    {
        get
        {
            EnsureLoaded();
            return dalamud!;
        }
    }

    public static string ContractDirectory
    {
        get
        {
            EnsureLoaded();
            return contractDirectory!;
        }
    }

    public static void EnsureLoaded()
    {
        if (dalamud is not null)
            return;

        lock (Gate)
        {
            if (dalamud is not null)
                return;

            var configured = Environment.GetEnvironmentVariable("RIFT_DALAMUD_CONTRACT_DIR");
            if (string.IsNullOrWhiteSpace(configured))
                configured = Environment.GetEnvironmentVariable("RIFT_HOOKS");
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException("Rift requires RIFT_DALAMUD_CONTRACT_DIR (or RIFT_HOOKS) pointing at a frozen trusted Dalamud runtime.");

            var directory = Path.GetFullPath(configured);
            var path = Path.Combine(directory, "Dalamud.dll");
            if (!File.Exists(path))
                throw new FileNotFoundException("Frozen Dalamud contract assembly was not found.", path);

            contractDirectory = directory;
            AssemblyLoadContext.Default.Resolving += ResolveTrustedSibling;

            dalamud = AssemblyLoadContext.Default.Assemblies.FirstOrDefault(a =>
                string.Equals(a.GetName().Name, "Dalamud", StringComparison.OrdinalIgnoreCase));
            dalamud ??= AssemblyLoadContext.Default.LoadFromAssemblyPath(path);
        }
    }

    /// <summary>
    /// Gives a plugin ALC the exact trusted assembly identity for Dalamud and for
    /// dependencies that are part of the frozen runtime. Artifact-local dependencies
    /// remain plugin-local when no trusted sibling exists.
    /// </summary>
    public static Assembly? TryResolveTrusted(AssemblyName name)
    {
        EnsureLoaded();
        if (string.IsNullOrWhiteSpace(name.Name))
            return null;

        var loaded = AssemblyLoadContext.Default.Assemblies.FirstOrDefault(a =>
            string.Equals(a.GetName().Name, name.Name, StringComparison.OrdinalIgnoreCase));
        if (loaded is not null)
            return loaded;

        var candidate = Path.Combine(contractDirectory!, name.Name + ".dll");
        if (!File.Exists(candidate))
            return null;

        try
        {
            return AssemblyLoadContext.Default.LoadFromAssemblyPath(candidate);
        }
        catch (FileLoadException)
        {
            return AssemblyLoadContext.Default.Assemblies.FirstOrDefault(a =>
                string.Equals(a.GetName().Name, name.Name, StringComparison.OrdinalIgnoreCase));
        }
    }

    private static Assembly? ResolveTrustedSibling(AssemblyLoadContext context, AssemblyName name)
    {
        if (string.IsNullOrWhiteSpace(contractDirectory) || string.IsNullOrWhiteSpace(name.Name))
            return null;
        var candidate = Path.Combine(contractDirectory, name.Name + ".dll");
        return File.Exists(candidate) ? context.LoadFromAssemblyPath(candidate) : null;
    }
}
