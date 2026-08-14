using System.Collections;
using System.Reflection;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed record DalamudCollectionPlugin(
    string InternalName,
    Guid WorkingPluginId,
    bool WantsEnabled);

internal sealed record DalamudPluginCollection(
    Guid Id,
    string Name,
    bool IsEnabled,
    bool IsDefault,
    IReadOnlyList<DalamudCollectionPlugin> Plugins);

internal sealed record DalamudCollectionOperationResult(bool Success, string Message);

/// <summary>
/// Provides a fail-closed compatibility bridge to Dalamud's plugin collections/profiles.
/// Omega only mirrors collection membership/state and delegates state changes back to Dalamud;
/// it does not persist or apply a second plugin-profile model of its own.
/// </summary>
internal sealed class DalamudProfileBridge
{
    public IReadOnlyList<DalamudPluginCollection> ReadCollections()
    {
        try
        {
            var manager = GetProfileManager();
            var profiles = Get(manager, "Profiles") as IEnumerable;
            if (profiles is null)
                return [];

            return profiles.Cast<object>()
                .Select(MapCollection)
                .OrderByDescending(x => x.IsDefault)
                .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega could not read Dalamud plugin collections.");
            return [];
        }
    }

    public async Task<DalamudCollectionOperationResult> SetCollectionEnabledAsync(Guid id, bool enabled)
    {
        try
        {
            var manager = GetProfileManager();
            if (Bool(Get(manager, "IsBusy")))
                return new(false, "Dalamud is already applying collection changes.");

            var profile = FindProfile(manager, id);
            if (profile is null)
                return new(false, "The Dalamud collection no longer exists.");
            if (Bool(Get(profile, "IsDefaultProfile")))
                return new(false, "The default Dalamud collection is always enabled.");
            if (Bool(Get(profile, "IsEnabled")) == enabled)
                return new(true, $"{Text(Get(profile, "Name"), "Collection")} is already {(enabled ? "on" : "off")}.");

            var method = profile.GetType().GetMethod(
                "SetStateAsync",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null,
                types: [typeof(bool), typeof(bool)],
                modifiers: null)
                ?? throw new MissingMethodException("Dalamud Profile.SetStateAsync(bool, bool) was not found.");
            var task = method.Invoke(profile, [enabled, true]) as Task
                ?? throw new InvalidOperationException("Dalamud collection state change did not return a Task.");
            await task.ConfigureAwait(false);
            return new(true, $"{Text(Get(profile, "Name"), "Collection")} turned {(enabled ? "on" : "off")}.");
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not change Dalamud collection {CollectionId}.", id);
            return new(false, $"Dalamud could not change this collection: {RootMessage(ex)}");
        }
    }

    private static DalamudPluginCollection MapCollection(object profile)
    {
        var plugins = Get(profile, "Plugins") as IEnumerable;
        var entries = plugins is null
            ? []
            : plugins.Cast<object>().Select(MapPlugin).ToArray();
        return new(
            GuidValue(Get(profile, "Guid")),
            Text(Get(profile, "Name"), "Collection"),
            Bool(Get(profile, "IsEnabled")),
            Bool(Get(profile, "IsDefaultProfile")),
            entries);
    }

    private static DalamudCollectionPlugin MapPlugin(object entry)
        => new(
            Text(Get(entry, "InternalName"), "Unknown plugin"),
            GuidValue(Get(entry, "WorkingPluginId")),
            Bool(Get(entry, "IsEnabled")));

    private static object? FindProfile(object manager, Guid id)
    {
        var profiles = Get(manager, "Profiles") as IEnumerable;
        return profiles?.Cast<object>().FirstOrDefault(x => GuidValue(Get(x, "Guid")) == id);
    }

    private static object GetProfileManager()
    {
        var assembly = typeof(IDalamudPluginInterface).Assembly;
        var managerType = RequireType(assembly, "Dalamud.Plugin.Internal.Profiles.ProfileManager");
        var serviceOpenType = RequireType(assembly, "Dalamud.Service`1");
        var serviceType = serviceOpenType.MakeGenericType(managerType);
        var get = serviceType.GetMethod("Get", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMethodException("Dalamud service locator could not resolve ProfileManager.");
        return get.Invoke(null, null) ?? throw new InvalidOperationException("Dalamud ProfileManager service was null.");
    }

    private static object? Get(object? target, string property)
        => target?.GetType().GetProperty(property, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)?.GetValue(target);

    private static Type RequireType(Assembly assembly, string name)
        => assembly.GetType(name, throwOnError: false) ?? throw new TypeLoadException($"Dalamud internal type changed: {name}");

    private static string Text(object? value, string fallback = "")
        => value?.ToString() is { Length: > 0 } text ? text : fallback;

    private static bool Bool(object? value) => value is bool flag && flag;

    private static Guid GuidValue(object? value)
        => value is Guid guid ? guid : Guid.TryParse(value?.ToString(), out var parsed) ? parsed : Guid.Empty;

    private static string RootMessage(Exception ex)
    {
        while (ex.InnerException is not null)
            ex = ex.InnerException;
        return ex.Message;
    }
}
