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


    public async Task<DalamudCollectionOperationResult> AddPluginToCollectionAsync(Guid id, string internalName)
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
                return new(false, "The default Dalamud collection is managed automatically.");

            var declaration = FindPluginDeclaration(manager, internalName);
            if (declaration is null || declaration.Value.WorkingPluginId == Guid.Empty)
                return new(false, $"Dalamud could not resolve the installed plugin identity for {internalName}.");

            if (ProfileContainsPlugin(profile, declaration.Value.WorkingPluginId))
                return new(true, $"{internalName} is already in {Text(Get(profile, "Name"), "Collection")}.");

            // Named Dalamud profiles intentionally overlap. Adding membership here only touches
            // the selected profile; existing membership in other named profiles is preserved.
            await InvokeProfileAddOrUpdateAsync(
                profile,
                declaration.Value.WorkingPluginId,
                internalName,
                state: true,
                apply: true).ConfigureAwait(false);
            return new(true, $"Added {internalName} to {Text(Get(profile, "Name"), "Collection")}. Existing named collection memberships were kept.");
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not add {Plugin} to Dalamud collection {CollectionId}.", internalName, id);
            return new(false, $"Dalamud could not add this plugin to the collection: {RootMessage(ex)}");
        }
    }

    public async Task<DalamudCollectionOperationResult> RemovePluginFromCollectionAsync(Guid id, Guid workingPluginId)
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
                return new(false, "The default Dalamud collection is managed automatically.");
            if (!ProfileContainsPlugin(profile, workingPluginId))
                return new(true, "The plugin is no longer in this collection.");

            var internalName = FindProfilePluginName(profile, workingPluginId);
            await InvokeProfileRemoveAsync(profile, workingPluginId, apply: true).ConfigureAwait(false);
            return new(true, $"Removed {internalName} from {Text(Get(profile, "Name"), "Collection")}.");
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not remove plugin {PluginId} from Dalamud collection {CollectionId}.", workingPluginId, id);
            return new(false, $"Dalamud could not remove this plugin from the collection: {RootMessage(ex)}");
        }
    }

    public async Task<DalamudCollectionOperationResult> SetPluginStateInCollectionAsync(
        Guid id,
        Guid workingPluginId,
        string internalName,
        bool enabled)
    {
        try
        {
            var manager = GetProfileManager();
            if (Bool(Get(manager, "IsBusy")))
                return new(false, "Dalamud is already applying collection changes.");

            var profile = FindProfile(manager, id);
            if (profile is null)
                return new(false, "The Dalamud collection no longer exists.");
            if (!ProfileContainsPlugin(profile, workingPluginId))
                return new(false, "The plugin is no longer in this collection.");

            await InvokeProfileAddOrUpdateAsync(profile, workingPluginId, internalName, enabled, apply: true).ConfigureAwait(false);
            return new(true, $"{internalName} is now {(enabled ? "enabled" : "disabled")} in {Text(Get(profile, "Name"), "Collection")}.");
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not change plugin {PluginId} in Dalamud collection {CollectionId}.", workingPluginId, id);
            return new(false, $"Dalamud could not change this plugin in the collection: {RootMessage(ex)}");
        }
    }

    private static (Guid WorkingPluginId, bool WantsEnabled)? FindPluginDeclaration(object manager, string internalName)
    {
        var profiles = Get(manager, "Profiles") as IEnumerable;
        if (profiles is null)
            return null;

        foreach (var profile in profiles.Cast<object>())
        {
            var plugins = Get(profile, "Plugins") as IEnumerable;
            if (plugins is null)
                continue;

            foreach (var entry in plugins.Cast<object>())
            {
                if (!string.Equals(Text(Get(entry, "InternalName")), internalName, StringComparison.OrdinalIgnoreCase))
                    continue;
                var id = GuidValue(Get(entry, "WorkingPluginId"));
                if (id != Guid.Empty)
                    return (id, Bool(Get(entry, "IsEnabled")));
            }
        }

        return null;
    }

    private static bool ProfileContainsPlugin(object profile, Guid workingPluginId)
    {
        var plugins = Get(profile, "Plugins") as IEnumerable;
        return plugins?.Cast<object>().Any(x => GuidValue(Get(x, "WorkingPluginId")) == workingPluginId) == true;
    }

    private static string FindProfilePluginName(object profile, Guid workingPluginId)
    {
        var plugins = Get(profile, "Plugins") as IEnumerable;
        var entry = plugins?.Cast<object>().FirstOrDefault(x => GuidValue(Get(x, "WorkingPluginId")) == workingPluginId);
        return Text(Get(entry, "InternalName"), "plugin");
    }

    private static async Task InvokeProfileAddOrUpdateAsync(
        object profile,
        Guid workingPluginId,
        string internalName,
        bool state,
        bool apply)
    {
        var method = profile.GetType().GetMethod(
            "AddOrUpdateAsync",
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            types: [typeof(Guid), typeof(string), typeof(bool), typeof(bool)],
            modifiers: null)
            ?? throw new MissingMethodException("Dalamud Profile.AddOrUpdateAsync(Guid, string, bool, bool) was not found.");
        var task = method.Invoke(profile, [workingPluginId, internalName, state, apply]) as Task
            ?? throw new InvalidOperationException("Dalamud collection plugin change did not return a Task.");
        await task.ConfigureAwait(false);
    }

    private static async Task InvokeProfileRemoveAsync(object profile, Guid workingPluginId, bool apply)
    {
        var method = profile.GetType().GetMethod(
            "RemoveAsync",
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            types: [typeof(Guid), typeof(bool), typeof(bool)],
            modifiers: null)
            ?? throw new MissingMethodException("Dalamud Profile.RemoveAsync(Guid, bool, bool) was not found.");
        var task = method.Invoke(profile, [workingPluginId, apply, true]) as Task
            ?? throw new InvalidOperationException("Dalamud collection plugin removal did not return a Task.");
        await task.ConfigureAwait(false);
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
