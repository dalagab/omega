using System.Collections;
using System.Reflection;
using Dalamud.Plugin;

namespace Dalagab.Omega;

/// <summary>
/// Disables Omega through Dalamud's own persisted plugin/profile state after the first-use EULA is
/// declined. The request is deferred until the next framework tick so the ImGui popup can close
/// cleanly before Dalamud unloads the plugin that owns it.
/// </summary>
internal sealed class OmegaSelfDisableService
{
    public void Request()
        => _ = DisableAfterUiFrameAsync();

    private static async Task DisableAfterUiFrameAsync()
    {
        try
        {
            await Plugin.Framework.DelayTicks(1).ConfigureAwait(false);
            await PersistDisabledStateAndUnloadAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Plugin.Log.Error(ex, "Omega could not disable itself after the EULA was declined.");
        }
    }

    private static async Task PersistDisabledStateAndUnloadAsync()
    {
        var dalamudAssembly = typeof(IDalamudPluginInterface).Assembly;
        var pluginManagerType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.PluginManager");
        var profileManagerType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.Profiles.ProfileManager");
        var disposalModeType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.Types.PluginLoaderDisposalMode");
        var serviceOpenType = RequireType(dalamudAssembly, "Dalamud.Service`1");

        var pluginManager = GetInternalService(serviceOpenType, pluginManagerType);
        var profileManager = GetInternalService(serviceOpenType, profileManagerType);
        var localPlugin = FindInstalledPlugin(pluginManager, pluginManagerType, Plugin.PluginInterface.InternalName)
            ?? throw new InvalidOperationException("Omega disappeared from Dalamud's installed-plugin list before it could be disabled.");

        var localType = localPlugin.GetType();
        var internalName = Text(localType.GetProperty("InternalName", AllInstance)?.GetValue(localPlugin), Plugin.PluginInterface.InternalName);
        var workingPluginId = GuidValue(localType.GetProperty("EffectiveWorkingPluginId", AllInstance)?.GetValue(localPlugin));
        if (workingPluginId == Guid.Empty)
            throw new InvalidOperationException("Dalamud did not expose Omega's effective plugin identity.");

        var profiles = profileManagerType.GetProperty("Profiles", AllInstance)?.GetValue(profileManager) as IEnumerable
            ?? throw new MissingMemberException("Dalamud ProfileManager.Profiles was not available.");

        var changedProfiles = 0;
        foreach (var profile in profiles.Cast<object>())
        {
            var wantsPlugin = profile.GetType().GetMethod(
                "WantsPlugin",
                AllInstance,
                binder: null,
                types: [typeof(Guid)],
                modifiers: null);
            if (wantsPlugin?.Invoke(profile, [workingPluginId]) is null)
                continue;

            var addOrUpdate = profile.GetType().GetMethod(
                "AddOrUpdateAsync",
                AllInstance,
                binder: null,
                types: [typeof(Guid), typeof(string), typeof(bool), typeof(bool)],
                modifiers: null)
                ?? throw new MissingMethodException("Dalamud Profile.AddOrUpdateAsync(Guid, string, bool, bool) was not found.");
            var task = addOrUpdate.Invoke(profile, [workingPluginId, internalName, false, false]) as Task
                ?? throw new InvalidOperationException("Dalamud profile disable did not return a Task.");
            await task.ConfigureAwait(false);
            changedProfiles++;
        }

        // Developer plugins can exist before a profile declaration is available. In that case also
        // turn off their explicit boot/reload switches so declining the agreement still behaves as a
        // persistent disable rather than a one-session hide.
        var isDev = Bool(localType.GetProperty("IsDev", AllInstance)?.GetValue(localPlugin));
        if (isDev)
        {
            SetBoolProperty(localPlugin, "AutomaticReload", false);
            SetBoolProperty(localPlugin, "StartOnBoot", false);
            QueueDalamudConfigurationSave(dalamudAssembly, serviceOpenType);
        }

        if (changedProfiles == 0 && !isDev)
            Plugin.Log.Warning("Omega was not present in a Dalamud profile while declining the EULA; unloading it for this session anyway.");

        var state = Text(localType.GetProperty("State", AllInstance)?.GetValue(localPlugin));
        if (state is not ("Loaded" or "LoadError" or "UnloadError"))
            return;

        var unload = localType.GetMethod("UnloadAsync", AllInstance)
            ?? throw new MissingMethodException("Dalamud LocalPlugin.UnloadAsync was not found.");
        var waitMode = Enum.Parse(disposalModeType, "WaitBeforeDispose");
        _ = unload.Invoke(localPlugin, [waitMode]) as Task
            ?? throw new InvalidOperationException("Dalamud plugin unload invocation did not return a Task.");

        // Do not await our own unload. The persistent disabled state has already been written and
        // Dalamud now owns the remaining lifecycle. Awaiting here would keep Omega's load context
        // alive solely for a continuation after it has deliberately been unloaded.
    }

    private static object? FindInstalledPlugin(object pluginManager, Type pluginManagerType, string internalName)
    {
        var installed = pluginManagerType.GetProperty("InstalledPlugins", AllInstance)?.GetValue(pluginManager) as IEnumerable
            ?? throw new MissingMemberException("Dalamud PluginManager.InstalledPlugins was not available.");
        return installed.Cast<object>().FirstOrDefault(candidate =>
            string.Equals(
                Text(candidate.GetType().GetProperty("InternalName", AllInstance)?.GetValue(candidate)),
                internalName,
                StringComparison.OrdinalIgnoreCase));
    }

    private static void QueueDalamudConfigurationSave(Assembly dalamudAssembly, Type serviceOpenType)
    {
        try
        {
            var configurationType = RequireType(dalamudAssembly, "Dalamud.Configuration.Internal.DalamudConfiguration");
            var configuration = GetInternalService(serviceOpenType, configurationType);
            configurationType.GetMethod("QueueSave", AllInstance)?.Invoke(configuration, null);
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega could not explicitly queue Dalamud's dev-plugin settings save after EULA decline.");
        }
    }

    private static void SetBoolProperty(object target, string propertyName, bool value)
    {
        var property = target.GetType().GetProperty(propertyName, AllInstance);
        if (property?.CanWrite == true && property.PropertyType == typeof(bool))
            property.SetValue(target, value);
    }

    private static object GetInternalService(Type serviceOpenType, Type serviceType)
    {
        var closed = serviceOpenType.MakeGenericType(serviceType);
        var get = closed.GetMethod("Get", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMethodException($"Dalamud service locator could not resolve {serviceType.Name}.");
        return get.Invoke(null, null) ?? throw new InvalidOperationException($"Dalamud service {serviceType.Name} was null.");
    }

    private static Type RequireType(Assembly assembly, string fullName)
        => assembly.GetType(fullName, throwOnError: false) ?? throw new TypeLoadException($"Dalamud internal type changed: {fullName}");

    private static Guid GuidValue(object? value)
        => value is Guid guid ? guid : Guid.TryParse(value?.ToString(), out var parsed) ? parsed : Guid.Empty;

    private static bool Bool(object? value)
        => value is bool result && result;

    private static string Text(object? value, string fallback = "")
        => value?.ToString() ?? fallback;

    private const BindingFlags AllInstance = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
}
