using System.Collections;
using System.Reflection;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal enum RepositoryBridgeOutcome
{
    Added,
    AlreadyPresent,
    Updated,
    Removed,
    NotFound,
    InvalidUrl,
    Failed,
}

internal sealed record RepositoryBridgeResult(
    RepositoryBridgeOutcome Outcome,
    string Message,
    bool OwnedByOmega = false)
{
    public bool Success => Outcome is RepositoryBridgeOutcome.Added or RepositoryBridgeOutcome.AlreadyPresent or RepositoryBridgeOutcome.Updated or RepositoryBridgeOutcome.Removed;
}

internal sealed record DalamudRepositoryState(bool Available, bool Present, bool Enabled, string Message);

/// <summary>
/// Isolates Omega's API-15 reflection access to Dalamud's third-party repository configuration.
/// Omega never edits files directly; it mutates the live DalamudConfiguration object, queues a save,
/// and asks PluginManager to rebuild/reload repositories through its own code path.
/// </summary>
internal sealed class DalamudRepositoryBridge
{
    private const BindingFlags AllInstance = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;

    public DalamudRepositoryState GetState(string url)
    {
        try
        {
            var normalized = NormalizeUrl(url);
            var context = ResolveContext();
            var existing = FindRepositorySetting(context.RepositoryList, normalized);
            if (existing is null)
                return new DalamudRepositoryState(true, false, false, "Not registered in Dalamud");

            return new DalamudRepositoryState(
                true,
                true,
                ReadBool(existing, "IsEnabled"),
                ReadBool(existing, "IsEnabled") ? "Registered and enabled in Dalamud" : "Registered but disabled in Dalamud");
        }
        catch (Exception ex)
        {
            return new DalamudRepositoryState(false, false, false, $"Dalamud repository integration unavailable: {ex.GetBaseException().Message}");
        }
    }

    public async Task<RepositoryBridgeResult> EnsureIntegratedAsync(string url, bool enabled, CancellationToken cancellationToken = default)
    {
        if (!TryNormalizeUrl(url, out var normalized, out var error))
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.InvalidUrl, error);

        try
        {
            var context = ResolveContext();
            var existing = FindRepositorySetting(context.RepositoryList, normalized);
            if (existing is not null)
            {
                return new RepositoryBridgeResult(
                    RepositoryBridgeOutcome.AlreadyPresent,
                    "Repository already exists in Dalamud. Omega will treat it as user-managed and will not modify or remove it.",
                    OwnedByOmega: false);
            }

            var setting = Activator.CreateInstance(context.RepositorySettingsType, nonPublic: true)
                ?? throw new InvalidOperationException("Could not construct Dalamud ThirdPartyRepoSettings.");
            Set(setting, "Url", normalized);
            Set(setting, "IsEnabled", enabled);
            context.RepositoryList.Add(setting);
            QueueSave(context.Configuration);

            try
            {
                await RefreshDalamudRepositoriesAsync(context.PluginManager, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                context.RepositoryList.Remove(setting);
                QueueSave(context.Configuration);
                throw;
            }

            return new RepositoryBridgeResult(
                RepositoryBridgeOutcome.Added,
                enabled
                    ? "Repository added to Dalamud and enabled. Dalamud now owns normal servicing/update discovery for plugins from this feed."
                    : "Repository added to Dalamud but left disabled.",
                OwnedByOmega: true);
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Failed to integrate repository {Repository} with Dalamud", url);
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.Failed, $"Dalamud repository integration failed: {ex.GetBaseException().Message}");
        }
    }

    /// <summary>
    /// Enables a pre-existing Dalamud repository only after the user explicitly selected that
    /// repository in Omega's install confirmation. Ownership remains with the user; Omega will
    /// not subsequently toggle or remove the repository as if it were Omega-managed.
    /// </summary>
    public async Task<RepositoryBridgeResult> EnableExistingForExplicitInstallAsync(
        string url,
        CancellationToken cancellationToken = default)
    {
        if (!TryNormalizeUrl(url, out var normalized, out var error))
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.InvalidUrl, error);

        try
        {
            var context = ResolveContext();
            var existing = FindRepositorySetting(context.RepositoryList, normalized);
            if (existing is null)
                return new RepositoryBridgeResult(RepositoryBridgeOutcome.NotFound, "The selected repository is no longer present in Dalamud.");
            if (ReadBool(existing, "IsEnabled"))
                return new RepositoryBridgeResult(RepositoryBridgeOutcome.AlreadyPresent, "Repository is already enabled in Dalamud.", OwnedByOmega: false);

            Set(existing, "IsEnabled", true);
            QueueSave(context.Configuration);
            try
            {
                await RefreshDalamudRepositoriesAsync(context.PluginManager, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                Set(existing, "IsEnabled", false);
                QueueSave(context.Configuration);
                throw;
            }

            return new RepositoryBridgeResult(
                RepositoryBridgeOutcome.Updated,
                "Selected repository enabled in Dalamud for this installation.",
                OwnedByOmega: false);
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Failed to enable explicitly selected Dalamud repository {Repository}", url);
            return new RepositoryBridgeResult(
                RepositoryBridgeOutcome.Failed,
                $"Dalamud could not enable the selected repository: {ex.GetBaseException().Message}");
        }
    }

    public async Task<RepositoryBridgeResult> SetManagedEnabledAsync(string url, bool enabled, CancellationToken cancellationToken = default)
    {
        if (!TryNormalizeUrl(url, out var normalized, out var error))
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.InvalidUrl, error);

        try
        {
            var context = ResolveContext();
            var existing = FindRepositorySetting(context.RepositoryList, normalized);
            if (existing is null)
                return new RepositoryBridgeResult(RepositoryBridgeOutcome.NotFound, "The Omega-managed repository is no longer present in Dalamud.");

            var previous = ReadBool(existing, "IsEnabled");
            if (previous == enabled)
                return new RepositoryBridgeResult(RepositoryBridgeOutcome.Updated, enabled ? "Repository is already enabled in Dalamud." : "Repository is already disabled in Dalamud.", OwnedByOmega: true);

            Set(existing, "IsEnabled", enabled);
            QueueSave(context.Configuration);
            try
            {
                await RefreshDalamudRepositoriesAsync(context.PluginManager, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                Set(existing, "IsEnabled", previous);
                QueueSave(context.Configuration);
                throw;
            }

            return new RepositoryBridgeResult(
                RepositoryBridgeOutcome.Updated,
                enabled ? "Omega-managed repository enabled in Dalamud." : "Omega-managed repository disabled in Dalamud.",
                OwnedByOmega: true);
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Failed to update Dalamud repository state for {Repository}", url);
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.Failed, $"Could not update Dalamud repository state: {ex.GetBaseException().Message}");
        }
    }

    public async Task<RepositoryBridgeResult> RemoveManagedAsync(string url, CancellationToken cancellationToken = default)
    {
        if (!TryNormalizeUrl(url, out var normalized, out var error))
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.InvalidUrl, error);

        try
        {
            var context = ResolveContext();
            var existing = FindRepositorySetting(context.RepositoryList, normalized);
            if (existing is null)
                return new RepositoryBridgeResult(RepositoryBridgeOutcome.Removed, "Repository was already absent from Dalamud.");

            var index = context.RepositoryList.IndexOf(existing);
            context.RepositoryList.Remove(existing);
            QueueSave(context.Configuration);
            try
            {
                await RefreshDalamudRepositoriesAsync(context.PluginManager, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                if (index >= 0 && index <= context.RepositoryList.Count)
                    context.RepositoryList.Insert(index, existing);
                else
                    context.RepositoryList.Add(existing);
                QueueSave(context.Configuration);
                throw;
            }

            return new RepositoryBridgeResult(RepositoryBridgeOutcome.Removed, "Omega-managed repository removed from Dalamud.");
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Failed to remove Dalamud repository {Repository}", url);
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.Failed, $"Could not remove Dalamud repository: {ex.GetBaseException().Message}");
        }
    }

    private static ReflectionContext ResolveContext()
    {
        var dalamudAssembly = typeof(IDalamudPluginInterface).Assembly;
        var serviceOpenType = RequireType(dalamudAssembly, "Dalamud.Service`1");
        var configurationType = RequireType(dalamudAssembly, "Dalamud.Configuration.Internal.DalamudConfiguration");
        var repositorySettingsType = RequireType(dalamudAssembly, "Dalamud.Configuration.ThirdPartyRepoSettings");
        var pluginManagerType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.PluginManager");

        var configuration = GetInternalService(serviceOpenType, configurationType);
        var pluginManager = GetInternalService(serviceOpenType, pluginManagerType);
        var listProperty = configurationType.GetProperty("ThirdRepoList", AllInstance)
            ?? throw new MissingMemberException("DalamudConfiguration.ThirdRepoList was not found.");
        var list = listProperty.GetValue(configuration) as IList
            ?? throw new InvalidOperationException("DalamudConfiguration.ThirdRepoList is not an IList.");

        return new ReflectionContext(configuration, pluginManager, repositorySettingsType, list);
    }

    private static object? FindRepositorySetting(IList list, string normalizedUrl)
    {
        foreach (var item in list)
        {
            if (item is null)
                continue;
            var candidate = item.GetType().GetProperty("Url", AllInstance)?.GetValue(item) as string;
            if (string.IsNullOrWhiteSpace(candidate))
                continue;
            if (string.Equals(NormalizeUrl(candidate), normalizedUrl, StringComparison.OrdinalIgnoreCase))
                return item;
        }

        return null;
    }

    private static async Task RefreshDalamudRepositoriesAsync(object pluginManager, CancellationToken cancellationToken)
    {
        var method = pluginManager.GetType().GetMethod("SetPluginReposFromConfigAsync", AllInstance, null, [typeof(bool)], null)
            ?? throw new MissingMethodException("Dalamud PluginManager.SetPluginReposFromConfigAsync(bool) was not found.");
        var task = method.Invoke(pluginManager, [true]) as Task
            ?? throw new InvalidOperationException("Dalamud repository refresh invocation did not return a Task.");
        await task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void QueueSave(object configuration)
    {
        var method = configuration.GetType().GetMethod("QueueSave", AllInstance, null, Type.EmptyTypes, null)
            ?? throw new MissingMethodException("DalamudConfiguration.QueueSave() was not found.");
        method.Invoke(configuration, null);
    }

    private static bool ReadBool(object target, string propertyName)
        => target.GetType().GetProperty(propertyName, AllInstance)?.GetValue(target) as bool? ?? false;

    private static void Set(object target, string propertyName, object? value)
    {
        var property = target.GetType().GetProperty(propertyName, AllInstance)
            ?? throw new MissingMemberException(target.GetType().FullName, propertyName);
        if (!property.CanWrite)
            throw new InvalidOperationException($"Dalamud property {target.GetType().Name}.{propertyName} is not writable.");
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

    private static bool TryNormalizeUrl(string url, out string normalized, out string error)
    {
        normalized = string.Empty;
        error = string.Empty;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            error = "Repository URL must be an absolute HTTPS URL.";
            return false;
        }

        normalized = NormalizeUrl(uri.ToString());
        return true;
    }

    private static string NormalizeUrl(string url) => url.Trim().TrimEnd('/');

    private sealed record ReflectionContext(object Configuration, object PluginManager, Type RepositorySettingsType, IList RepositoryList);
}
