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

internal sealed record DalamudRepositoryRegistration(string Url, bool Enabled);

internal sealed record DalamudRepositoryUsage(int InstalledCount, IReadOnlyList<string> PluginNames)
{
    public static readonly DalamudRepositoryUsage Empty = new(0, Array.Empty<string>());
}


/// <summary>
/// Isolates Omega's API-15 reflection access to Dalamud's third-party repository configuration.
/// Omega never edits files directly; it mutates the live DalamudConfiguration object, queues a save,
/// and asks PluginManager to rebuild/reload repositories through its own code path.
/// </summary>
internal sealed class DalamudRepositoryBridge
{
    private const BindingFlags AllInstance = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;

    public IReadOnlyList<DalamudRepositoryRegistration> GetConfiguredRepositories()
    {
        try
        {
            var context = ResolveContext();
            var result = new List<DalamudRepositoryRegistration>();
            foreach (var item in context.RepositoryList)
            {
                if (item is null)
                    continue;
                var candidate = item.GetType().GetProperty("Url", AllInstance)?.GetValue(item) as string;
                if (string.IsNullOrWhiteSpace(candidate))
                    continue;
                result.Add(new DalamudRepositoryRegistration(NormalizeUrl(candidate), ReadBool(item, "IsEnabled")));
            }
            return result
                .DistinctBy(x => x.Url, StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x.Url, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega could not enumerate Dalamud third-party repositories.");
            return [];
        }
    }

    public IReadOnlyDictionary<string, DalamudRepositoryUsage> GetInstalledPluginUsageByRepository()
    {
        try
        {
            return Plugin.PluginInterface.InstalledPlugins
                .Select(plugin => new
                {
                    Url = NormalizeUrl(plugin.Manifest.InstalledFromUrl ?? string.Empty),
                    Name = string.IsNullOrWhiteSpace(plugin.Name) ? plugin.InternalName : plugin.Name,
                })
                .Where(item => !string.IsNullOrWhiteSpace(item.Url))
                .GroupBy(item => item.Url, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => new DalamudRepositoryUsage(
                        group.Count(),
                        group.Select(item => item.Name)
                            .Distinct(StringComparer.OrdinalIgnoreCase)
                            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                            .ToArray()),
                    StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega could not map installed plugins to Dalamud repositories.");
            return new Dictionary<string, DalamudRepositoryUsage>(StringComparer.OrdinalIgnoreCase);
        }
    }

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

    public async Task<RepositoryBridgeResult> EnsureIntegratedAsync(
        string url,
        bool enabled,
        CancellationToken cancellationToken = default,
        bool ownedByOmega = true)
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
                OwnedByOmega: ownedByOmega);
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

    /// <summary>
    /// Stages or completes migration of one exact, caller-supplied repository URL while preserving
    /// Dalamud's installed-plugin servicing semantics. This is intentionally used only for Omega's
    /// own historical repository URL.
    ///
    /// Dalamud filters third-party updates by LocalPlugin.Manifest.InstalledFromUrl. While the
    /// installed manifest still points at the legacy URL, both repository rows are retained and the
    /// live LocalPlugin manifest is retargeted in memory so update discovery follows the canonical
    /// feed. A normal Dalamud update then persists the canonical InstalledFromUrl. On a later launch,
    /// once the installed manifest already points at the canonical feed, the legacy row is removed.
    /// </summary>
    public async Task<RepositoryBridgeResult> MigrateKnownInstalledPluginRepositoryAsync(
        string internalName,
        string legacyUrl,
        string canonicalUrl,
        CancellationToken cancellationToken = default)
    {
        if (!TryNormalizeUrl(legacyUrl, out var legacy, out var legacyError))
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.InvalidUrl, legacyError);
        if (!TryNormalizeUrl(canonicalUrl, out var canonical, out var canonicalError))
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.InvalidUrl, canonicalError);
        if (string.IsNullOrWhiteSpace(internalName))
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.Failed, "Installed plugin identity is required for repository migration.");

        try
        {
            var context = ResolveContext();
            var legacySetting = FindRepositorySetting(context.RepositoryList, legacy);
            var canonicalSetting = FindRepositorySetting(context.RepositoryList, canonical);
            var reflected = FindInstalledPlugin(context.PluginManager, internalName);
            var localManifest = reflected?.Manifest;
            var previousInstalledFrom = ReadString(localManifest, "InstalledFromUrl");
            var installedFromLegacy = NormalizeUrl(previousInstalledFrom).Equals(legacy, StringComparison.OrdinalIgnoreCase);
            var installedFromCanonical = NormalizeUrl(previousInstalledFrom).Equals(canonical, StringComparison.OrdinalIgnoreCase);
            var exposedInstalledFromLegacy = Plugin.PluginInterface.InstalledPlugins.Any(plugin =>
                plugin.InternalName.Equals(internalName, StringComparison.OrdinalIgnoreCase) &&
                NormalizeUrl(plugin.Manifest.InstalledFromUrl ?? string.Empty).Equals(legacy, StringComparison.OrdinalIgnoreCase));
            if (exposedInstalledFromLegacy && (localManifest is null || !installedFromLegacy))
            {
                return new RepositoryBridgeResult(
                    RepositoryBridgeOutcome.Failed,
                    "Dalamud exposed Omega as installed from the legacy repository, but the live LocalPlugin manifest could not be retargeted safely; legacy state was retained.");
            }

            if (legacySetting is null && canonicalSetting is null)
                return new RepositoryBridgeResult(RepositoryBridgeOutcome.NotFound, "Neither the legacy nor canonical Omega repository is registered in Dalamud.");

            var legacyEnabled = legacySetting is not null && ReadBool(legacySetting, "IsEnabled");
            var canonicalEnabledBefore = canonicalSetting is not null && ReadBool(canonicalSetting, "IsEnabled");
            var legacyIndex = legacySetting is null ? -1 : context.RepositoryList.IndexOf(legacySetting);
            var createdCanonical = false;
            var createdLegacyRecovery = false;
            var enabledCanonical = false;
            var removedLegacy = false;
            var changedInstalledFrom = false;
            object? createdCanonicalSetting = null;
            object? createdLegacySetting = null;

            try
            {
                if (installedFromLegacy)
                {
                    // Keep a legacy row until Dalamud itself has persisted canonical provenance. This
                    // guarantees Omega is not orphaned on the next game boot if the user does not
                    // install an update during this session.
                    if (legacySetting is null && canonicalSetting is not null)
                    {
                        createdLegacySetting = CreateRepositorySetting(
                            context.RepositorySettingsType,
                            legacy,
                            ReadBool(canonicalSetting, "IsEnabled"));
                        context.RepositoryList.Add(createdLegacySetting);
                        legacySetting = createdLegacySetting;
                        legacyEnabled = ReadBool(createdLegacySetting, "IsEnabled");
                        createdLegacyRecovery = true;
                    }
                    if (legacySetting is null)
                    {
                        return new RepositoryBridgeResult(
                            RepositoryBridgeOutcome.Failed,
                            "Omega is installed from the legacy repository, but no servicing row remains to preserve safe boot behavior; migration was not attempted.");
                    }

                    if (canonicalSetting is null)
                    {
                        createdCanonicalSetting = CreateRepositorySetting(context.RepositorySettingsType, canonical, legacyEnabled);
                        context.RepositoryList.Add(createdCanonicalSetting);
                        canonicalSetting = createdCanonicalSetting;
                        createdCanonical = true;
                    }
                    else if (legacyEnabled && !canonicalEnabledBefore)
                    {
                        Set(canonicalSetting, "IsEnabled", true);
                        enabledCanonical = true;
                    }

                    if (localManifest is not null)
                    {
                        Set(localManifest, "InstalledFromUrl", canonical);
                        changedInstalledFrom = true;
                    }
                }
                else if (legacySetting is not null)
                {
                    // Once Dalamud has persisted canonical provenance (or Omega was installed from a
                    // different source), the historical row is no longer needed. Preserve effective
                    // enabled state when consolidating an old+new duplicate.
                    if (canonicalSetting is null)
                    {
                        createdCanonicalSetting = CreateRepositorySetting(context.RepositorySettingsType, canonical, legacyEnabled);
                        context.RepositoryList.Add(createdCanonicalSetting);
                        canonicalSetting = createdCanonicalSetting;
                        createdCanonical = true;
                    }
                    else if (legacyEnabled && !canonicalEnabledBefore)
                    {
                        Set(canonicalSetting, "IsEnabled", true);
                        enabledCanonical = true;
                    }

                    context.RepositoryList.Remove(legacySetting);
                    removedLegacy = true;
                }
                else if (installedFromCanonical)
                {
                    return new RepositoryBridgeResult(
                        RepositoryBridgeOutcome.AlreadyPresent,
                        "Omega repository servicing is already canonical.",
                        OwnedByOmega: false);
                }

                if (createdCanonical || createdLegacyRecovery || enabledCanonical || removedLegacy)
                    QueueSave(context.Configuration);

                // Refresh only after the repository set and live provenance are mutually serviceable.
                // PluginManager's update scan can then select the canonical feed immediately.
                await RefreshDalamudRepositoriesAsync(context.PluginManager, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                if (changedInstalledFrom && localManifest is not null)
                    Set(localManifest, "InstalledFromUrl", previousInstalledFrom);

                if (removedLegacy && legacySetting is not null)
                {
                    if (legacyIndex >= 0 && legacyIndex <= context.RepositoryList.Count)
                        context.RepositoryList.Insert(legacyIndex, legacySetting);
                    else
                        context.RepositoryList.Add(legacySetting);
                }
                if (createdCanonical && createdCanonicalSetting is not null)
                    context.RepositoryList.Remove(createdCanonicalSetting);
                if (createdLegacyRecovery && createdLegacySetting is not null)
                    context.RepositoryList.Remove(createdLegacySetting);
                if (enabledCanonical && canonicalSetting is not null)
                    Set(canonicalSetting, "IsEnabled", canonicalEnabledBefore);

                if (createdCanonical || createdLegacyRecovery || enabledCanonical || removedLegacy)
                    QueueSave(context.Configuration);
                throw;
            }

            return new RepositoryBridgeResult(
                RepositoryBridgeOutcome.Updated,
                installedFromLegacy
                    ? "Omega stable repository added; the legacy row is retained until a normal Dalamud update persists canonical servicing provenance."
                    : removedLegacy
                        ? "Omega legacy repository removed after canonical servicing provenance was confirmed."
                        : "Omega repository servicing is canonical.",
                OwnedByOmega: false);
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Failed to migrate known installed plugin repository from {LegacyRepository} to {CanonicalRepository}", legacyUrl, canonicalUrl);
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.Failed, $"Dalamud repository migration failed: {ex.GetBaseException().Message}");
        }
    }

    private static InstalledPluginReflection? FindInstalledPlugin(object pluginManager, string internalName)
    {
        var installedProperty = pluginManager.GetType().GetProperty("InstalledPlugins", AllInstance)
            ?? throw new MissingMemberException("Dalamud PluginManager.InstalledPlugins was not found.");
        if (installedProperty.GetValue(pluginManager) is not IEnumerable installed)
            throw new InvalidOperationException("Dalamud PluginManager.InstalledPlugins was not enumerable.");

        foreach (var plugin in installed)
        {
            if (plugin is null)
                continue;
            var manifest = plugin.GetType().GetProperty("Manifest", AllInstance)?.GetValue(plugin);
            if (manifest is null)
                continue;
            var candidate = ReadString(manifest, "InternalName");
            if (candidate.Equals(internalName, StringComparison.OrdinalIgnoreCase))
                return new InstalledPluginReflection(plugin, manifest);
        }

        return null;
    }

    private static object CreateRepositorySetting(Type repositorySettingsType, string url, bool enabled)
    {
        var setting = Activator.CreateInstance(repositorySettingsType, nonPublic: true)
            ?? throw new InvalidOperationException("Could not construct Dalamud ThirdPartyRepoSettings.");
        Set(setting, "Url", url);
        Set(setting, "IsEnabled", enabled);
        return setting;
    }

    private static string ReadString(object? target, string propertyName)
        => target?.GetType().GetProperty(propertyName, AllInstance)?.GetValue(target) as string ?? string.Empty;

    /// <summary>
    /// Removes a user-selected third-party repository only when no currently installed plugin
    /// points at it through Dalamud's persisted InstalledFromUrl provenance. The usage check is
    /// repeated inside the bridge immediately before the configuration mutation so UI state
    /// cannot race a plugin install.
    /// </summary>
    public async Task<RepositoryBridgeResult> RemoveIfUnusedAsync(string url, CancellationToken cancellationToken = default)
    {
        if (!TryNormalizeUrl(url, out var normalized, out var error))
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.InvalidUrl, error);

        try
        {
            var usage = GetInstalledPluginUsageByRepository();
            if (usage.TryGetValue(normalized, out var inUse) && inUse.InstalledCount > 0)
            {
                var names = string.Join(", ", inUse.PluginNames.Take(6));
                var suffix = inUse.PluginNames.Count > 6 ? $" (+{inUse.PluginNames.Count - 6} more)" : string.Empty;
                return new RepositoryBridgeResult(
                    RepositoryBridgeOutcome.Failed,
                    $"Cannot remove this repository while {inUse.InstalledCount} installed plugin(s) use it: {names}{suffix}");
            }

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

            return new RepositoryBridgeResult(RepositoryBridgeOutcome.Removed, "Repository removed from Dalamud.");
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Failed to remove unused Dalamud repository {Repository}", url);
            return new RepositoryBridgeResult(RepositoryBridgeOutcome.Failed, $"Could not remove Dalamud repository: {ex.GetBaseException().Message}");
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

    private sealed record InstalledPluginReflection(object Plugin, object Manifest);

    private sealed record ReflectionContext(object Configuration, object PluginManager, Type RepositorySettingsType, IList RepositoryList);
}
