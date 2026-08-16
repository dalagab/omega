using System.Reflection;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal enum InstallOutcome
{
    Installed,
    AlreadyInstalled,
    Incompatible,
    RepositoryIntegrationRequired,
    Failed,
}

internal sealed record InstallResult(InstallOutcome Outcome, string Message);

internal enum UpdateOutcome
{
    Updated,
    AlreadyCurrent,
    NotInstalled,
    Incompatible,
    RepositoryIntegrationRequired,
    DevPluginBlocked,
    Failed,
}

internal sealed record UpdateResult(
    UpdateOutcome Outcome,
    string Message,
    string PreviousSourceUrl = "",
    string NewSourceUrl = "",
    bool Migrated = false)
{
    public bool Success => Outcome is UpdateOutcome.Updated or UpdateOutcome.AlreadyCurrent;
}

internal enum UninstallOutcome
{
    Uninstalled,
    NotInstalled,
    SelfRemovalBlocked,
    DevPluginBlocked,
    Failed,
}

internal sealed record UninstallResult(UninstallOutcome Outcome, string Message);

/// <summary>
/// Fail-closed API-15 bridge to Dalamud's plugin lifecycle paths. Omega selects metadata and requests
/// install/uninstall actions, while Dalamud remains responsible for package retrieval, loading, and removal.
/// </summary>
internal sealed class DalamudInstallerBridge
{
    private readonly IDalamudPluginInterface pluginInterface;

    public DalamudInstallerBridge(IDalamudPluginInterface pluginInterface)
    {
        this.pluginInterface = pluginInterface;
    }

    public async Task<InstallResult> InstallAsync(MarketplacePlugin plugin, bool allowTesting, CancellationToken cancellationToken = default)
    {
        if (pluginInterface.InstalledPlugins.Any(x => x.InternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase)))
            return new InstallResult(InstallOutcome.AlreadyInstalled, $"{plugin.Name} is already installed.");

        var dalamudVersion = pluginInterface.GetDalamudVersion().Version;
        var currentApi = pluginInterface.Manifest.DalamudApiLevel;
        if (plugin.MinimumDalamudVersion is not null && plugin.MinimumDalamudVersion > dalamudVersion)
            return new InstallResult(InstallOutcome.Incompatible, $"Requires Dalamud {plugin.MinimumDalamudVersion} or newer.");

        if (!plugin.HasCurrentApiBuild(currentApi, allowTesting, out var useTesting))
            return new InstallResult(InstallOutcome.Incompatible, $"No installable API {currentApi} build is advertised by this repository entry.");

        if (!plugin.SourceIsOfficial && !IsRepositoryRegisteredWithDalamud(plugin.SourceUrl))
        {
            return new InstallResult(
                InstallOutcome.RepositoryIntegrationRequired,
                $"The selected repository is not currently available to Dalamud, so {plugin.Name} could not be installed.");
        }

        try
        {
            await InstallThroughDalamudInternalsAsync(plugin, useTesting, cancellationToken).ConfigureAwait(false);
            return new InstallResult(InstallOutcome.Installed, $"Installed {plugin.Name}.");
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Dalamud internal install bridge failed for {Plugin}", plugin.InternalName);
            return new InstallResult(
                InstallOutcome.Failed,
                $"Omega could not install {plugin.Name} through the current Dalamud installation service: {ex.GetBaseException().Message}");
        }
    }

    public async Task<UpdateResult> UpdateAsync(
        MarketplacePlugin plugin,
        bool allowTesting,
        CancellationToken cancellationToken = default)
    {
        var exposed = pluginInterface.InstalledPlugins.FirstOrDefault(x =>
            x.InternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase));
        if (exposed is null)
            return new UpdateResult(UpdateOutcome.NotInstalled, $"{plugin.Name} is no longer installed.");
        if (exposed.IsDev)
        {
            return new UpdateResult(
                UpdateOutcome.DevPluginBlocked,
                $"{plugin.Name} is a developer plugin and cannot be updated through the marketplace lifecycle.");
        }

        var installedVersion = exposed.Version;
        if (installedVersion is null)
            return new UpdateResult(UpdateOutcome.Failed, $"{plugin.Name} does not currently expose a stable installed version.");

        var dalamudVersion = pluginInterface.GetDalamudVersion().Version;
        var currentApi = pluginInterface.Manifest.DalamudApiLevel;
        if (plugin.MinimumDalamudVersion is not null && plugin.MinimumDalamudVersion > dalamudVersion)
            return new UpdateResult(UpdateOutcome.Incompatible, $"Requires Dalamud {plugin.MinimumDalamudVersion} or newer.");
        if (!plugin.HasCurrentApiBuild(currentApi, allowTesting, out var useTesting))
            return new UpdateResult(UpdateOutcome.Incompatible, $"No updateable API {currentApi} build is advertised by this repository entry.");

        var targetVersion = useTesting
            ? plugin.TestingAssemblyVersion ?? plugin.AssemblyVersion
            : plugin.AssemblyVersion;
        if (targetVersion <= installedVersion)
        {
            return new UpdateResult(
                UpdateOutcome.AlreadyCurrent,
                $"{plugin.Name} is already at v{installedVersion} or newer.",
                exposed.Manifest.InstalledFromUrl ?? string.Empty,
                plugin.SourceUrl);
        }

        if (!plugin.SourceIsOfficial && !IsRepositoryRegisteredWithDalamud(plugin.SourceUrl))
        {
            return new UpdateResult(
                UpdateOutcome.RepositoryIntegrationRequired,
                $"The selected repository is not currently available to Dalamud, so {plugin.Name} could not be updated.",
                exposed.Manifest.InstalledFromUrl ?? string.Empty,
                plugin.SourceUrl);
        }

        var previousSource = exposed.Manifest.InstalledFromUrl ?? string.Empty;
        try
        {
            await UpdateThroughDalamudInternalsAsync(plugin, useTesting, cancellationToken).ConfigureAwait(false);
            var moved = !PluginUpdateRules.IsSamePublishingSource(previousSource, plugin.SourceUrl, plugin.SourceIsOfficial);
            return new UpdateResult(
                UpdateOutcome.Updated,
                moved
                    ? $"Updated {plugin.Name} to v{targetVersion} and migrated it to {plugin.SourceName}."
                    : $"Updated {plugin.Name} to v{targetVersion}.",
                previousSource,
                plugin.SourceUrl,
                Migrated: moved);
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Dalamud internal update bridge failed for {Plugin} from {Repository}", plugin.InternalName, plugin.SourceUrl);
            return new UpdateResult(
                UpdateOutcome.Failed,
                $"Omega could not update {plugin.Name} through the current Dalamud lifecycle service: {ex.GetBaseException().Message}",
                previousSource,
                plugin.SourceUrl);
        }
    }

    public async Task<UninstallResult> UninstallAsync(string internalName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(internalName))
            return new UninstallResult(UninstallOutcome.NotInstalled, "No installed plugin was selected.");

        if (internalName.Equals(pluginInterface.InternalName, StringComparison.OrdinalIgnoreCase))
        {
            return new UninstallResult(
                UninstallOutcome.SelfRemovalBlocked,
                "Omega cannot uninstall itself while it is running. Remove Omega from Dalamud's installed plugins page.");
        }

        var exposed = pluginInterface.InstalledPlugins.FirstOrDefault(x =>
            x.InternalName.Equals(internalName, StringComparison.OrdinalIgnoreCase));
        if (exposed is null)
            return new UninstallResult(UninstallOutcome.NotInstalled, $"{internalName} is no longer installed.");
        if (exposed.IsDev)
        {
            return new UninstallResult(
                UninstallOutcome.DevPluginBlocked,
                $"{exposed.Name} is a developer plugin. Remove its dev-plugin location through Dalamud instead.");
        }

        try
        {
            await UninstallThroughDalamudInternalsAsync(internalName, cancellationToken).ConfigureAwait(false);
            return new UninstallResult(UninstallOutcome.Uninstalled, $"Uninstalled {exposed.Name}. Dalamud will clean the scheduled plugin files during its normal cleanup cycle.");
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Dalamud internal uninstall bridge failed for {Plugin}", internalName);
            return new UninstallResult(
                UninstallOutcome.Failed,
                $"Omega could not uninstall {exposed.Name} through the current Dalamud lifecycle service: {ex.GetBaseException().Message}");
        }
    }

    private static async Task UninstallThroughDalamudInternalsAsync(string internalName, CancellationToken cancellationToken)
    {
        var dalamudAssembly = typeof(IDalamudPluginInterface).Assembly;
        var pluginManagerType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.PluginManager");
        var disposalModeType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.Types.PluginLoaderDisposalMode");
        var serviceOpenType = RequireType(dalamudAssembly, "Dalamud.Service`1");
        var pluginManager = GetInternalService(serviceOpenType, pluginManagerType);

        var installedProperty = pluginManagerType.GetProperty("InstalledPlugins", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMemberException("Dalamud PluginManager.InstalledPlugins was not found.");
        if (installedProperty.GetValue(pluginManager) is not System.Collections.IEnumerable installedPlugins)
            throw new InvalidOperationException("Dalamud PluginManager.InstalledPlugins is not enumerable.");

        object? localPlugin = null;
        foreach (var candidate in installedPlugins)
        {
            if (candidate is null)
                continue;
            var candidateName = candidate.GetType().GetProperty("InternalName", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)?.GetValue(candidate) as string;
            if (internalName.Equals(candidateName, StringComparison.OrdinalIgnoreCase))
            {
                localPlugin = candidate;
                break;
            }
        }

        if (localPlugin is null)
            throw new InvalidOperationException("The installed plugin disappeared before Dalamud could uninstall it.");

        var localType = localPlugin.GetType();
        var isDevValue = localType.GetProperty("IsDev", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)?.GetValue(localPlugin);
        var isDev = isDevValue is bool value && value;
        if (isDev)
            throw new InvalidOperationException("Developer plugins are not removed through the marketplace uninstall path.");

        var stateProperty = localType.GetProperty("State", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMemberException("Dalamud LocalPlugin.State was not found.");
        var state = stateProperty.GetValue(localPlugin)?.ToString() ?? string.Empty;
        if (state is "Loaded" or "LoadError")
        {
            var unloadMethod = localType.GetMethod("UnloadAsync", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                ?? throw new MissingMethodException("Dalamud LocalPlugin.UnloadAsync was not found.");
            var waitMode = Enum.Parse(disposalModeType, "WaitBeforeDispose");
            var unloadTask = unloadMethod.Invoke(localPlugin, [waitMode]) as Task
                ?? throw new InvalidOperationException("Dalamud plugin unload invocation did not return a Task.");
            await unloadTask.WaitAsync(cancellationToken).ConfigureAwait(false);
            state = stateProperty.GetValue(localPlugin)?.ToString() ?? string.Empty;
        }

        if (state is not ("Unloaded" or "DependencyResolutionFailed"))
            throw new InvalidOperationException($"Dalamud could not put the plugin into a removable state (state={state}).");

        var scheduleDeletion = localType.GetMethod("ScheduleDeletion", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMethodException("Dalamud LocalPlugin.ScheduleDeletion was not found.");
        scheduleDeletion.Invoke(localPlugin, [true]);

        var removePlugin = pluginManagerType.GetMethod("RemovePlugin", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMethodException("Dalamud PluginManager.RemovePlugin was not found.");
        removePlugin.Invoke(pluginManager, [localPlugin]);
    }

    private static async Task InstallThroughDalamudInternalsAsync(MarketplacePlugin plugin, bool useTesting, CancellationToken cancellationToken)
    {
        var dalamudAssembly = typeof(IDalamudPluginInterface).Assembly;
        var pluginManagerType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.PluginManager");
        var remoteManifestType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.Types.Manifest.RemotePluginManifest");
        var pluginRepositoryType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.Types.PluginRepository");
        var serviceOpenType = RequireType(dalamudAssembly, "Dalamud.Service`1");
        var loadReasonType = RequireType(dalamudAssembly, "Dalamud.Plugin.PluginLoadReason");

        var pluginManager = GetInternalService(serviceOpenType, pluginManagerType);
        var remoteManifest = CreateRemoteManifest(plugin, pluginManager, remoteManifestType, pluginRepositoryType);
        EnsureManifestEligible(pluginManager, pluginManagerType, remoteManifest);

        var installMethod = pluginManagerType.GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(x => x.Name == "InstallPluginAsync")
            .OrderBy(x => x.GetParameters().Length)
            .FirstOrDefault(x => x.GetParameters().Length is 3 or 4)
            ?? throw new MissingMethodException("Dalamud PluginManager.InstallPluginAsync was not found.");
        var installerReason = Enum.Parse(loadReasonType, "Installer");
        var installArguments = installMethod.GetParameters().Length == 4
            ? new object?[] { remoteManifest, useTesting, installerReason, null }
            : new object?[] { remoteManifest, useTesting, installerReason };
        var task = installMethod.Invoke(pluginManager, installArguments) as Task
            ?? throw new InvalidOperationException("Dalamud install invocation did not return a Task.");

        await task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task UpdateThroughDalamudInternalsAsync(MarketplacePlugin plugin, bool useTesting, CancellationToken cancellationToken)
    {
        var dalamudAssembly = typeof(IDalamudPluginInterface).Assembly;
        var pluginManagerType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.PluginManager");
        var remoteManifestType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.Types.Manifest.RemotePluginManifest");
        var pluginRepositoryType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.Types.PluginRepository");
        var availableUpdateType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.Types.AvailablePluginUpdate");
        var serviceOpenType = RequireType(dalamudAssembly, "Dalamud.Service`1");

        var pluginManager = GetInternalService(serviceOpenType, pluginManagerType);
        var localPlugin = FindInstalledLocalPlugin(pluginManager, pluginManagerType, plugin.InternalName)
            ?? throw new InvalidOperationException("The installed plugin disappeared before Dalamud could update it.");
        var remoteManifest = CreateRemoteManifest(plugin, pluginManager, remoteManifestType, pluginRepositoryType);
        EnsureManifestEligible(pluginManager, pluginManagerType, remoteManifest);

        var updateMetadata = Activator.CreateInstance(
            availableUpdateType,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: [localPlugin, remoteManifest, useTesting],
            culture: null)
            ?? throw new InvalidOperationException("Could not construct Dalamud update metadata.");

        var updateMethod = pluginManagerType.GetMethod(
            "UpdateSinglePluginAsync",
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            types: [availableUpdateType, typeof(bool), typeof(bool)],
            modifiers: null)
            ?? throw new MissingMethodException("Dalamud PluginManager.UpdateSinglePluginAsync was not found.");
        var task = updateMethod.Invoke(pluginManager, [updateMetadata, true, false]) as Task
            ?? throw new InvalidOperationException("Dalamud update invocation did not return a Task.");

        await task.WaitAsync(cancellationToken).ConfigureAwait(false);
        var result = task.GetType().GetProperty("Result", BindingFlags.Instance | BindingFlags.Public)?.GetValue(task)
            ?? throw new InvalidOperationException("Dalamud update invocation completed without a result.");
        var status = result.GetType().GetProperty("Status", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)?.GetValue(result)?.ToString();
        if (!string.Equals(status, "Success", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Dalamud update returned {status ?? "an unknown status"}.");
    }

    private static object CreateRemoteManifest(
        MarketplacePlugin plugin,
        object pluginManager,
        Type remoteManifestType,
        Type pluginRepositoryType)
    {
        var remoteManifest = Activator.CreateInstance(remoteManifestType, nonPublic: true)
            ?? throw new InvalidOperationException("Could not construct Dalamud remote manifest.");

        Set(remoteManifest, "Author", plugin.Author);
        Set(remoteManifest, "Name", plugin.Name);
        Set(remoteManifest, "InternalName", plugin.InternalName);
        Set(remoteManifest, "Punchline", plugin.Punchline);
        Set(remoteManifest, "Description", plugin.Description);
        Set(remoteManifest, "Changelog", plugin.Changelog);
        Set(remoteManifest, "AssemblyVersion", plugin.AssemblyVersion);
        Set(remoteManifest, "DalamudApiLevel", plugin.DalamudApiLevel);
        SetApplicableVersion(remoteManifest, plugin.ApplicableVersion);
        Set(remoteManifest, "MinimumDalamudVersion", plugin.MinimumDalamudVersion);
        Set(remoteManifest, "RepoUrl", plugin.RepoUrl);
        Set(remoteManifest, "DownloadLinkInstall", plugin.DownloadLinkInstall);
        Set(remoteManifest, "DownloadLinkUpdate", plugin.DownloadLinkUpdate);
        Set(remoteManifest, "DownloadLinkTesting", plugin.DownloadLinkTesting);
        Set(remoteManifest, "DownloadCount", plugin.DownloadCount);
        Set(remoteManifest, "LastUpdate", plugin.LastUpdate);
        Set(remoteManifest, "IsHide", plugin.IsHide);
        Set(remoteManifest, "IsTestingExclusive", plugin.IsTestingExclusive);
        Set(remoteManifest, "IconUrl", NullIfWhiteSpace(plugin.IconUrl));
        Set(remoteManifest, "ImageUrls", plugin.ImageUrls.ToList());
        Set(remoteManifest, "Tags", plugin.Tags.ToList());
        Set(remoteManifest, "CategoryTags", plugin.CategoryTags.ToList());
        Set(remoteManifest, "TestingAssemblyVersion", plugin.TestingAssemblyVersion);
        Set(remoteManifest, "TestingDalamudApiLevel", plugin.TestingDalamudApiLevel);
        Set(remoteManifest, "Dip17Channel", NullIfWhiteSpace(plugin.Dip17Channel));

        var sourceRepo = FindRepository(pluginManager, pluginRepositoryType, plugin.SourceUrl);
        Set(remoteManifest, "SourceRepo", sourceRepo);
        return remoteManifest;
    }

    private static void EnsureManifestEligible(object pluginManager, Type pluginManagerType, object remoteManifest)
    {
        var eligibleMethod = pluginManagerType.GetMethod("IsManifestEligible", BindingFlags.Instance | BindingFlags.Public)
            ?? throw new MissingMethodException("Dalamud PluginManager.IsManifestEligible was not found.");
        var eligible = (bool)(eligibleMethod.Invoke(pluginManager, [remoteManifest]) ?? false);
        if (!eligible)
            throw new InvalidOperationException("Dalamud rejected this repository manifest as ineligible.");
    }

    private static object? FindInstalledLocalPlugin(object pluginManager, Type pluginManagerType, string internalName)
    {
        var installedProperty = pluginManagerType.GetProperty("InstalledPlugins", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMemberException("Dalamud PluginManager.InstalledPlugins was not found.");
        if (installedProperty.GetValue(pluginManager) is not System.Collections.IEnumerable installedPlugins)
            throw new InvalidOperationException("Dalamud PluginManager.InstalledPlugins is not enumerable.");

        foreach (var candidate in installedPlugins)
        {
            if (candidate is null)
                continue;
            var candidateName = candidate.GetType().GetProperty("InternalName", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)?.GetValue(candidate) as string;
            if (internalName.Equals(candidateName, StringComparison.OrdinalIgnoreCase))
                return candidate;
        }

        return null;
    }

    private static bool IsRepositoryRegisteredWithDalamud(string sourceUrl)
    {
        try
        {
            var dalamudAssembly = typeof(IDalamudPluginInterface).Assembly;
            var pluginManagerType = RequireType(dalamudAssembly, "Dalamud.Plugin.Internal.PluginManager");
            var serviceOpenType = RequireType(dalamudAssembly, "Dalamud.Service`1");
            var pluginManager = GetInternalService(serviceOpenType, pluginManagerType);
            var reposProperty = pluginManagerType.GetProperty("Repos", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (reposProperty?.GetValue(pluginManager) is not System.Collections.IEnumerable repositories)
                return false;

            foreach (var repository in repositories)
            {
                if (repository is null)
                    continue;
                var url = repository.GetType().GetProperty("PluginMasterUrl", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)?.GetValue(repository) as string;
                if (string.Equals(NormalizeUrl(url), NormalizeUrl(sourceUrl), StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Could not inspect Dalamud repository registration for {Repository}", sourceUrl);
        }

        return false;
    }

    private static object FindRepository(object pluginManager, Type repositoryType, string sourceUrl)
    {
        var reposProperty = pluginManager.GetType().GetProperty("Repos", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMemberException("Dalamud PluginManager.Repos was not found.");
        if (reposProperty.GetValue(pluginManager) is not System.Collections.IEnumerable repositories)
            throw new InvalidOperationException("Dalamud PluginManager.Repos is not enumerable.");

        foreach (var repository in repositories)
        {
            if (repository is null || !repositoryType.IsInstanceOfType(repository))
                continue;
            var url = repository.GetType().GetProperty("PluginMasterUrl", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)?.GetValue(repository) as string;
            if (string.Equals(NormalizeUrl(url), NormalizeUrl(sourceUrl), StringComparison.OrdinalIgnoreCase))
                return repository;
        }

        throw new InvalidOperationException("The source repository is not registered with Dalamud.");
    }

    private static string NormalizeUrl(string? url) => (url ?? string.Empty).Trim().TrimEnd('/');

    private static object GetInternalService(Type serviceOpenType, Type serviceType)
    {
        var closed = serviceOpenType.MakeGenericType(serviceType);
        var get = closed.GetMethod("Get", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMethodException($"Dalamud service locator could not resolve {serviceType.Name}.");
        return get.Invoke(null, null) ?? throw new InvalidOperationException($"Dalamud service {serviceType.Name} was null.");
    }

    private static Type RequireType(Assembly assembly, string fullName)
        => assembly.GetType(fullName, throwOnError: false) ?? throw new TypeLoadException($"Dalamud internal type changed: {fullName}");

    private static void Set(object target, string propertyName, object? value)
    {
        if (value is null)
            return;
        var property = target.GetType().GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        if (property?.CanWrite == true)
            property.SetValue(target, value);
    }

    private static void SetApplicableVersion(object remoteManifest, string applicableVersion)
    {
        if (string.IsNullOrWhiteSpace(applicableVersion))
            return;

        var property = remoteManifest.GetType().GetProperty("ApplicableVersion", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        if (property?.CanWrite != true)
            return;

        try
        {
            var gameVersion = Activator.CreateInstance(property.PropertyType, [applicableVersion]);
            if (gameVersion is not null)
                property.SetValue(remoteManifest, gameVersion);
        }
        catch (Exception ex)
        {
            throw new InvalidDataException($"Repository entry has invalid ApplicableVersion '{applicableVersion}'.", ex);
        }
    }

    private static string? NullIfWhiteSpace(string value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
