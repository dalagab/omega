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
                $"{plugin.SourceName} is not registered with Dalamud. Integrate this source from Omega's Sources window before installing so Dalamud can service and update the plugin later.");
        }

        try
        {
            await InstallThroughDalamudInternalsAsync(plugin, useTesting, cancellationToken).ConfigureAwait(false);
            return new InstallResult(InstallOutcome.Installed, $"Installed {plugin.Name} through Dalamud.");
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Dalamud internal install bridge failed for {Plugin}", plugin.InternalName);
            return new InstallResult(
                InstallOutcome.Failed,
                $"Omega could not install {plugin.Name} through the current Dalamud installation service: {ex.GetBaseException().Message}");
        }
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
        var remoteManifest = Activator.CreateInstance(remoteManifestType, nonPublic: true) ?? throw new InvalidOperationException("Could not construct Dalamud remote manifest.");

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

        var eligibleMethod = pluginManagerType.GetMethod("IsManifestEligible", BindingFlags.Instance | BindingFlags.Public)
            ?? throw new MissingMethodException("Dalamud PluginManager.IsManifestEligible was not found.");
        var eligible = (bool)(eligibleMethod.Invoke(pluginManager, [remoteManifest]) ?? false);
        if (!eligible)
            throw new InvalidOperationException("Dalamud rejected this repository manifest as ineligible.");

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
