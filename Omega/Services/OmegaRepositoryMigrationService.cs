using System.Net;

namespace Dalagab.Omega;

/// <summary>
/// One-time servicing-endpoint migration for Omega itself.
///
/// Historical Omega installs registered the raw main-branch PluginMaster. Tagged releases now
/// publish a generated stable PluginMaster on the omega-latest release. Dalamud deliberately ties
/// third-party updates to the InstalledFromUrl recorded on the installed plugin, so moving only the
/// ThirdRepoList row would make the new feed invisible to update discovery until the local plugin
/// provenance changed as well.
///
/// This service therefore validates the canonical feed first, migrates only Omega's exact legacy
/// repository URL through Dalamud's live configuration, adds the canonical feed alongside it, and
/// temporarily retargets the running LocalPlugin manifest in memory. The legacy row remains until
/// the next ordinary Dalamud update persists canonical InstalledFromUrl, after which a later launch
/// removes the legacy row. No plugin files or Dalamud JSON files are edited by Omega.
/// </summary>
internal sealed class OmegaRepositoryMigrationService : IDisposable
{
    internal const string LegacyRepositoryUrl =
        "https://raw.githubusercontent.com/dalagab/omega/main/repository/pluginmaster.json";
    internal const string CanonicalRepositoryUrl = OmegaSelfUpdateService.RepositoryManifestUrl;

    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(8);

    private readonly Configuration configuration;
    private readonly MarketplaceCatalogService catalog;
    private readonly DalamudRepositoryBridge bridge;
    private readonly RepositoryClient repositoryClient = new();
    private readonly CancellationTokenSource cts = new();
    private readonly Task worker;

    public OmegaRepositoryMigrationService(
        Configuration configuration,
        MarketplaceCatalogService catalog,
        DalamudRepositoryBridge bridge)
    {
        this.configuration = configuration;
        this.catalog = catalog;
        this.bridge = bridge;
        worker = RunAsync(cts.Token);
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(InitialDelay, cancellationToken).ConfigureAwait(false);

            var configured = bridge.GetConfiguredRepositories();
            var legacyConfigured = configured.Any(x => SameUrl(x.Url, LegacyRepositoryUrl));
            var canonicalConfigured = configured.Any(x => SameUrl(x.Url, CanonicalRepositoryUrl));
            var installedSource = GetInstalledOmegaSource();
            var installedFromLegacy = SameUrl(installedSource, LegacyRepositoryUrl);

            // Nothing to migrate. If the config row was already migrated during a previous session
            // but the installed package has not yet been updated, we still need to re-apply the
            // transient provenance retarget below on every launch until Dalamud persists it itself.
            if (!legacyConfigured && !(canonicalConfigured && installedFromLegacy))
                return;

            if (!await ValidateCanonicalFeedAsync(cancellationToken).ConfigureAwait(false))
                return;

            var result = await bridge.MigrateKnownInstalledPluginRepositoryAsync(
                    Plugin.PluginInterface.InternalName,
                    LegacyRepositoryUrl,
                    CanonicalRepositoryUrl,
                    cancellationToken)
                .ConfigureAwait(false);

            if (!result.Success)
            {
                Plugin.Log.Warning(
                    "Omega repository servicing migration did not complete: {Message}",
                    result.Message);
                return;
            }

            RefreshOmegaRepositoryAwareness();
            Plugin.Log.Information(
                "Omega repository servicing endpoint migrated to the generated stable feed; result={Outcome}; message={Message}",
                result.Outcome,
                result.Message);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            // Migration is fail-safe: the existing repository registration remains usable whenever
            // validation or Dalamud's own repository refresh cannot complete.
            Plugin.Log.Warning(ex, "Omega could not migrate its legacy Dalamud repository servicing endpoint; existing state was retained.");
        }
    }

    private async Task<bool> ValidateCanonicalFeedAsync(CancellationToken cancellationToken)
    {
        try
        {
            var source = new RepositorySource
            {
                Name = "Omega stable",
                Url = CanonicalRepositoryUrl,
                Enabled = true,
                IsCurated = true,
                IsOfficial = false,
            };
            var fetched = await repositoryClient.FetchAsync(source, cancellationToken).ConfigureAwait(false);
            var omega = RepositoryManifestParser.Parse(fetched.ManifestJson, source)
                .FirstOrDefault(x => x.InternalName.Equals(Plugin.PluginInterface.InternalName, StringComparison.OrdinalIgnoreCase));
            if (omega is null)
            {
                Plugin.Log.Warning("Omega canonical repository migration was skipped because the stable feed did not contain {InternalName}.", Plugin.PluginInterface.InternalName);
                return false;
            }

            if (!IsSafeCanonicalEntry(omega, BuildInfo.Version, out var reason))
            {
                Plugin.Log.Warning("Omega canonical repository migration was skipped because the stable feed failed validation: {Reason}", reason);
                return false;
            }

            return true;
        }
        catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            // The generated stable feed is created by the first tagged release using the new
            // publication workflow. Until then there is nothing to migrate to, and this is not an
            // operational error.
            Plugin.Log.Information(
                "Omega repository migration is waiting for the generated stable release feed to be published.");
            return false;
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega canonical repository migration was skipped because the stable feed could not be validated.");
            return false;
        }
    }

    internal static bool IsSafeCanonicalEntry(MarketplacePlugin plugin, string runningVersion, out string reason)
    {
        reason = string.Empty;
        if (!plugin.InternalName.Equals("DalagabOmega", StringComparison.OrdinalIgnoreCase))
        {
            reason = "plugin identity mismatch";
            return false;
        }

        if (!OmegaSelfUpdateService.TryComparableVersion(plugin.AssemblyVersionText, out var remote) ||
            !OmegaSelfUpdateService.TryComparableVersion(runningVersion, out var current))
        {
            reason = "invalid version";
            return false;
        }
        if (remote.CompareTo(current) < 0)
        {
            reason = $"stable feed {remote} is older than running Omega {current}";
            return false;
        }

        if (!TryImmutableOmegaPackageVersion(plugin.DownloadLinkInstall, out var immutableVersion) ||
            immutableVersion != remote)
        {
            reason = "install URL is not the matching immutable Omega release package";
            return false;
        }
        if (!SameUrl(plugin.DownloadLinkInstall, plugin.DownloadLinkUpdate))
        {
            reason = "install and update URLs differ";
            return false;
        }

        return true;
    }

    private static bool TryImmutableOmegaPackageVersion(string url, out Version version)
    {
        version = new Version(0, 0, 0, 0);
        if (!Uri.TryCreate((url ?? string.Empty).Trim(), UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase))
            return false;

        var parts = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 6 ||
            !parts[0].Equals("dalagab", StringComparison.OrdinalIgnoreCase) ||
            !parts[1].Equals("omega", StringComparison.OrdinalIgnoreCase) ||
            !parts[2].Equals("releases", StringComparison.OrdinalIgnoreCase) ||
            !parts[3].Equals("download", StringComparison.OrdinalIgnoreCase) ||
            !parts[4].StartsWith('v') ||
            !parts[5].Equals("Omega.zip", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!Version.TryParse(parts[4][1..], out var tagged) || tagged.Build < 0)
            return false;
        version = new Version(tagged.Major, tagged.Minor, tagged.Build, 0);
        return true;
    }

    private static string GetInstalledOmegaSource()
    {
        try
        {
            return Plugin.PluginInterface.InstalledPlugins
                .FirstOrDefault(x => x.InternalName.Equals(Plugin.PluginInterface.InternalName, StringComparison.OrdinalIgnoreCase))
                ?.Manifest.InstalledFromUrl ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private void RefreshOmegaRepositoryAwareness()
    {
        try
        {
            if (!DalamudRepositoryAwareness.MergeExisting(
                    configuration,
                    bridge,
                    catalog,
                    Plugin.PluginInterface.Manifest.DalamudApiLevel))
                return;
            configuration.Save();
            catalog.LoadCached(configuration.Repositories);
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega repository migration completed, but local repository awareness could not be refreshed immediately.");
        }
    }

    private static bool SameUrl(string? left, string? right)
        => (left ?? string.Empty).Trim().TrimEnd('/').Equals(
            (right ?? string.Empty).Trim().TrimEnd('/'),
            StringComparison.OrdinalIgnoreCase);

    public void Dispose()
    {
        cts.Cancel();
        try { worker.Wait(TimeSpan.FromMilliseconds(250)); } catch { }
        repositoryClient.Dispose();
        cts.Dispose();
    }
}
