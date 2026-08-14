namespace Dalagab.Omega;

/// <summary>
/// Keeps repository preparation invisible to the marketplace user. A single install request
/// ensures the selected source is serviceable by Dalamud, then delegates package installation
/// to Dalamud's own installer bridge. Pre-existing user-managed repositories are never
/// modified silently. Explicitly choosing a disabled repository in the install confirmation is
/// consent to enable that repository for Dalamud servicing; ownership remains unchanged.
/// </summary>
internal sealed class PluginInstallCoordinator
{
    private readonly Configuration configuration;
    private readonly DalamudInstallerBridge installer;
    private readonly DalamudRepositoryBridge repositories;

    public PluginInstallCoordinator(
        Configuration configuration,
        DalamudInstallerBridge installer,
        DalamudRepositoryBridge repositories)
    {
        this.configuration = configuration;
        this.installer = installer;
        this.repositories = repositories;
    }

    /// <summary>
    /// Installs one explicitly selected repository variant through Dalamud.
    /// </summary>
    public async Task<InstallResult> InstallAsync(
        MarketplacePlugin plugin,
        RepositorySource? source,
        bool allowTesting,
        CancellationToken cancellationToken = default)
    {
        if (!plugin.SourceIsOfficial)
        {
            var ready = await EnsureRepositoryReadyAsync(plugin, source, cancellationToken).ConfigureAwait(false);
            if (ready is not null)
                return ready;
        }

        return await installer.InstallAsync(plugin, allowTesting, cancellationToken).ConfigureAwait(false);
    }

    private async Task<InstallResult?> EnsureRepositoryReadyAsync(
        MarketplacePlugin plugin,
        RepositorySource? source,
        CancellationToken cancellationToken)
    {
        if (source is null)
        {
            return Failed(
                $"Omega does not have a local source definition for {plugin.SourceName}. " +
                "Reload the catalog or add the repository before installing.");
        }

        var state = repositories.GetState(source.Url);
        if (!state.Available)
            return Failed(state.Message);

        if (state.Present && !state.Enabled)
        {
            var enabled = source.DalamudManagedByOmega
                ? await repositories.SetManagedEnabledAsync(source.Url, true, cancellationToken).ConfigureAwait(false)
                : await repositories.EnableExistingForExplicitInstallAsync(source.Url, cancellationToken).ConfigureAwait(false);
            if (!enabled.Success)
                return Failed(enabled.Message);

            source.IntegrateWithDalamud = true;
            configuration.Save();
            return null;
        }

        if (state.Present)
            return null;

        var integrated = await repositories.EnsureIntegratedAsync(source.Url, true, cancellationToken).ConfigureAwait(false);
        if (!integrated.Success)
            return Failed(integrated.Message);

        source.IntegrateWithDalamud = true;
        source.DalamudManagedByOmega = integrated.OwnedByOmega;
        configuration.Save();
        return null;
    }

    private static InstallResult Failed(string message)
        => new(InstallOutcome.Failed, message);
}
