namespace Dalagab.Omega;

/// <summary>
/// Keeps plugin lifecycle preparation invisible to the marketplace user. Install requests ensure
/// the selected source is serviceable before delegating to Dalamud; uninstall requests delegate
/// directly to Dalamud's lifecycle bridge. Pre-existing user-managed repositories are never modified
/// silently. Explicitly choosing a disabled repository in the install confirmation is consent to
/// enable that repository for Dalamud servicing; ownership remains unchanged.
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
            var error = await EnsureRepositoryReadyAsync(plugin, source, cancellationToken).ConfigureAwait(false);
            if (error is not null)
                return FailedInstall(error);
        }

        return await installer.InstallAsync(plugin, allowTesting, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Updates one installed plugin through Dalamud. If the selected package is published from a
    /// different repository, the new source is prepared first and Dalamud performs the replacement
    /// as a normal in-place update, which migrates the installed source without touching old repos.
    /// </summary>
    public async Task<UpdateResult> UpdateAsync(
        MarketplacePlugin plugin,
        RepositorySource? source,
        bool allowTesting,
        CancellationToken cancellationToken = default)
    {
        if (!plugin.SourceIsOfficial)
        {
            var error = await EnsureRepositoryReadyAsync(plugin, source, cancellationToken).ConfigureAwait(false);
            if (error is not null)
                return FailedUpdate(error, plugin);
        }

        return await installer.UpdateAsync(plugin, allowTesting, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Uninstalls one installed plugin through Dalamud's lifecycle manager.
    /// </summary>
    public Task<UninstallResult> UninstallAsync(
        string internalName,
        CancellationToken cancellationToken = default)
        => installer.UninstallAsync(internalName, cancellationToken);

    private async Task<string?> EnsureRepositoryReadyAsync(
        MarketplacePlugin plugin,
        RepositorySource? source,
        CancellationToken cancellationToken)
    {
        if (source is null)
        {
            return
                $"Omega does not have a usable repository descriptor for {plugin.SourceName}. " +
                "Refresh Definitions before continuing.";
        }

        var state = repositories.GetState(source.Url);
        if (!state.Available)
            return state.Message;

        if (state.Present && !state.Enabled)
        {
            var enabled = source.DalamudManagedByOmega
                ? await repositories.SetManagedEnabledAsync(source.Url, true, cancellationToken).ConfigureAwait(false)
                : await repositories.EnableExistingForExplicitInstallAsync(source.Url, cancellationToken).ConfigureAwait(false);
            if (!enabled.Success)
                return enabled.Message;

            source.IntegrateWithDalamud = true;
            configuration.Save();
            return null;
        }

        if (state.Present)
            return null;

        var integrated = await repositories.EnsureIntegratedAsync(source.Url, true, cancellationToken).ConfigureAwait(false);
        if (!integrated.Success)
            return integrated.Message;

        source.IntegrateWithDalamud = true;
        source.DalamudManagedByOmega = integrated.OwnedByOmega;
        configuration.Save();
        return null;
    }

    private static InstallResult FailedInstall(string message)
        => new(InstallOutcome.Failed, message);

    private static UpdateResult FailedUpdate(string message, MarketplacePlugin plugin)
        => new(UpdateOutcome.Failed, message, NewSourceUrl: plugin.SourceUrl);
}
