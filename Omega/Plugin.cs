using Dalamud.Game.Command;
using Dalamud.Interface;
using Dalamud.IoC;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;
using Dalamud.Storage.Assets;

namespace Dalagab.Omega;

public sealed class Plugin : IDalamudPlugin
{
    private const string CommandName = "/omega";
    private const string CommandAlias = "/omg";

    [PluginService] internal static IDalamudPluginInterface PluginInterface { get; private set; } = null!;
    [PluginService] internal static ICommandManager CommandManager { get; private set; } = null!;
    [PluginService] internal static IPluginLog Log { get; private set; } = null!;
    [PluginService] internal static ITextureProvider TextureProvider { get; private set; } = null!;
    [PluginService] internal static IDalamudAssetManager DalamudAssets { get; private set; } = null!;
    [PluginService] internal static ITitleScreenMenu TitleScreenMenu { get; private set; } = null!;
    [PluginService] internal static IGameInteropProvider GameInterop { get; private set; } = null!;
    [PluginService] internal static INotificationManager Notifications { get; private set; } = null!;

    private readonly WindowSystem windowSystem = new("DalagabOmega");
    private readonly MarketplaceCatalogService catalog;
    private readonly DalamudDefaultCatalogBridge defaultCatalogBridge;
    private readonly CatalogUpdateCoordinator catalogUpdates;
    private readonly PluginIconCache iconCache;
    private readonly PluginRecencyLedger pluginRecency;
    private readonly PluginLibraryLedger libraryLedger;
    private readonly PluginConfigBackupService configBackups;
    private readonly MarketplaceWindow marketplaceWindow;
    private readonly DalamudSystemMenuBridge systemMenuBridge;
    private readonly DailyCatalogUpdateService dailyCatalogUpdate;
    private readonly OmegaSelfUpdateService selfUpdates;
    private readonly OmegaRepositoryMigrationService repositoryMigration;
    private readonly IReadOnlyTitleScreenMenuEntry? titleScreenEntry;

    public Configuration Configuration { get; }

    public Plugin()
    {
        Configuration = PluginInterface.GetPluginConfig() as Configuration ?? new Configuration();
        MigrateConfigurationSchema();
        var assemblyDirectory = PluginInterface.AssemblyLocation.Directory?.FullName ?? string.Empty;
        MergeBundledSources(assemblyDirectory);

        var catalogDatabasePath = Path.Combine(PluginInterface.ConfigDirectory.FullName, SqliteCatalogStore.DatabaseFileName);
        catalog = new MarketplaceCatalogService(catalogDatabasePath);
        ImportBootstrapCatalog(assemblyDirectory);
        catalog.LoadCached(Configuration.Repositories);
        MergeDatabaseSources();
        var repositoryBridge = new DalamudRepositoryBridge();
        MergeDalamudRepositoryAwareness(repositoryBridge);
        defaultCatalogBridge = new DalamudDefaultCatalogBridge();
        RefreshDefaultCatalog();

        catalogUpdates = new CatalogUpdateCoordinator(
            Configuration,
            catalog,
            assemblyDirectory,
            PluginInterface.ConfigDirectory.FullName);
        iconCache = new PluginIconCache(PluginInterface.ConfigDirectory.FullName);
        pluginRecency = new PluginRecencyLedger(PluginInterface.ConfigDirectory.FullName);
        libraryLedger = new PluginLibraryLedger(PluginInterface.ConfigDirectory.FullName);
        libraryLedger.ObserveInstalled(PluginInterface.InstalledPlugins.Select(x => x.InternalName));
        configBackups = new PluginConfigBackupService(PluginInterface.ConfigFile.FullName);
        selfUpdates = new OmegaSelfUpdateService(Configuration);
        repositoryMigration = new OmegaRepositoryMigrationService(Configuration, catalog, repositoryBridge);
        var profileBridge = new DalamudProfileBridge();
        marketplaceWindow = CreateMarketplaceWindow(assemblyDirectory, repositoryBridge, profileBridge);
        windowSystem.AddWindow(marketplaceWindow);

        RegisterUiCallbacks();
        PluginInterface.ActivePluginsChanged += OnActivePluginsChanged;
        titleScreenEntry = TryRegisterTitleScreenEntry(assemblyDirectory);
        systemMenuBridge = new DalamudSystemMenuBridge(GameInterop, OpenMainUi);
        dailyCatalogUpdate = new DailyCatalogUpdateService(Configuration, catalog, catalogUpdates, Notifications);
        catalogUpdates.SeedIfEmpty();

        Log.Information(
            "Omega {Version} by Dalagab Group loaded; buildStamp={BuildStamp}; titleMenu={TitleMenu}; systemMenu={SystemMenu}",
            BuildInfo.Version,
            BuildInfo.BuildStamp,
            titleScreenEntry is not null,
            systemMenuBridge.IsAvailable);
    }

    private void MigrateConfigurationSchema()
    {
        if (Configuration.Version >= 9)
            return;
        Configuration.Version = 9;
        Configuration.Save();
    }

    private void MergeDalamudRepositoryAwareness(DalamudRepositoryBridge repositoryBridge)
    {
        try
        {
            if (!DalamudRepositoryAwareness.MergeExisting(
                    Configuration,
                    repositoryBridge,
                    catalog,
                    PluginInterface.Manifest.DalamudApiLevel))
                return;
            Configuration.Save();
            catalog.LoadCached(Configuration.Repositories);
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "Omega could not merge existing Dalamud repository awareness.");
        }
    }

    private void MergeBundledSources(string assemblyDirectory)
    {
        var path = Path.Combine(assemblyDirectory, "curated-sources.json");
        if (CuratedSourceCatalog.MergeInto(Configuration, path))
            Configuration.Save();
    }

    private void ImportBootstrapCatalog(string assemblyDirectory)
    {
        var bundlePath = Path.Combine(assemblyDirectory, "omega-catalog.sqlite.zip");
        try
        {
            if (catalog.ImportBootstrapBundle(bundlePath))
                Log.Information("Omega seeded its production SQLite catalog from {Bundle}.", bundlePath);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Omega could not seed its SQLite catalog from {Bundle}.", bundlePath);
        }
    }

    private void MergeDatabaseSources()
    {
        try
        {
            var definitions = catalog.ReadDatabaseSourceDefinitions();
            if (!CuratedSourceCatalog.MergeDefinitionsInto(Configuration, definitions))
                return;
            Configuration.Save();
            catalog.LoadCached(Configuration.Repositories);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Omega could not merge source definitions from its SQLite catalog.");
        }
    }

    private MarketplaceWindow CreateMarketplaceWindow(
        string assemblyDirectory,
        DalamudRepositoryBridge repositoryBridge,
        DalamudProfileBridge profileBridge)
    {
        var installCoordinator = new PluginInstallCoordinator(
            Configuration,
            new DalamudInstallerBridge(PluginInterface),
            repositoryBridge);
        return new MarketplaceWindow(
            Configuration,
            catalog,
            catalogUpdates,
            installCoordinator,
            repositoryBridge,
            profileBridge,
            iconCache,
            pluginRecency,
            libraryLedger,
            configBackups,
            selfUpdates,
            Path.Combine(assemblyDirectory, "icon.png"),
            Path.Combine(assemblyDirectory, "sigmascope-banner.png"),
            Path.Combine(assemblyDirectory, "company-fallback.png"),
            Path.Combine(assemblyDirectory, "EULA.md"));
    }

    private void RegisterUiCallbacks()
    {
        CommandManager.AddHandler(CommandName, new CommandInfo(OnCommand)
        {
            HelpMessage = "Open Omega by the Dalagab Group.",
        });
        CommandManager.AddHandler(CommandAlias, new CommandInfo(OnCommand)
        {
            HelpMessage = "Open Omega by the Dalagab Group.",
        });
        PluginInterface.UiBuilder.Draw += windowSystem.Draw;
        PluginInterface.UiBuilder.OpenMainUi += OpenMainUi;
        PluginInterface.UiBuilder.OpenConfigUi += OpenMainUi;
    }

    public void Dispose()
    {
        dailyCatalogUpdate.Dispose();
        repositoryMigration.Dispose();
        selfUpdates.Dispose();
        catalogUpdates.Dispose();
        systemMenuBridge.Dispose();

        if (titleScreenEntry is not null)
        {
            try
            {
                TitleScreenMenu.RemoveEntry(titleScreenEntry);
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Omega title-screen entry was already unavailable during unload.");
            }
        }

        PluginInterface.ActivePluginsChanged -= OnActivePluginsChanged;
        PluginInterface.UiBuilder.Draw -= windowSystem.Draw;
        PluginInterface.UiBuilder.OpenMainUi -= OpenMainUi;
        PluginInterface.UiBuilder.OpenConfigUi -= OpenMainUi;
        CommandManager.RemoveHandler(CommandName);
        CommandManager.RemoveHandler(CommandAlias);
        windowSystem.RemoveAllWindows();
        marketplaceWindow.Dispose();
        iconCache.Dispose();
        catalog.Dispose();
    }

    private IReadOnlyTitleScreenMenuEntry? TryRegisterTitleScreenEntry(string assemblyDirectory)
    {
        try
        {
            var titleIconPath = Path.Combine(assemblyDirectory, "title-icon.png");
            if (!File.Exists(titleIconPath))
            {
                Log.Warning("Omega title-screen icon was not found at {Path}.", titleIconPath);
                return null;
            }

            var texture = TextureProvider.GetFromFile(titleIconPath);
            return TitleScreenMenu.AddEntry(1000, "Omega", texture, OpenMainUi);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Omega could not register its title-screen menu entry.");
            return null;
        }
    }

    private void OnCommand(string command, string arguments) => OpenMainUi();

    private void OnActivePluginsChanged(IActivePluginsChangedEventArgs args)
        => libraryLedger.ObserveInstalled(PluginInterface.InstalledPlugins.Select(x => x.InternalName));

    private void RefreshDefaultCatalog()
    {
        var defaults = defaultCatalogBridge.ReadAvailable();
        if (defaults.Count > 0)
            catalog.SetDefaultPlugins(defaults);
    }

    private void OpenMainUi()
    {
        RefreshDefaultCatalog();
        marketplaceWindow.IsOpen = true;
        dailyCatalogUpdate.TriggerIfDue();
        selfUpdates.TriggerIfDue();
    }
}
