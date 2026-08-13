using Dalamud.Game.Command;
using Dalamud.Interface;
using Dalamud.IoC;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;
using Dalamud.Plugin.Services;

namespace Dalagab.Omega;

public sealed class Plugin : IDalamudPlugin
{
    private const string CommandName = "/omega";

    [PluginService] internal static IDalamudPluginInterface PluginInterface { get; private set; } = null!;
    [PluginService] internal static ICommandManager CommandManager { get; private set; } = null!;
    [PluginService] internal static IPluginLog Log { get; private set; } = null!;
    [PluginService] internal static ITextureProvider TextureProvider { get; private set; } = null!;
    [PluginService] internal static ITitleScreenMenu TitleScreenMenu { get; private set; } = null!;
    [PluginService] internal static IGameInteropProvider GameInterop { get; private set; } = null!;

    private readonly WindowSystem windowSystem = new("DalagabOmega");
    private readonly MarketplaceCatalogService catalog;
    private readonly CatalogUpdateCoordinator catalogUpdates;
    private readonly PluginIconCache iconCache;
    private readonly MarketplaceWindow marketplaceWindow;
    private readonly DalamudSystemMenuBridge systemMenuBridge;
    private readonly DailyCatalogUpdateService dailyCatalogUpdate;
    private readonly IReadOnlyTitleScreenMenuEntry? titleScreenEntry;

    public Configuration Configuration { get; }

    public Plugin()
    {
        Configuration = PluginInterface.GetPluginConfig() as Configuration ?? new Configuration();
        var assemblyDirectory = PluginInterface.AssemblyLocation.Directory?.FullName ?? string.Empty;
        var curatedSourcePath = Path.Combine(assemblyDirectory, "curated-sources.json");
        if (CuratedSourceCatalog.MergeInto(Configuration, curatedSourcePath))
            Configuration.Save();

        var catalogDatabasePath = Path.Combine(PluginInterface.ConfigDirectory.FullName, "catalog-db");
        catalog = new MarketplaceCatalogService(catalogDatabasePath);

        // A GitHub runner can publish a prebuilt Omega database. Importing it is entirely local:
        // no repository requests occur here, and newer per-source local records always win.
        var bundlePaths = new[]
        {
            Path.Combine(assemblyDirectory, "omega-catalog-db.zip"),
            Path.Combine(PluginInterface.ConfigDirectory.FullName, "omega-catalog-db.zip"),
        };
        var configurationChangedByBundle = false;
        foreach (var bundlePath in bundlePaths.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!File.Exists(bundlePath))
                continue;

            try
            {
                var import = catalog.ImportBundle(bundlePath);
                configurationChangedByBundle |= CuratedSourceCatalog.MergeDefinitionsInto(Configuration, import.SourceDefinitions);
                Log.Information(
                    "Omega imported prebuilt catalog bundle {Bundle}; imported={Imported}; skipped={Skipped}; sources={Sources}",
                    bundlePath,
                    import.ImportedRecords,
                    import.SkippedRecords,
                    import.SourceDefinitions.Count);
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Omega could not import prebuilt catalog bundle {Bundle}", bundlePath);
            }
        }

        if (configurationChangedByBundle)
            Configuration.Save();

        catalog.LoadCached(Configuration.Repositories);
        catalogUpdates = new CatalogUpdateCoordinator(
            Configuration,
            catalog,
            assemblyDirectory,
            PluginInterface.ConfigDirectory.FullName);
        iconCache = new PluginIconCache();
        var repositoryBridge = new DalamudRepositoryBridge();
        var iconPath = Path.Combine(assemblyDirectory, "icon.png");
        var fallbackIconPath = Path.Combine(assemblyDirectory, "company-fallback.png");
        marketplaceWindow = new MarketplaceWindow(
            Configuration,
            catalog,
            catalogUpdates,
            new DalamudInstallerBridge(PluginInterface),
            repositoryBridge,
            iconCache,
            iconPath,
            fallbackIconPath);
        windowSystem.AddWindow(marketplaceWindow);

        CommandManager.AddHandler(CommandName, new CommandInfo(OnCommand)
        {
            HelpMessage = "Open Omega by the Dalagab Group.",
        });

        PluginInterface.UiBuilder.Draw += windowSystem.Draw;
        PluginInterface.UiBuilder.OpenMainUi += OpenMainUi;
        PluginInterface.UiBuilder.OpenConfigUi += OpenMainUi;

        titleScreenEntry = TryRegisterTitleScreenEntry(assemblyDirectory);
        systemMenuBridge = new DalamudSystemMenuBridge(GameInterop, OpenMainUi);
        dailyCatalogUpdate = new DailyCatalogUpdateService(Configuration, catalog, catalogUpdates);
        catalogUpdates.SeedIfEmpty();

        Log.Information(
            "Omega {Version} by Dalagab Group loaded; buildStamp={BuildStamp}; titleMenu={TitleMenu}; systemMenu={SystemMenu}",
            BuildInfo.Version,
            BuildInfo.BuildStamp,
            titleScreenEntry is not null,
            systemMenuBridge.IsAvailable);
    }

    public void Dispose()
    {
        dailyCatalogUpdate.Dispose();
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

        PluginInterface.UiBuilder.Draw -= windowSystem.Draw;
        PluginInterface.UiBuilder.OpenMainUi -= OpenMainUi;
        PluginInterface.UiBuilder.OpenConfigUi -= OpenMainUi;
        CommandManager.RemoveHandler(CommandName);
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

    private void OpenMainUi()
    {
        marketplaceWindow.IsOpen = true;
        dailyCatalogUpdate.TriggerIfDue();
    }
}
