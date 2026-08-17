using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Interface.Textures;
using Dalamud.Interface.ImGuiFileDialog;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal enum MarketplaceView
{
    Spotlight,
    Discover,
    Library,
    Updates,
}

internal enum LibrarySection
{
    All,
    Security,
    Collections,
}

internal enum MarketplaceStatusFilter
{
    All,
    Installed,
    Installable,
    OutdatedApi,
}

internal enum LibraryRuntimeFilter
{
    All,
    Loaded,
    NotLoaded,
}

internal enum MarketplaceSecurityFilter
{
    All,
    Scanned,
    NotScanned,
    CautionOrHigher,
    HighOrCritical,
}

internal enum MarketplaceContentFilter
{
    All,
    ExcludeAdult,
    AdultOnly,
}

internal enum MarketplaceSort
{
    Name,
    LastUpdated,
    Downloads,
    HighestApi,
    Version,
}

internal enum RepositoryTaskKind
{
    None,
    Integrate,
    Detach,
    SetEnabled,
}

internal enum SourceManagerSection
{
    Curated,
    UserAdded,
    DalamudConfigured,
}

internal sealed partial class MarketplaceWindow : Window, IDisposable
{
    private static readonly string[] PromotedInternalNames =
    [
        "HonseFarm.Client",
        "AetherLovePlugin",
        "InventoryTools",
        "GatherBuddy",
        "ChatTwo",
    ];
    private readonly Configuration configuration;
    private readonly MarketplaceCatalogService catalog;
    private readonly CatalogUpdateCoordinator updates;
    private readonly PluginInstallCoordinator installer;
    private readonly DalamudRepositoryBridge repositoryBridge;
    private readonly DalamudProfileBridge profileBridge;
    private readonly PluginIconCache iconCache;
    private readonly PluginRecencyLedger pluginRecency;
    private readonly PluginLibraryLedger libraryLedger;
    private readonly PluginConfigBackupService configBackups;
    private readonly OmegaSelfUpdateService selfUpdates;
    private readonly FileDialogManager fileDialogs = new();
    private readonly ISharedImmediateTexture? omegaIconTexture;
    private readonly string fallbackIconPath;
    private readonly ISharedImmediateTexture? fallbackIconTexture;
    private readonly string[] eulaLines;
    private readonly bool eulaDocumentAvailable;

    private string search = string.Empty;
    private readonly List<string> selectedAuthors = [];
    private string authorSearch = string.Empty;
    private string selectedSource = "All sources";
    private string selectedCategory = "All categories";
    private readonly List<string> selectedTags = [];
    private string tagSearch = string.Empty;
    private int selectedApi;
    private MarketplaceView activeView;
    private LibrarySection librarySection;
    private MarketplaceStatusFilter statusFilter;
    private LibraryRuntimeFilter libraryRuntimeFilter;
    private MarketplaceSecurityFilter securityFilter;
    private MarketplaceContentFilter contentFilter;
    private MarketplaceSort sort = MarketplaceSort.Name;
    private bool resetStorefrontScroll;

    private MarketplacePlugin? selectedPlugin;
    private MarketplaceView detailsReturnView = MarketplaceView.Discover;
    private LibrarySection detailsReturnLibrarySection = LibrarySection.All;
    private MarketplacePlugin? pendingInstall;
    private string pendingInstallSourceUrl = string.Empty;
    private Task<InstallResult>? installTask;
    private string installingInternalName = string.Empty;
    private MarketplacePlugin? pendingUpdate;
    private string pendingUpdatePreviousSourceUrl = string.Empty;
    private Task<UpdateResult>? updateTask;
    private string updatingInternalName = string.Empty;
    private MarketplacePlugin? pendingUninstall;
    private Task<UninstallResult>? uninstallTask;
    private string uninstallingInternalName = string.Empty;
    private string operationMessage = string.Empty;
    private Task<PluginConfigBackupResult>? configBackupTask;
    private string backingUpPluginName = string.Empty;
    private Task<PluginConfigImportResult>? configImportTask;
    private string importingPluginName = string.Empty;
    private string pendingConfigImportPath = string.Empty;
    private PluginConfigBackupInspection? pendingConfigImportInspection;
    private bool configImportFinished;
    private string configImportResultMessage = string.Empty;

    private bool detailsOpen;
    private bool filtersOpen;
    private bool settingsOpen;
    private bool aboutOpen;
    private bool installPopupOpen;
    private bool updateMigrationPopupOpen;
    private bool uninstallPopupOpen;
    private bool addSourceOpen;
    private bool requestInstallPopup;
    private bool requestUpdateMigrationPopup;
    private bool requestUninstallPopup;
    private bool requestSettingsPopup;
    private bool requestAboutPopup;
    private bool requestTagsPopup;
    private bool requestEulaPopup;
    private bool requestScreenshotPopup;
    private bool requestConfigImportPopup;
    private string selectedScreenshotUrl = string.Empty;
    private bool eulaRequiredOpen;
    private bool eulaReviewOpen;
    private DateTimeOffset? eulaOpenedAtUtc;
    private bool isMinimized;
    private bool minimizedDragMoved;
    private static readonly Vector2 DefaultExpandedWindowSize = new(1080f, 840f);
    private Vector2 expandedWindowSize = DefaultExpandedWindowSize;
    private Vector2 expandedWindowPosition;
    private bool migrateLegacyFullscreenGeometry;

    private SourceManagerSection sourceSection = SourceManagerSection.Curated;
    private string sourceSearch = string.Empty;
    private string newRepositoryName = string.Empty;
    private string newRepositoryUrl = string.Empty;
    private bool integrateNewRepositoryWithDalamud = true;

    private Task<RepositoryBridgeResult>? repositoryTask;
    private RepositorySource? repositoryTaskSource;
    private RepositoryTaskKind repositoryTaskKind;
    private readonly Dictionary<string, string> selectedVariantSource = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> stableIdCache = new(StringComparer.Ordinal);
    private readonly Dictionary<string, RepositorySource> configuredSourceByUrl = new(StringComparer.OrdinalIgnoreCase);
    private bool configuredSourceIndexValid;
    private int sourceStateRevision;

    private long sidebarCatalogRevision = -1;
    private int sidebarInstalledSignature;
    private int sidebarSourceStateRevision = -1;
    private int sidebarCurrentApi;
    private Version? sidebarDalamudVersion;
    private bool sidebarPreferTesting;
    private (int Installed, int Installable, int Outdated, int Updates) sidebarCounts;

    private long categoryCatalogRevision = -1;
    private string categorySource = string.Empty;
    private string[] cachedCategories = [];
    private bool cachedHasMoreCategories;

    private long filterCatalogRevision = -1;
    private int filterInstalledSignature;
    private int filterSourceStateRevision = -1;
    private int filterCurrentApi;
    private Version? filterDalamudVersion;
    private MarketplaceView filterView;
    private MarketplaceSort filterSort;
    private string filterSearch = string.Empty;
    private string filterAuthors = string.Empty;
    private string filterSource = string.Empty;
    private string filterCategory = string.Empty;
    private string filterTags = string.Empty;
    private int filterApi;
    private MarketplaceStatusFilter filterStatus;
    private LibraryRuntimeFilter filterLibraryRuntime;
    private MarketplaceSecurityFilter filterSecurity;
    private MarketplaceContentFilter filterContent;
    private bool filterPreferTesting;
    private MarketplacePlugin[] cachedFilteredPlugins = [];

    private readonly Dictionary<string, PluginAutomationState?> pluginAutomationStateCache = new(StringComparer.OrdinalIgnoreCase);
    private long pluginAutomationStateCatalogRevision = -1;

    private long tagPickerCatalogRevision = -1;
    private int tagPickerCurrentApi;
    private string tagPickerSource = string.Empty;
    private string tagPickerSearchCache = string.Empty;
    private string tagPickerSelectionCache = string.Empty;
    private MarketplaceTagInfo[] cachedTagPickerResults = [];
    private int cachedTagPickerMatchCount;

    public MarketplaceWindow(
        Configuration configuration,
        MarketplaceCatalogService catalog,
        CatalogUpdateCoordinator updates,
        PluginInstallCoordinator installer,
        DalamudRepositoryBridge repositoryBridge,
        DalamudProfileBridge profileBridge,
        PluginIconCache iconCache,
        PluginRecencyLedger pluginRecency,
        PluginLibraryLedger libraryLedger,
        PluginConfigBackupService configBackups,
        OmegaSelfUpdateService selfUpdates,
        string omegaIconPath,
        string fallbackIconPath,
        string eulaPath)
        : base("Omega###DalagabOmegaMain")
    {
        this.configuration = configuration;
        this.catalog = catalog;
        this.updates = updates;
        this.installer = installer;
        this.repositoryBridge = repositoryBridge;
        this.profileBridge = profileBridge;
        this.iconCache = iconCache;
        this.pluginRecency = pluginRecency;
        this.libraryLedger = libraryLedger;
        this.configBackups = configBackups;
        this.selfUpdates = selfUpdates;
        omegaIconTexture = File.Exists(omegaIconPath) ? Plugin.TextureProvider.GetFromFile(omegaIconPath) : null;
        this.fallbackIconPath = fallbackIconPath;
        fallbackIconTexture = File.Exists(fallbackIconPath) ? Plugin.TextureProvider.GetFromFile(fallbackIconPath) : null;
        eulaLines = LoadEulaLines(eulaPath, out var eulaAvailable);
        eulaDocumentAvailable = eulaAvailable;
        migrateLegacyFullscreenGeometry = configuration.WindowGeometryRevision < 1;
        Size = DefaultExpandedWindowSize;
        SizeCondition = ImGuiCond.FirstUseEver;
        SizeConstraints = new WindowSizeConstraints
        {
            MinimumSize = DefaultExpandedWindowSize,
            MaximumSize = new Vector2(float.MaxValue),
        };
        ForceMainWindow = true;
        Flags = ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse;
    }

    public void Dispose()
    {
    }

    public override void Draw()
    {
        CompleteInstallTaskIfReady();
        CompleteUpdateTaskIfReady();
        CompleteUninstallTaskIfReady();
        CompleteRepositoryTaskIfReady();
        CompleteCollectionOperationIfReady();
        CompleteConfigBackupTaskIfReady();
        CompleteConfigImportTaskIfReady();
        var versionInfo = Plugin.PluginInterface.GetDalamudVersion();
        var currentApi = Plugin.PluginInterface.Manifest.DalamudApiLevel;
        var installed = Plugin.PluginInterface.InstalledPlugins
            .Where(x => x is not null && !string.IsNullOrWhiteSpace(x.InternalName))
            .GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);
        libraryLedger.ObserveInstalled(installed.Keys);

        PushOmegaTheme();

        if (isMinimized)
        {
            DrawMinimizedWindow();
            PopOmegaTheme();
            return;
        }

        CaptureExpandedWindowState();
        CompleteLegacyFullscreenGeometryMigration();
        DrawApplicationBar();
        ImGui.Spacing();

        if (!configuration.EulaAccepted)
        {
            DrawRequiredEulaGate();
            PopOmegaTheme();
            return;
        }

        EvaluateRepositoryRiskWarnings(installed, currentApi);

        const float sidebarWidth = 64f;
        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(8f, 16f));
        ImGui.BeginChild("omega-app-sidebar", new Vector2(sidebarWidth, 0f), false,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);
        DrawSidebar(installed, currentApi, versionInfo.Version);
        ImGui.EndChild();
        ImGui.PopStyleVar();

        ImGui.SameLine(0f, 12f);
        ImGui.BeginChild("omega-app-content", Vector2.Zero, false, ImGuiWindowFlags.NoScrollbar);
        if (activeView is MarketplaceView.Library or MarketplaceView.Updates)
            DrawContentHeader(versionInfo.Version, currentApi);

        if (activeView == MarketplaceView.Library)
            DrawLibraryTabs(installed.Count);

        if (ShouldDrawMarketplaceFilters())
            DrawSearchAndCategoryButtons(currentApi);
        if (activeView != MarketplaceView.Spotlight)
            ImGui.Spacing();

        ImGui.BeginChild("omega-storefront", Vector2.Zero, false);
        DrawStorefrontLayout(installed, currentApi, versionInfo.Version);
        ImGui.EndChild();
        ImGui.EndChild();

        OpenRequestedPopups();
        DrawInstallModal(currentApi, versionInfo.Version);
        DrawUpdateMigrationModal(currentApi, versionInfo.Version);
        DrawUninstallModal();
        DrawSettingsModal();
        DrawAboutModal();
        DrawEulaReviewModal();
        DrawTagPickerPopup(currentApi);
        DrawScreenshotViewerModal();
        DrawRepositoryRiskModal();
        DrawConfigImportModal();
        fileDialogs.Draw();

        PopOmegaTheme();
    }

    private void OpenRequestedPopups()
    {
        if (requestInstallPopup)
        {
            ImGui.OpenPopup("Choose repository###DalagabOmegaInstall");
            requestInstallPopup = false;
        }

        if (requestUpdateMigrationPopup)
        {
            ImGui.OpenPopup("Move plugin repository###DalagabOmegaUpdateMigration");
            requestUpdateMigrationPopup = false;
        }

        if (requestUninstallPopup)
        {
            ImGui.OpenPopup("Uninstall plugin###DalagabOmegaUninstall");
            requestUninstallPopup = false;
        }

        if (requestSettingsPopup)
        {
            ImGui.OpenPopup("Settings###DalagabOmegaSettings");
            requestSettingsPopup = false;
        }

        if (requestAboutPopup)
        {
            ImGui.OpenPopup(AboutPopupId);
            requestAboutPopup = false;
        }

        if (requestTagsPopup)
        {
            ImGui.OpenPopup("Tags###DalagabOmegaTags");
            requestTagsPopup = false;
        }

        if (requestScreenshotPopup)
        {
            ImGui.OpenPopup(ScreenshotPopupId);
            requestScreenshotPopup = false;
        }

        if (requestEulaPopup)
        {
            ImGui.OpenPopup(EulaPopupId);
            requestEulaPopup = false;
        }

        if (requestRepositoryRiskPopup)
        {
            ImGui.OpenPopup(RepositoryRiskPopupId);
            requestRepositoryRiskPopup = false;
        }

        if (requestConfigImportPopup)
        {
            ImGui.OpenPopup("Import configuration backup###DalagabOmegaConfigImport");
            requestConfigImportPopup = false;
        }
    }
}
