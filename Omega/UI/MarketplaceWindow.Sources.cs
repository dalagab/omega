using System.Diagnostics;
using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private sealed record RepositorySettingsSnapshot(
        IReadOnlyDictionary<string, RepositoryCatalogStatus> Statuses,
        IReadOnlyList<DalamudRepositoryRegistration> DalamudRepositories,
        IReadOnlyDictionary<string, DalamudRepositoryRegistration> DalamudByUrl,
        IReadOnlyDictionary<string, DalamudRepositoryUsage> InstalledUsage,
        IReadOnlySet<string> DefinitionsUrls,
        IReadOnlySet<string> DivergentUrls,
        IReadOnlyDictionary<string, int[]> ApiLevelsByUrl,
        int[] AvailableApiLevels,
        int InstalledSignature);

    private RepositorySettingsSnapshot? repositorySettingsSnapshot;
    private long repositorySettingsCatalogRevision = -1;
    private int repositorySettingsSourceRevision = -1;
    private int repositorySettingsInstalledSignature;
    private string repositoryVisibleRowsKey = string.Empty;
    private RepositorySource[] repositoryVisibleRows = [];

    private void DrawSettingsModal()
    {
        if (!settingsOpen)
            return;

        var keepOpen = settingsOpen;
        ImGui.SetNextWindowSize(UiModalSize(920f, 660f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal("Settings###DalagabOmegaSettings", ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoCollapse |
                ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse))
        {
            settingsOpen = keepOpen;
            return;
        }

        // The modal itself never scrolls. Keeping Omega chrome and tabs outside any scrolling
        // child means the close cross remains visible regardless of repository-list position.
        if (DrawOmegaModalHeader("Settings", "settings"))
        {
            settingsOpen = false;
            ImGui.CloseCurrentPopup();
            ImGui.EndPopup();
            return;
        }

        DrawSettingsTabs();
        ImGui.Separator();
        ImGui.Spacing();

        var currentApi = Plugin.PluginInterface.Manifest.DalamudApiLevel;
        switch (settingsSection)
        {
            case SettingsSection.General:
                // General can grow as user-facing preferences are added. Keep the Settings header
                // and tab bar fixed while the body scrolls, so Install permissions is always reachable.
                ImGui.BeginChild("omega-settings-general-scroll", Vector2.Zero, false,
                    ImGuiWindowFlags.AlwaysVerticalScrollbar);
                DrawSettingsGeneralTab();
                ImGui.EndChild();
                break;
            case SettingsSection.Community:
                DrawSettingsCommunityTab();
                break;
            case SettingsSection.Legal:
                if (DrawSettingsLegalTab())
                {
                    settingsOpen = keepOpen && settingsOpen;
                    ImGui.EndPopup();
                    return;
                }
                break;
            default:
                DrawSettingsRepositoriesTab(currentApi);
                break;
        }

        settingsOpen = keepOpen && settingsOpen;
        ImGui.EndPopup();
    }

    private void DrawSettingsTabs()
    {
        if (DrawRoundedButton("General", "settings-tab-general", Ui(112f, 32f), settingsSection == SettingsSection.General))
            settingsSection = SettingsSection.General;
        ImGui.SameLine(0f, Ui(8f));
        if (DrawRoundedButton("Repositories", "settings-tab-repositories", Ui(142f, 32f), settingsSection == SettingsSection.Repositories))
            settingsSection = SettingsSection.Repositories;
        ImGui.SameLine(0f, Ui(8f));
        if (DrawRoundedButton("Community", "settings-tab-community", Ui(128f, 32f), settingsSection == SettingsSection.Community))
            settingsSection = SettingsSection.Community;
        ImGui.SameLine(0f, Ui(8f));
        if (DrawRoundedButton("Legal", "settings-tab-legal", Ui(104f, 32f), settingsSection == SettingsSection.Legal))
            settingsSection = SettingsSection.Legal;
    }

    private void DrawSettingsRepositoriesTab(int currentApi)
    {
        var snapshot = GetRepositorySettingsSnapshot(currentApi);
        if (EnsureDalamudRepositoriesRemainSelected(snapshot))
            snapshot = GetRepositorySettingsSnapshot(currentApi);

        var shownSources = GetVisibleSourceRows(currentApi, snapshot);
        DrawSourcesHeader(currentApi, snapshot, shownSources);
        if (addSourceOpen)
            DrawAddSourceTools();

        if (sourceSection == SourceManagerSection.Curated)
            DrawSourceBulkSelection(shownSources, snapshot);

        var unmanaged = sourceSection == SourceManagerSection.DalamudConfigured
            ? shownSources.Where(x => !snapshot.DefinitionsUrls.Contains(NormalizeUrl(x.Url))).ToArray()
            : Array.Empty<RepositorySource>();
        DrawSourcesTable(shownSources, snapshot, unmanaged.Length > 0, currentApi);
        if (unmanaged.Length > 0)
            DrawUnmanagedSourceSubmissionFooter(unmanaged);
    }

    private RepositorySettingsSnapshot GetRepositorySettingsSnapshot(int currentApi)
    {
        var installed = Plugin.PluginInterface.InstalledPlugins
            .Where(x => x is not null &&
                        !string.IsNullOrWhiteSpace(x.InternalName) &&
                        !x.Manifest.ScheduledForDeletion)
            .GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);
        var installedSignature = GetInstalledSignature(installed);
        var catalogRevision = catalog.Revision;

        if (repositorySettingsSnapshot is not null &&
            repositorySettingsCatalogRevision == catalogRevision &&
            repositorySettingsSourceRevision == sourceStateRevision &&
            repositorySettingsInstalledSignature == installedSignature)
            return repositorySettingsSnapshot;

        var statuses = catalog.GetRepositoryInventoryStatuses(currentApi)
            .ToDictionary(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase);
        var dalamudRepositories = repositoryBridge.GetConfiguredRepositories();
        var dalamudByUrl = dalamudRepositories
            .GroupBy(x => NormalizeUrl(x.Url), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);
        var installedUsage = repositoryBridge.GetInstalledPluginUsageByRepository();

        var knownUrls = configuration.Repositories.Select(x => NormalizeUrl(x.Url))
            .Concat(dalamudRepositories.Select(x => NormalizeUrl(x.Url)))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var definitionsUrls = knownUrls
            .Where(catalog.IsSourceInDefinitions)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var apiSets = new Dictionary<string, HashSet<int>>(StringComparer.OrdinalIgnoreCase);
        var divergentUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var variant in catalog.GetRepositoryInventoryVariants())
        {
            var normalized = NormalizeUrl(variant.SourceUrl);
            if (string.IsNullOrWhiteSpace(normalized))
                continue;

            if (!apiSets.TryGetValue(normalized, out var levels))
            {
                levels = [];
                apiSets[normalized] = levels;
            }

            AddRepositoryApiLevel(levels, variant.DalamudApiLevel);
            AddRepositoryApiLevel(levels, variant.TestingDalamudApiLevel ?? 0);
            if (variant.OmegaMinimumApiLevel is int minimum && variant.OmegaMaximumApiLevel is int maximum &&
                minimum > 0 && maximum >= minimum && maximum - minimum <= 32)
            {
                for (var api = minimum; api <= maximum; api++)
                    AddRepositoryApiLevel(levels, api);
            }

            if (variant.SecurityFindings.Any(finding =>
                    finding.RuleId.Equals("artifact.cross-source-hash-mismatch", StringComparison.OrdinalIgnoreCase)))
                divergentUrls.Add(normalized);
        }

        foreach (var (normalized, status) in statuses)
        {
            if (!apiSets.TryGetValue(normalized, out var levels))
            {
                levels = [];
                apiSets[normalized] = levels;
            }
            AddRepositoryApiLevel(levels, status.HighestKnownApiLevel);
        }

        var apiLevelsByUrl = apiSets.ToDictionary(
            x => x.Key,
            x => x.Value.OrderByDescending(level => level).ToArray(),
            StringComparer.OrdinalIgnoreCase);
        var availableApiLevels = apiLevelsByUrl.Values
            .SelectMany(x => x)
            .Append(currentApi)
            .Where(x => x > 0)
            .Distinct()
            .OrderByDescending(x => x)
            .ToArray();

        repositorySettingsSnapshot = new RepositorySettingsSnapshot(
            statuses,
            dalamudRepositories,
            dalamudByUrl,
            installedUsage,
            definitionsUrls,
            divergentUrls,
            apiLevelsByUrl,
            availableApiLevels,
            installedSignature);
        repositorySettingsCatalogRevision = catalogRevision;
        repositorySettingsSourceRevision = sourceStateRevision;
        repositorySettingsInstalledSignature = installedSignature;
        repositoryVisibleRowsKey = string.Empty;
        return repositorySettingsSnapshot;
    }

    private static void AddRepositoryApiLevel(HashSet<int> levels, int api)
    {
        if (api > 0)
            levels.Add(api);
    }

    private bool EnsureDalamudRepositoriesRemainSelected(RepositorySettingsSnapshot snapshot)
    {
        var changed = false;
        foreach (var source in configuration.Repositories)
        {
            var protectedByDalamud = snapshot.DalamudByUrl.ContainsKey(NormalizeUrl(source.Url));
            if ((!source.IsOfficial && !protectedByDalamud) || source.Enabled)
                continue;
            source.Enabled = true;
            changed = true;
        }

        if (!changed)
            return false;

        configuration.Save();
        InvalidateSourceCaches();
        catalog.LoadCached(configuration.Repositories);
        operationMessage = "Repositories already configured in Dalamud were kept enabled in Omega.";
        return true;
    }

    private void DrawSourcesHeader(
        int currentApi,
        RepositorySettingsSnapshot snapshot,
        IReadOnlyList<RepositorySource> shownSources)
    {
        var selectedApis = GetSelectedRepositoryApiLevels(currentApi);
        var curatedCount = configuration.Repositories
            .Where(x => x.IsCurated)
            .Count(x => IsRepositoryVisibleInSettings(x.Url, snapshot.Statuses) &&
                        RepositoryMatchesApiFilter(x.Url, RepositoryStatus(snapshot, x.Url), snapshot, selectedApis, false));
        var dalamudCount = snapshot.DalamudRepositories
            .Count(x => IsDalamudRepositoryVisibleInSettings(x.Url, snapshot.Statuses) &&
                        RepositoryMatchesApiFilter(x.Url, RepositoryStatus(snapshot, x.Url), snapshot, selectedApis, true));

        ImGui.TextDisabled("Plugin sources");
        ImGui.TextWrapped(sourceSection == SourceManagerSection.DalamudConfigured
            ? "Repositories configured in Dalamud. Omega will not disable an existing Dalamud repository from this screen."
            : "Repositories published through Omega Definitions. Choose which full Dalamud API versions you want to see.");
        ImGui.Separator();

        if (DrawPillButton($"Omega ({curatedCount})", "sources-curated", Ui(126f, 32f), sourceSection == SourceManagerSection.Curated))
        {
            sourceSection = SourceManagerSection.Curated;
            sourceSearch = string.Empty;
            repositoryVisibleRowsKey = string.Empty;
        }
        ImGui.SameLine();
        if (DrawPillButton($"Dalamud ({dalamudCount})", "sources-dalamud", Ui(132f, 32f), sourceSection == SourceManagerSection.DalamudConfigured))
        {
            sourceSection = SourceManagerSection.DalamudConfigured;
            sourceSearch = string.Empty;
            repositoryVisibleRowsKey = string.Empty;
        }
        ImGui.SameLine();
        if (DrawPillButton(addSourceOpen ? "Hide add tools" : "Add source", "sources-add", Ui(128f, 32f), addSourceOpen))
            addSourceOpen = !addSourceOpen;

        DrawRepositoryApiFilter(currentApi, snapshot.AvailableApiLevels);

        ImGui.SetNextItemWidth(Math.Min(Ui(520f), ImGui.GetContentRegionAvail().X));
        ImGui.InputTextWithHint("##source-search", "Filter repositories by name or URL...", ref sourceSearch, 256);
        if (ImGui.IsItemEdited())
            repositoryVisibleRowsKey = string.Empty;

        ImGui.SameLine();
        ImGui.TextDisabled($"{shownSources.Count} shown");
    }

    private void DrawRepositoryApiFilter(int currentApi, IReadOnlyList<int> availableApiLevels)
    {
        var available = availableApiLevels
            .Where(x => x > 0)
            .Distinct()
            .OrderByDescending(x => x)
            .ToArray();
        var selected = GetSelectedRepositoryApiLevels(currentApi);

        var allSelected = configuration.RepositoryApiLevelsCustomized &&
                          available.Length > 0 &&
                          available.All(selected.Contains);
        var selectionLabel = !configuration.RepositoryApiLevelsCustomized
            ? $"Current API {currentApi}"
            : allSelected
                ? "All APIs"
                : selected.Count == 1
                    ? $"API {selected.First()}"
                    : $"{selected.Count} APIs selected";

        ImGui.Spacing();
        ImGui.TextDisabled("API versions to show");
        ImGui.SameLine();
        ImGui.SetNextItemWidth(Math.Min(Ui(240f), Math.Max(Ui(170f), ImGui.GetContentRegionAvail().X)));
        if (ImGui.BeginCombo("##repository-api-selector", selectionLabel))
        {
            var keepOpen = ImGuiSelectableFlags.DontClosePopups;
            if (ImGui.Selectable(
                    $"Current only (API {currentApi})##repository-api-current",
                    !configuration.RepositoryApiLevelsCustomized,
                    keepOpen))
            {
                configuration.RepositoryApiLevelsCustomized = false;
                configuration.RepositoryApiLevels = [];
                repositoryApiSelectionAnchor = currentApi;
                configuration.Save();
                repositoryVisibleRowsKey = string.Empty;
                selected = GetSelectedRepositoryApiLevels(currentApi);
            }

            if (ImGui.Selectable(
                    "All APIs##repository-api-all",
                    allSelected,
                    keepOpen))
            {
                configuration.RepositoryApiLevelsCustomized = true;
                configuration.RepositoryApiLevels = available.OrderBy(x => x).ToList();
                repositoryApiSelectionAnchor = null;
                configuration.Save();
                repositoryVisibleRowsKey = string.Empty;
                selected = GetSelectedRepositoryApiLevels(currentApi);
            }

            ImGui.Separator();
            for (var index = 0; index < available.Length; index++)
            {
                var api = available[index];
                var isSelected = selected.Contains(api);
                if (!ImGui.Selectable($"API {api}##repository-api-{api}", isSelected, keepOpen))
                    continue;

                var next = selected.ToHashSet();
                var io = ImGui.GetIO();
                if (io.KeyShift && repositoryApiSelectionAnchor is { } anchor)
                {
                    var anchorIndex = Array.IndexOf(available, anchor);
                    if (anchorIndex < 0)
                        anchorIndex = index;
                    if (!io.KeyCtrl)
                        next.Clear();
                    var first = Math.Min(anchorIndex, index);
                    var last = Math.Max(anchorIndex, index);
                    for (var rangeIndex = first; rangeIndex <= last; rangeIndex++)
                        next.Add(available[rangeIndex]);
                }
                else if (io.KeyCtrl)
                {
                    if (!next.Add(api))
                        next.Remove(api);
                    repositoryApiSelectionAnchor = api;
                }
                else
                {
                    next.Clear();
                    next.Add(api);
                    repositoryApiSelectionAnchor = api;
                }

                configuration.RepositoryApiLevelsCustomized = true;
                configuration.RepositoryApiLevels = next.OrderBy(x => x).ToList();
                configuration.Save();
                repositoryVisibleRowsKey = string.Empty;
                selected = next;
            }

            ImGui.Separator();
            ImGui.TextDisabled("Click = one · Shift-click = range · Ctrl-click = toggle");
            ImGui.EndCombo();
        }

        ImGui.TextDisabled(configuration.RepositoryApiLevelsCustomized
            ? "This only filters the repository manager. Existing Dalamud repositories are protected from bulk disable."
            : $"Default: current API {currentApi} only. Existing Dalamud repositories are protected from bulk disable.");
    }

    private HashSet<int> GetSelectedRepositoryApiLevels(int currentApi)
    {
        if (!configuration.RepositoryApiLevelsCustomized)
            return [currentApi];
        return configuration.RepositoryApiLevels
            .Where(x => x > 0)
            .ToHashSet();
    }

    private static bool IsRepositoryVisibleInSettings(
        string sourceUrl,
        IReadOnlyDictionary<string, RepositoryCatalogStatus> statuses)
    {
        return statuses.TryGetValue(NormalizeUrl(sourceUrl), out var status) &&
               (status.PluginCount > 0 || status.HighestKnownApiLevel > 0);
    }

    private static bool IsDalamudRepositoryVisibleInSettings(
        string sourceUrl,
        IReadOnlyDictionary<string, RepositoryCatalogStatus> statuses)
        => !string.IsNullOrWhiteSpace(sourceUrl) &&
           (!statuses.TryGetValue(NormalizeUrl(sourceUrl), out var status) ||
            status.PluginCount > 0 || status.HighestKnownApiLevel > 0);

    private static RepositoryCatalogStatus? RepositoryStatus(RepositorySettingsSnapshot snapshot, string sourceUrl)
        => snapshot.Statuses.TryGetValue(NormalizeUrl(sourceUrl), out var status) ? status : null;

    private RepositorySource[] GetVisibleSourceRows(int currentApi, RepositorySettingsSnapshot snapshot)
    {
        var selectedApis = GetSelectedRepositoryApiLevels(currentApi);
        var apiKey = string.Join(",", selectedApis.OrderBy(x => x));
        var key = string.Join("\u001f",
            catalog.Revision,
            sourceStateRevision,
            snapshot.InstalledSignature,
            sourceSection,
            sourceSearch.Trim(),
            apiKey);
        if (key.Equals(repositoryVisibleRowsKey, StringComparison.Ordinal))
            return repositoryVisibleRows;

        var query = sourceSearch.Trim();
        if (sourceSection == SourceManagerSection.DalamudConfigured)
        {
            repositoryVisibleRows = snapshot.DalamudRepositories
                .Where(registration => IsDalamudRepositoryVisibleInSettings(registration.Url, snapshot.Statuses))
                .Select(registration =>
                {
                    var normalized = NormalizeUrl(registration.Url);
                    var configured = configuration.Repositories.FirstOrDefault(x =>
                        NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase));
                    if (configured is not null)
                        return configured;

                    snapshot.Statuses.TryGetValue(normalized, out var known);
                    return new RepositorySource
                    {
                        Name = known?.SourceName ?? RepositoryDisplayNameFromUrl(registration.Url),
                        Url = registration.Url,
                        Enabled = registration.Enabled,
                        IsCurated = false,
                        IsExperimental = true,
                        IntegrateWithDalamud = true,
                        DalamudManagedByOmega = false,
                    };
                })
                .Where(x => RepositoryMatchesApiFilter(
                    x.Url,
                    RepositoryStatus(snapshot, x.Url),
                    snapshot,
                    selectedApis,
                    true))
                .Where(x => string.IsNullOrWhiteSpace(query) || Contains(x.Name, query) || Contains(x.Url, query))
                .OrderByDescending(x => snapshot.DivergentUrls.Contains(NormalizeUrl(x.Url)))
                .ThenBy(x => snapshot.DefinitionsUrls.Contains(NormalizeUrl(x.Url)) ? 0 : 1)
                .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        else
        {
            repositoryVisibleRows = configuration.Repositories
                .Where(x => x.IsCurated)
                .Where(x => IsRepositoryVisibleInSettings(x.Url, snapshot.Statuses))
                .Where(x => RepositoryMatchesApiFilter(
                    x.Url,
                    RepositoryStatus(snapshot, x.Url),
                    snapshot,
                    selectedApis,
                    false))
                .Where(x => string.IsNullOrWhiteSpace(query) || Contains(x.Name, query) || Contains(x.Url, query))
                .OrderBy(x => RepositoryProviderRules.SortPriority(
                    x.Name,
                    x.Url,
                    x.IsOfficial,
                    snapshot.Statuses.TryGetValue(NormalizeUrl(x.Url), out var status) ? status.PluginCount : 0))
                .ThenByDescending(x => snapshot.Statuses.TryGetValue(NormalizeUrl(x.Url), out var status) ? status.PluginCount : 0)
                .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        repositoryVisibleRowsKey = key;
        return repositoryVisibleRows;
    }

    private static bool RepositoryMatchesApiFilter(
        string sourceUrl,
        RepositoryCatalogStatus? status,
        RepositorySettingsSnapshot snapshot,
        IReadOnlySet<int> selectedApis,
        bool keepUnknownDalamudSource)
    {
        var normalized = NormalizeUrl(sourceUrl);
        if (snapshot.ApiLevelsByUrl.TryGetValue(normalized, out var levels) && levels.Length > 0)
            return selectedApis.Count > 0 && levels.Any(selectedApis.Contains);

        if (status is not null && status.HighestKnownApiLevel > 0)
            return selectedApis.Contains(status.HighestKnownApiLevel);

        // Unknown local Dalamud rows stay manageable even though they cannot be assigned to an API filter.
        return keepUnknownDalamudSource;
    }

    private void DrawSourceBulkSelection(
        IReadOnlyList<RepositorySource> shownSources,
        RepositorySettingsSnapshot snapshot)
    {
        ImGui.Spacing();
        var protectedCount = shownSources.Count(source =>
            source.IsOfficial || snapshot.DalamudByUrl.ContainsKey(NormalizeUrl(source.Url)));
        if (ImGui.SmallButton("Use shown##repository-use-shown"))
            ApplyBulkRepositorySelection(shownSources, snapshot, enabled: true);
        ImGui.SameLine();
        if (ImGui.SmallButton("Don't use shown##repository-disable-shown"))
            ApplyBulkRepositorySelection(shownSources, snapshot, enabled: false);
        if (protectedCount > 0)
        {
            ImGui.SameLine();
            ImGui.TextDisabled($"{protectedCount} protected by Dalamud");
        }
    }

    private void ApplyBulkRepositorySelection(
        IReadOnlyList<RepositorySource> shownSources,
        RepositorySettingsSnapshot snapshot,
        bool enabled)
    {
        var changed = 0;
        var protectedCount = 0;
        foreach (var source in shownSources)
        {
            var protectedByDalamud = source.IsOfficial || snapshot.DalamudByUrl.ContainsKey(NormalizeUrl(source.Url));
            if (!enabled && protectedByDalamud)
            {
                protectedCount++;
                continue;
            }
            if (source.Enabled == enabled)
                continue;
            source.Enabled = enabled;
            changed++;
        }

        if (changed > 0)
        {
            configuration.Save();
            InvalidateSourceCaches();
            catalog.LoadCached(configuration.Repositories);
        }

        operationMessage = enabled
            ? $"Enabled {changed} shown Omega repositor{(changed == 1 ? "y" : "ies")}."
            : $"Disabled {changed} shown Omega repositor{(changed == 1 ? "y" : "ies")}." +
              (protectedCount > 0 ? $" {protectedCount} existing Dalamud repositor{(protectedCount == 1 ? "y was" : "ies were")} kept enabled." : string.Empty);
    }

    private void DrawSourcesTable(
        IReadOnlyList<RepositorySource> shownSources,
        RepositorySettingsSnapshot snapshot,
        bool reserveSubmissionFooter,
        int currentApi)
    {
        ImGui.Spacing();
        var footerReserve = reserveSubmissionFooter ? Ui(66f) : 0f;
        var tableHeight = Math.Max(Ui(160f), ImGui.GetContentRegionAvail().Y - footerReserve);
        var tableFlags = ImGuiTableFlags.ScrollY | ImGuiTableFlags.RowBg |
                         ImGuiTableFlags.BordersInnerH | ImGuiTableFlags.SizingStretchProp;
        var isDalamudView = sourceSection == SourceManagerSection.DalamudConfigured;
        var columnCount = isDalamudView ? 7 : 5;
        if (!ImGui.BeginTable("omega-source-table", columnCount, tableFlags,
                new Vector2(Math.Min(Ui(920f), ImGui.GetContentRegionAvail().X), tableHeight), 0f))
            return;

        ImGui.TableSetupScrollFreeze(0, 1);
        ImGui.TableSetupColumn("Use", ImGuiTableColumnFlags.WidthFixed, Ui(44f));
        ImGui.TableSetupColumn("Repository", ImGuiTableColumnFlags.WidthStretch);
        ImGui.TableSetupColumn(isDalamudView ? "Available" : "Plugins", ImGuiTableColumnFlags.WidthFixed, Ui(64f));
        if (isDalamudView)
            ImGui.TableSetupColumn("Installed", ImGuiTableColumnFlags.WidthFixed, Ui(72f));
        ImGui.TableSetupColumn("API", ImGuiTableColumnFlags.WidthFixed, Ui(72f));
        ImGui.TableSetupColumn("State", ImGuiTableColumnFlags.WidthFixed, Ui(isDalamudView ? 150f : 120f));
        if (isDalamudView)
            ImGui.TableSetupColumn("Action", ImGuiTableColumnFlags.WidthFixed, Ui(82f));
        ImGui.TableHeadersRow();

        // Repositories can number in the hundreds. Only draw the rows currently visible in the
        // scroll viewport; provider artwork and per-row UI therefore stay proportional to what the
        // user can actually see instead of the full Definitions inventory.
        var clipper = ImGui.ImGuiListClipper();
        clipper.Begin(shownSources.Count, ImGui.GetFrameHeightWithSpacing());
        while (clipper.Step())
        {
            for (var index = clipper.DisplayStart; index < clipper.DisplayEnd; index++)
            {
                var source = shownSources[index];
                var normalized = NormalizeUrl(source.Url);
                snapshot.Statuses.TryGetValue(normalized, out var status);
                snapshot.DalamudByUrl.TryGetValue(normalized, out var dalamudRegistration);
                snapshot.InstalledUsage.TryGetValue(normalized, out var usage);
                snapshot.ApiLevelsByUrl.TryGetValue(normalized, out var apiLevels);
                DrawSourceRow(
                    source,
                    status,
                    dalamudRegistration,
                    usage ?? DalamudRepositoryUsage.Empty,
                    snapshot.DefinitionsUrls.Contains(normalized),
                    snapshot.DivergentUrls.Contains(normalized),
                    apiLevels ?? [],
                    currentApi);
            }
        }
        ImGui.EndTable();
    }

    private void DrawSourceRow(
        RepositorySource source,
        RepositoryCatalogStatus? status,
        DalamudRepositoryRegistration? dalamudRegistration,
        DalamudRepositoryUsage usage,
        bool inDefinitions,
        bool divergent,
        IReadOnlyList<int> apiLevels,
        int currentApi)
    {
        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        if (sourceSection == SourceManagerSection.DalamudConfigured)
        {
            var enabledInDalamud = dalamudRegistration?.Enabled == true;
            ImGui.BeginDisabled();
            ImGui.Checkbox($"##dalamud-source-enabled-{StableId(source.Url)}", ref enabledInDalamud);
            ImGui.EndDisabled();
            if (ImGui.IsItemHovered())
                SetReadableTooltip(enabledInDalamud ? "Enabled in Dalamud" : "Configured but disabled in Dalamud");
        }
        else
        {
            DrawSourceEnabledCheckbox(source, source.IsOfficial || dalamudRegistration is not null);
        }

        ImGui.TableSetColumnIndex(1);
        var unmanagedDalamudSource = sourceSection == SourceManagerSection.DalamudConfigured && !inDefinitions;
        if (unmanagedDalamudSource)
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.34f, 0.64f, 0.98f, 1f));
        DrawRepositoryName(
            source.Name,
            source.Url,
            source.IsOfficial,
            currentApi,
            knownPluginCount: status?.PluginCount ?? 0);
        if (unmanagedDalamudSource)
            ImGui.PopStyleColor();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(unmanagedDalamudSource
                ? $"{source.Url}\nUnmanaged local source: configured in Dalamud but not present in Omega online Definitions."
                : source.Url);

        ImGui.TableSetColumnIndex(2);
        ImGui.Text(status?.PluginCount.ToString() ?? "—");

        var nextColumn = 3;
        if (sourceSection == SourceManagerSection.DalamudConfigured)
        {
            ImGui.TableSetColumnIndex(nextColumn++);
            ImGui.TextUnformatted(usage.InstalledCount.ToString());
            if (usage.InstalledCount > 0 && ImGui.IsItemHovered())
                SetReadableTooltip($"Installed from this repository: {string.Join(", ", usage.PluginNames)}");
        }

        ImGui.TableSetColumnIndex(nextColumn++);
        ImGui.TextUnformatted(FormatRepositoryApiLevels(apiLevels, status));
        if (apiLevels.Count > 1 && ImGui.IsItemHovered())
            SetReadableTooltip($"Known full API versions: {string.Join(", ", apiLevels.OrderByDescending(x => x))}");

        ImGui.TableSetColumnIndex(nextColumn++);
        if (sourceSection == SourceManagerSection.DalamudConfigured)
        {
            DrawDalamudSourceReviewState(source, status, dalamudRegistration, inDefinitions);
            ImGui.TableSetColumnIndex(nextColumn);
            DrawDalamudRepositoryRemoveAction(source, usage, inDefinitions);
        }
        else
        {
            DrawSourceState(source, status, dalamudRegistration, divergent);
        }
    }

    private static string FormatRepositoryApiLevels(IReadOnlyList<int> levels, RepositoryCatalogStatus? status)
    {
        if (levels.Count == 0)
            return status is null || status.HighestKnownApiLevel <= 0 ? "?" : status.HighestKnownApiLevel.ToString();
        if (levels.Count <= 3)
            return string.Join(",", levels.OrderByDescending(x => x));
        var newest = levels.OrderByDescending(x => x).Take(2);
        return $"{string.Join(",", newest)}…";
    }

    private void DrawDalamudRepositoryRemoveAction(RepositorySource source, DalamudRepositoryUsage usage, bool inDefinitions)
    {
        var blockedByInstalledPlugins = usage.InstalledCount > 0;
        var busy = repositoryTask is not null;
        ImGui.BeginDisabled(blockedByInstalledPlugins || busy);
        if (ImGui.SmallButton($"Remove##dalamud-remove-{StableId(source.Url)}"))
            StartRepositoryTask(source, RepositoryTaskKind.Detach, repositoryBridge.RemoveIfUnusedAsync(source.Url));
        ImGui.EndDisabled();

        if (!ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
            return;

        if (blockedByInstalledPlugins)
        {
            var names = string.Join(", ", usage.PluginNames.Take(8));
            var suffix = usage.PluginNames.Count > 8 ? $" (+{usage.PluginNames.Count - 8} more)" : string.Empty;
            SetReadableTooltip($"Cannot remove this repository while {usage.InstalledCount} installed plugin(s) use it. Installed includes enabled and disabled plugins because both still retain this repository as their servicing source. {names}{suffix}");
        }
        else if (busy)
        {
            SetReadableTooltip("Another repository operation is still running.");
        }
        else
        {
            SetReadableTooltip(inDefinitions
                ? "Remove this repository from Dalamud. Its online Omega Definitions entry remains available. Removal is allowed only when no installed plugin still points at this repository."
                : "Remove this unmanaged repository from Dalamud. Its temporary local Omega overlay is removed as well. Removal is allowed only when no installed plugin still points at this repository.");
        }
    }

    private void DrawDalamudSourceReviewState(
        RepositorySource source,
        RepositoryCatalogStatus? status,
        DalamudRepositoryRegistration? dalamudRegistration,
        bool inDefinitions)
    {
        var normalized = NormalizeUrl(source.Url);
        var notice = repositoryRiskAllNotices.FirstOrDefault(x =>
            NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase));
        if (notice is not null)
        {
            var acknowledged = IsRepositoryRiskAcknowledged(notice);
            ImGui.TextColored(
                acknowledged ? new Vector4(0.95f, 0.64f, 0.20f, 1f) : new Vector4(0.96f, 0.30f, 0.24f, 1f),
                acknowledged ? "Risk acknowledged" : "Review required");
            if (ImGui.IsItemHovered())
                SetReadableTooltip($"{notice.DivergentArtifactCount} plugin package(s) from this repository differ from Omega's package baseline. Example: {notice.ExamplePlugin}.");
            if (!acknowledged)
            {
                ImGui.SameLine(0f, 8f);
                if (ImGui.SmallButton($"Acknowledge risk##ack-source-risk-{StableId(source.Url)}"))
                {
                    AcknowledgeRepositoryRisk(notice);
                    operationMessage = $"Acknowledged the current package-divergence evidence for {notice.Name}. A changed risk fingerprint will require review again.";
                }
            }
            return;
        }

        if (!inDefinitions)
        {
            ImGui.TextColored(new Vector4(0.34f, 0.64f, 0.98f, 1f),
                dalamudRegistration?.Enabled == true ? "Unmanaged local • enabled" : "Unmanaged local • disabled");
            if (ImGui.IsItemHovered())
                SetReadableTooltip(configuration.TrustUnrecognizedSources
                    ? "This repository exists locally in Dalamud but is not part of Omega's online Definitions. You chose to trust unrecognized source identity; Omega still reports security, permission, package, compatibility, and support concerns."
                    : "This repository exists locally in Dalamud but is not part of Omega's online Definitions. Omega can show its plugins as a temporary unmanaged overlay. Installing from an unrecognized source still requires explicit acknowledgement in the install flow.");
            return;
        }

        if (RepositoryProviderRules.RequiresExplicitInstallAcknowledgement(source.Name, source.Url, source.IsOfficial))
        {
            ImGui.TextColored(new Vector4(0.95f, 0.64f, 0.20f, 1f),
                "Unrecognized community");
            if (ImGui.IsItemHovered())
                SetReadableTooltip(configuration.TrustUnrecognizedSources
                    ? "This repository is outside Omega's recognized provider set. You chose to trust unrecognized source identity, so Omega skips that acknowledgement only; findings and other install protections remain active."
                    : "This repository is present in Omega Definitions but is outside Omega's recognized provider set. Installation from it requires explicit source acknowledgement; this is separate from Sigmascope findings.");
            return;
        }

        if (dalamudRegistration?.Enabled == true)
            ImGui.TextColored(new Vector4(0.34f, 0.86f, 0.61f, 1f), status is null ? "Enabled • not in Definitions" : "Enabled");
        else
            ImGui.TextDisabled(status is null ? "Disabled • not in Definitions" : "Disabled");
    }

    private static string RepositoryDisplayNameFromUrl(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host)
            ? uri.Host
            : "Dalamud repository";

    private void DrawSourceEnabledCheckbox(RepositorySource source, bool protectedByDalamud)
    {
        var enabled = source.Enabled || protectedByDalamud;
        ImGui.BeginDisabled(protectedByDalamud);
        var changed = ImGui.Checkbox($"##source-enabled-{StableId(source.Url)}", ref enabled);
        ImGui.EndDisabled();
        if (protectedByDalamud && ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
            SetReadableTooltip(source.IsOfficial
                ? "Built-in Dalamud repositories stay available."
                : "This repository already exists in Dalamud, so Omega will not disable it here. Manage the Dalamud registration from the Dalamud tab.");
        if (!changed || protectedByDalamud)
            return;

        source.Enabled = enabled;
        InvalidateSourceCaches();
        configuration.Save();
        catalog.LoadCached(configuration.Repositories);
        operationMessage = $"{source.Name} {(enabled ? "enabled" : "disabled")} in Omega.";
        if (!source.IsOfficial && source.IntegrateWithDalamud && source.DalamudManagedByOmega && repositoryTask is null)
            StartRepositoryTask(source, RepositoryTaskKind.SetEnabled, repositoryBridge.SetManagedEnabledAsync(source.Url, enabled));
    }

    private void DrawSourceState(
        RepositorySource source,
        RepositoryCatalogStatus? status,
        DalamudRepositoryRegistration? dalamudRegistration,
        bool divergent)
    {
        var dalamudPresent = source.IsOfficial || dalamudRegistration is not null;
        var dalamudEnabled = source.IsOfficial || dalamudRegistration?.Enabled == true;

        if (divergent)
        {
            ImGui.TextColored(new Vector4(0.96f, 0.30f, 0.24f, 1f), "Review");
            if (ImGui.IsItemHovered())
                SetReadableTooltip("This repository has at least one package whose plugin package SHA-256 differs from Omega's stable-provider package for the same plugin version. Review its source/package differences before installing or updating from it.");
        }
        else if (!source.Enabled)
        {
            ImGui.TextDisabled("Disabled");
        }
        else if (status?.IsStale == true)
        {
            ImGui.TextColored(new Vector4(0.95f, 0.48f, 0.18f, 1f), "Stale");
            if (ImGui.IsItemHovered())
                SetReadableTooltip("Every cached plugin in this repository is at least three Dalamud API levels behind current. Its plugins are hidden from the main marketplace.");
        }
        else if (status is null)
        {
            ImGui.TextDisabled("Not in Definitions");
        }
        else
        {
            ImGui.TextColored(new Vector4(0.34f, 0.86f, 0.61f, 1f), "Active");
        }

        if (!source.IsOfficial && dalamudPresent)
        {
            ImGui.SameLine(0f, 5f);
            ImGui.TextDisabled(dalamudEnabled ? "• Dalamud" : "• Dalamud off");
            if (ImGui.IsItemHovered())
                SetReadableTooltip((dalamudEnabled ? "Registered and enabled in Dalamud" : "Registered but disabled in Dalamud") +
                    (source.DalamudManagedByOmega ? " (Omega-managed)" : " (user-managed)"));
        }
    }

    private void DrawAddSourceTools()
    {
        ImGui.Separator();
        ImGui.Text("Add repository to Dalamud");
        ImGui.TextDisabled("Adds the PluginMaster URL to Dalamud.");
        ImGui.SetNextItemWidth(Math.Min(Ui(560f), ImGui.GetContentRegionAvail().X));
        ImGui.InputTextWithHint("##newRepoUrl", "https://.../pluginmaster.json", ref newRepositoryUrl, 512);

        var validUrl = Uri.TryCreate(newRepositoryUrl.Trim(), UriKind.Absolute, out var uri) &&
                       uri.Scheme == Uri.UriSchemeHttps;
        var canAdd = repositoryTask is null && validUrl;
        ImGui.BeginDisabled(!canAdd);
        if (ImGui.Button("Add to Dalamud") && uri is not null)
        {
            var source = new RepositorySource
            {
                Name = RepositoryDisplayNameFromUrl(uri.ToString()),
                Url = uri.ToString(),
                Enabled = true,
                IsCurated = false,
                IsExperimental = true,
                IntegrateWithDalamud = true,
                DalamudManagedByOmega = false,
            };
            newRepositoryUrl = string.Empty;
            sourceSection = SourceManagerSection.DalamudConfigured;
            sourceSearch = string.Empty;
            StartRepositoryTask(
                source,
                RepositoryTaskKind.Integrate,
                repositoryBridge.EnsureIntegratedAsync(source.Url, true, ownedByOmega: false));
        }
        ImGui.EndDisabled();

        ImGui.Spacing();
        ImGui.Text("Bulk import to Dalamud");
        ImGui.TextWrapped("Paste HTTPS PluginMaster JSON URLs to add them to Dalamud.");
        ImGui.BeginDisabled(repositoryTask is not null);
        if (ImGui.Button("Paste URL list from clipboard"))
        {
            var urls = ParseRepositoryList(ImGui.GetClipboardText());
            if (urls.Count == 0)
            {
                operationMessage = "No valid new HTTPS repository URLs were found on the clipboard.";
            }
            else
            {
                var source = new RepositorySource
                {
                    Name = urls.Count == 1 ? RepositoryDisplayNameFromUrl(urls[0]) : $"{urls.Count} repositories",
                    Url = urls[0],
                    Enabled = true,
                    IntegrateWithDalamud = true,
                    DalamudManagedByOmega = false,
                };
                sourceSection = SourceManagerSection.DalamudConfigured;
                sourceSearch = string.Empty;
                StartRepositoryTask(source, RepositoryTaskKind.Integrate, AddRepositoryListToDalamudAsync(urls));
            }
        }
        ImGui.EndDisabled();
    }

    private IReadOnlyList<string> ParseRepositoryList(string text)
    {
        var existing = repositoryBridge.GetConfiguredRepositories()
            .Select(x => NormalizeUrl(x.Url))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();
        foreach (var token in text.Split(
                     new[] { '\r', '\n', '\t', ';', ' ' },
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!Uri.TryCreate(token, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
                continue;
            var normalized = NormalizeUrl(uri.ToString());
            if (existing.Add(normalized))
                result.Add(uri.ToString());
        }
        return result;
    }

    private async Task<RepositoryBridgeResult> AddRepositoryListToDalamudAsync(IReadOnlyList<string> urls)
    {
        var added = 0;
        var existing = 0;
        var failures = new List<string>();
        foreach (var url in urls)
        {
            var result = await repositoryBridge.EnsureIntegratedAsync(url, true, ownedByOmega: false).ConfigureAwait(false);
            if (result.Outcome == RepositoryBridgeOutcome.Added)
                added++;
            else if (result.Outcome == RepositoryBridgeOutcome.AlreadyPresent)
                existing++;
            else if (!result.Success)
                failures.Add(result.Message);
        }

        var message = $"Added {added} repository source(s) to Dalamud" +
                      (existing > 0 ? $"; {existing} already present" : string.Empty) +
                      (failures.Count > 0 ? $"; {failures.Count} failed: {string.Join(" | ", failures.Take(3))}" : ".");
        return new RepositoryBridgeResult(
            failures.Count == 0 ? RepositoryBridgeOutcome.Added : added > 0 ? RepositoryBridgeOutcome.Updated : RepositoryBridgeOutcome.Failed,
            message,
            OwnedByOmega: false);
    }

    private void DrawUnmanagedSourceSubmissionFooter(IReadOnlyList<RepositorySource> unmanaged)
    {
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.34f, 0.64f, 0.98f, 1f),
            $"{unmanaged.Count} unmanaged Dalamud source{(unmanaged.Count == 1 ? string.Empty : "s")} not in Omega Definitions.");
        ImGui.SameLine();
        if (ImGui.SmallButton(unmanaged.Count == 1 ? "Add it to Omega on GitHub##submit-unmanaged-source" : "Add a source to Omega on GitHub##submit-unmanaged-source"))
        {
            var sourceUrl = unmanaged.Count == 1 ? unmanaged[0].Url : string.Empty;
            OpenSourceSubmissionIssue(sourceUrl);
        }
        if (ImGui.IsItemHovered())
            SetReadableTooltip(unmanaged.Count == 1
                ? "Open Omega's source-submission issue form with this repository URL prefilled."
                : "Open Omega's source-submission issue form. Multiple unmanaged sources are present, so choose the one you want to submit.");
    }

    private static void OpenSourceSubmissionIssue(string sourceUrl)
    {
        var url = $"{ProjectGitHubUrl}/issues/new?template=plugin-source.yml";
        if (!string.IsNullOrWhiteSpace(sourceUrl))
            url += $"&source-url={Uri.EscapeDataString(sourceUrl)}";
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Could not open Omega source-submission issue form.");
        }
    }

    private void StartRepositoryTask(RepositorySource source, RepositoryTaskKind kind, Task<RepositoryBridgeResult> task)
    {
        if (repositoryTask is not null)
            return;

        repositoryTaskSource = source;
        repositoryTaskKind = kind;
        repositoryTask = task;
        operationMessage = kind switch
        {
            RepositoryTaskKind.Integrate => $"Preparing {source.Name} for Dalamud servicing...",
            RepositoryTaskKind.Detach => $"Detaching {source.Name} from Dalamud...",
            RepositoryTaskKind.SetEnabled => $"Synchronizing {source.Name} with Dalamud...",
            _ => "Updating source...",
        };
    }

    private void CompleteRepositoryTaskIfReady()
    {
        if (repositoryTask is null || !repositoryTask.IsCompleted)
            return;

        var source = repositoryTaskSource;
        try
        {
            var result = repositoryTask.GetAwaiter().GetResult();
            operationMessage = result.Message;
            if (source is not null)
            {
                switch (repositoryTaskKind)
                {
                    case RepositoryTaskKind.Integrate when result.Success:
                        source.IntegrateWithDalamud = true;
                        source.DalamudManagedByOmega = result.OwnedByOmega;
                        RefreshDalamudRepositoryAwareness();
                        var unmanagedSources = configuration.Repositories
                            .Where(x => !x.IsCurated && x.Enabled)
                            .ToArray();
                        if (unmanagedSources.Length > 0)
                            _ = catalog.RefreshRepositoriesAsync(unmanagedSources, configuration.Repositories);
                        break;
                    case RepositoryTaskKind.Detach when result.Success:
                        source.IntegrateWithDalamud = false;
                        source.DalamudManagedByOmega = false;
                        RefreshDalamudRepositoryAwareness();
                        break;
                    case RepositoryTaskKind.SetEnabled when !result.Success:
                        var state = repositoryBridge.GetState(source.Url);
                        if (state.Available && state.Present)
                            source.Enabled = state.Enabled;
                        break;
                }

                InvalidateSourceCaches();
                configuration.Save();
                catalog.LoadCached(configuration.Repositories);
            }
        }
        catch (Exception ex)
        {
            operationMessage = $"Source operation failed: {ex.GetBaseException().Message}";
        }
        finally
        {
            repositoryTask = null;
            repositoryTaskSource = null;
            repositoryTaskKind = RepositoryTaskKind.None;
        }
    }

    private void CompleteInstallTaskIfReady()
    {
        if (installTask is null || !installTask.IsCompleted)
            return;

        try
        {
            var result = installTask.GetAwaiter().GetResult();
            operationMessage = result.Message;
            if (result.Outcome == InstallOutcome.Installed && !string.IsNullOrWhiteSpace(installingInternalName))
                libraryLedger.MarkInstalled(installingInternalName);
        }
        catch (Exception ex)
        {
            operationMessage = $"Install failed: {ex.GetBaseException().Message}";
        }
        finally
        {
            installTask = null;
            installingInternalName = string.Empty;
        }
    }

    private RepositorySource? FindConfiguredSource(string sourceUrl)
    {
        EnsureConfiguredSourceIndex();
        return configuredSourceByUrl.TryGetValue(NormalizeUrl(sourceUrl), out var source) ? source : null;
    }

    private void EnsureConfiguredSourceIndex()
    {
        if (configuredSourceIndexValid)
            return;

        configuredSourceByUrl.Clear();
        foreach (var source in configuration.Repositories)
            configuredSourceByUrl[NormalizeUrl(source.Url)] = source;
        configuredSourceIndexValid = true;
    }

    private void InvalidateRepositorySettingsSnapshot()
    {
        repositorySettingsSnapshot = null;
        repositorySettingsCatalogRevision = -1;
        repositorySettingsSourceRevision = -1;
        repositoryVisibleRowsKey = string.Empty;
        repositoryVisibleRows = [];
    }

    private void InvalidateSourceCaches()
    {
        configuredSourceByUrl.Clear();
        configuredSourceIndexValid = false;
        sourceStateRevision++;
        InvalidateRepositorySettingsSnapshot();
        sidebarCatalogRevision = -1;
        filterCatalogRevision = -1;
    }

}
