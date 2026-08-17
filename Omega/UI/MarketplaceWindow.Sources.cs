using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void DrawSettingsModal()
    {
        if (!settingsOpen)
            return;

        var keepOpen = settingsOpen;
        ImGui.SetNextWindowSize(UiModalSize(920f, 660f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal("Settings###DalagabOmegaSettings", ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoCollapse))
        {
            settingsOpen = keepOpen;
            return;
        }

        if (DrawOmegaModalHeader("Settings", "settings"))
        {
            settingsOpen = false;
            ImGui.CloseCurrentPopup();
            ImGui.EndPopup();
            return;
        }

        var currentApi = Plugin.PluginInterface.Manifest.DalamudApiLevel;
        if (DrawSettingsHeader())
        {
            settingsOpen = keepOpen && settingsOpen;
            ImGui.EndPopup();
            return;
        }
        DrawSourcesHeader();
        if (addSourceOpen)
            DrawAddSourceTools();

        var shownSources = GetVisibleSourceRows(currentApi);
        var statuses = catalog.GetRepositoryStatuses(currentApi)
            .ToDictionary(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase);
        DrawSourcesTable(shownSources, statuses);
        settingsOpen = keepOpen && settingsOpen;
        ImGui.EndPopup();
    }

    private void DrawSourcesHeader()
    {
        var curatedCount = configuration.Repositories.Count(x => x.IsCurated);
        var userCount = configuration.Repositories.Count(x => !x.IsCurated);
        var dalamudCount = repositoryBridge.GetConfiguredRepositories().Count;
        ImGui.TextDisabled("Plugin sources");
        ImGui.TextWrapped(sourceSection == SourceManagerSection.DalamudConfigured
            ? "Review every third-party repository currently configured in Dalamud. User-managed Dalamud entries are shown even when they are not enabled as Omega marketplace sources."
            : "Choose which plugin sources appear in Omega. You can also add your own repository.");
        ImGui.Separator();

        if (DrawPillButton($"Curated ({curatedCount})", "sources-curated", Ui(126f, 32f), sourceSection == SourceManagerSection.Curated))
        {
            sourceSection = SourceManagerSection.Curated;
            sourceSearch = string.Empty;
        }
        ImGui.SameLine();
        if (DrawPillButton($"My Sources ({userCount})", "sources-user", Ui(136f, 32f), sourceSection == SourceManagerSection.UserAdded))
        {
            sourceSection = SourceManagerSection.UserAdded;
            sourceSearch = string.Empty;
        }
        ImGui.SameLine();
        if (DrawPillButton($"Dalamud ({dalamudCount})", "sources-dalamud", Ui(132f, 32f), sourceSection == SourceManagerSection.DalamudConfigured))
        {
            sourceSection = SourceManagerSection.DalamudConfigured;
            sourceSearch = string.Empty;
            addSourceOpen = false;
        }
        ImGui.SameLine();
        if (DrawPillButton(addSourceOpen ? "Hide add tools" : "Add sources", "sources-add", Ui(128f, 32f), addSourceOpen))
        {
            if (sourceSection == SourceManagerSection.DalamudConfigured)
                sourceSection = SourceManagerSection.UserAdded;
            addSourceOpen = !addSourceOpen;
        }

        ImGui.SetNextItemWidth(Math.Min(Ui(520f), ImGui.GetContentRegionAvail().X));
        ImGui.InputTextWithHint("##source-search", "Filter repositories by name or URL...", ref sourceSearch, 256);
    }

    private RepositorySource[] GetVisibleSourceRows(int currentApi)
    {
        var statuses = catalog.GetRepositoryStatuses(currentApi)
            .ToDictionary(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase);

        if (sourceSection == SourceManagerSection.DalamudConfigured)
        {
            return repositoryBridge.GetConfiguredRepositories()
                .Select(registration =>
                {
                    var normalized = NormalizeUrl(registration.Url);
                    var configured = configuration.Repositories.FirstOrDefault(x =>
                        NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase));
                    if (configured is not null)
                        return configured;

                    statuses.TryGetValue(normalized, out var known);
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
                .Where(x => string.IsNullOrWhiteSpace(sourceSearch) ||
                            Contains(x.Name, sourceSearch.Trim()) ||
                            Contains(x.Url, sourceSearch.Trim()))
                .OrderByDescending(x => IsRepositoryArtifactDivergent(x.Url))
                .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        return configuration.Repositories
            .Where(x => sourceSection == SourceManagerSection.Curated ? x.IsCurated : !x.IsCurated)
            .Where(x => string.IsNullOrWhiteSpace(sourceSearch) ||
                        Contains(x.Name, sourceSearch.Trim()) ||
                        Contains(x.Url, sourceSearch.Trim()))
            .OrderBy(x => RepositoryProviderRules.SortPriority(
                x.Name,
                x.Url,
                x.IsOfficial,
                statuses.TryGetValue(NormalizeUrl(x.Url), out var status) ? status.PluginCount : 0))
            .ThenByDescending(x => statuses.TryGetValue(NormalizeUrl(x.Url), out var status) ? status.PluginCount : 0)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private void DrawSourcesTable(
        IReadOnlyList<RepositorySource> shownSources,
        IReadOnlyDictionary<string, RepositoryCatalogStatus> statuses)
    {
        ImGui.Spacing();
        if (!ImGui.BeginTable("omega-source-table", 5, ImGuiTableFlags.None, new Vector2(Math.Min(Ui(860f), ImGui.GetContentRegionAvail().X), Ui(addSourceOpen ? 230f : 360f)), 0f))
            return;

        ImGui.TableSetupColumn("Use");
        ImGui.TableSetupColumn("Repository");
        ImGui.TableSetupColumn("Plugins");
        ImGui.TableSetupColumn("API");
        ImGui.TableSetupColumn("State");
        ImGui.TableHeadersRow();
        var dalamudRepositories = repositoryBridge.GetConfiguredRepositories()
            .ToDictionary(x => NormalizeUrl(x.Url), StringComparer.OrdinalIgnoreCase);
        foreach (var source in shownSources)
        {
            statuses.TryGetValue(NormalizeUrl(source.Url), out var status);
            dalamudRepositories.TryGetValue(NormalizeUrl(source.Url), out var dalamudRegistration);
            DrawSourceRow(source, status, dalamudRegistration);
        }
        ImGui.EndTable();
    }

    private void DrawSourceRow(RepositorySource source, RepositoryCatalogStatus? status, DalamudRepositoryRegistration? dalamudRegistration)
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
            DrawSourceEnabledCheckbox(source);
        }

        ImGui.TableSetColumnIndex(1);
        DrawRepositoryName(source.Name, source.Url, source.IsOfficial, Plugin.PluginInterface.Manifest.DalamudApiLevel);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(source.Url);

        ImGui.TableSetColumnIndex(2);
        ImGui.Text(status?.PluginCount.ToString() ?? "—");
        ImGui.TableSetColumnIndex(3);
        ImGui.Text(status is null || status.HighestKnownApiLevel <= 0 ? "?" : status.HighestKnownApiLevel.ToString());
        ImGui.TableSetColumnIndex(4);
        if (sourceSection == SourceManagerSection.DalamudConfigured)
            DrawDalamudSourceReviewState(source, status, dalamudRegistration);
        else
            DrawSourceState(source, status, dalamudRegistration);
    }

    private void DrawDalamudSourceReviewState(
        RepositorySource source,
        RepositoryCatalogStatus? status,
        DalamudRepositoryRegistration? dalamudRegistration)
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

        if (dalamudRegistration?.Enabled == true)
            ImGui.TextColored(new Vector4(0.34f, 0.86f, 0.61f, 1f), status is null ? "Enabled • not in Definitions" : "Enabled");
        else
            ImGui.TextDisabled(status is null ? "Disabled • not in Definitions" : "Disabled");
    }

    private static string RepositoryDisplayNameFromUrl(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host)
            ? uri.Host
            : "Dalamud repository";

    private void DrawSourceEnabledCheckbox(RepositorySource source)
    {
        var enabled = source.Enabled;
        if (!ImGui.Checkbox($"##source-enabled-{StableId(source.Url)}", ref enabled))
            return;

        source.Enabled = enabled;
        InvalidateSourceCaches();
        configuration.Save();
        catalog.LoadCached(configuration.Repositories);
        operationMessage = $"{source.Name} {(enabled ? "enabled" : "disabled")} in Omega.";
        if (!source.IsOfficial && source.IntegrateWithDalamud && source.DalamudManagedByOmega && repositoryTask is null)
            StartRepositoryTask(source, RepositoryTaskKind.SetEnabled, repositoryBridge.SetManagedEnabledAsync(source.Url, enabled));
    }

    private void DrawSourceState(RepositorySource source, RepositoryCatalogStatus? status, DalamudRepositoryRegistration? dalamudRegistration)
    {
        var dalamudPresent = source.IsOfficial || dalamudRegistration is not null;
        var dalamudEnabled = source.IsOfficial || dalamudRegistration?.Enabled == true;

        if (IsRepositoryArtifactDivergent(source.Url))
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
        ImGui.Text("Add one source");
        ImGui.TextDisabled("A source may contain one plugin or many; it still needs to be a PluginMaster-compatible HTTPS JSON endpoint for Dalamud servicing.");
        ImGui.SetNextItemWidth(Math.Min(Ui(220f), ImGui.GetContentRegionAvail().X));
        ImGui.InputTextWithHint("##newRepoName", "Source name", ref newRepositoryName, 128);
        ImGui.SetNextItemWidth(Math.Min(Ui(480f), ImGui.GetContentRegionAvail().X));
        ImGui.InputTextWithHint("##newRepoUrl", "https://.../pluginmaster.json", ref newRepositoryUrl, 512);

        ImGui.Checkbox("Register this source with Dalamud", ref integrateNewRepositoryWithDalamud);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("When enabled, Omega also registers the source with Dalamud so plugins installed from it remain serviceable.");

        if (ImGui.Button("Add to My Sources") &&
            Uri.TryCreate(newRepositoryUrl.Trim(), UriKind.Absolute, out var uri) &&
            uri.Scheme == Uri.UriSchemeHttps)
        {
            var normalized = NormalizeUrl(uri.ToString());
            var duplicate = configuration.Repositories.Any(x =>
                NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase));

            if (duplicate)
            {
                operationMessage = "That source URL is already known to Omega.";
            }
            else
            {
                var source = new RepositorySource
                {
                    Name = string.IsNullOrWhiteSpace(newRepositoryName) ? uri.Host : newRepositoryName.Trim(),
                    Url = uri.ToString(),
                    Enabled = true,
                    IsCurated = false,
                    IsExperimental = true,
                };
                configuration.Repositories.Add(source);
                InvalidateSourceCaches();
                configuration.Save();
                catalog.LoadCached(configuration.Repositories);
                newRepositoryName = string.Empty;
                newRepositoryUrl = string.Empty;
                sourceSection = SourceManagerSection.UserAdded;
                sourceSearch = string.Empty;
                operationMessage = $"Added {source.Name}. Use Check for updates to load it into your local Definitions.";

                if (integrateNewRepositoryWithDalamud && repositoryTask is null)
                    StartRepositoryTask(source, RepositoryTaskKind.Integrate, repositoryBridge.EnsureIntegratedAsync(source.Url, source.Enabled));
            }
        }

        ImGui.Spacing();
        ImGui.Text("Bulk import");
        ImGui.TextWrapped("Copy many HTTPS PluginMaster JSON URLs and press the button. Bulk imports are added to My Sources only and are not registered with Dalamud automatically.");
        if (ImGui.Button("Paste URL list from clipboard"))
        {
            var result = AddRepositoryList(ImGui.GetClipboardText());
            sourceSection = SourceManagerSection.UserAdded;
            sourceSearch = string.Empty;
            operationMessage = result.Added > 0
                ? $"Added {result.Added} source(s); {result.Duplicates} duplicate(s), {result.Invalid} invalid. Use Check for updates to load them into your local Definitions."
                : $"No sources added; {result.Duplicates} duplicate(s), {result.Invalid} invalid.";
        }
    }

    private (int Added, int Duplicates, int Invalid) AddRepositoryList(string text)
    {
        var tokens = text.Split(
            new[] { '\r', '\n', '\t', ';', ' ' },
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var added = 0;
        var duplicates = 0;
        var invalid = 0;
        var known = configuration.Repositories
            .Select(x => NormalizeUrl(x.Url))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var token in tokens)
        {
            if (!Uri.TryCreate(token, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            {
                invalid++;
                continue;
            }

            var normalized = NormalizeUrl(uri.ToString());
            if (!known.Add(normalized))
            {
                duplicates++;
                continue;
            }

            configuration.Repositories.Add(new RepositorySource
            {
                Name = uri.Host,
                Url = uri.ToString(),
                Enabled = true,
                IsCurated = false,
                IsExperimental = true,
                IntegrateWithDalamud = false,
                DalamudManagedByOmega = false,
            });
            added++;
        }

        if (added > 0)
        {
            InvalidateSourceCaches();
            configuration.Save();
            catalog.LoadCached(configuration.Repositories);
        }

        return (added, duplicates, invalid);
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
                        break;
                    case RepositoryTaskKind.Detach when result.Success:
                        source.IntegrateWithDalamud = false;
                        source.DalamudManagedByOmega = false;
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

    private void InvalidateSourceCaches()
    {
        configuredSourceByUrl.Clear();
        configuredSourceIndexValid = false;
        sourceStateRevision++;
        sidebarCatalogRevision = -1;
        filterCatalogRevision = -1;
    }

}
