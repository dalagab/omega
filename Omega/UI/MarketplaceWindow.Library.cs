using System.Diagnostics;
using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Plugin;

namespace Dalagab.Omega;

/// <summary>
/// Owns the Microsoft Store-style Library surface and keeps Dalamud Collections nested under it.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private bool ShowingLibraryCollections
        => activeView == MarketplaceView.Library && librarySection == LibrarySection.Collections;

    private bool ShowingLibrarySigmascope
        => activeView == MarketplaceView.Library && librarySection == LibrarySection.Sigmascope;

    private void DrawLibraryTabs(int installedCount)
    {
        RefreshCollectionsIfNeeded();
        var startX = ImGui.GetCursorPosX();
        if (DrawRoundedButton(
                $"All   {installedCount}",
                "library-tab-all",
                Ui(96f, 32f),
                active: librarySection == LibrarySection.All))
        {
            SetLibrarySection(LibrarySection.All);
        }

        ImGui.SameLine(0f, 8f);
        if (DrawRoundedButton(
                SigmascopeInfo.Name,
                "library-tab-sigmascope",
                Ui(126f, 32f),
                active: librarySection == LibrarySection.Sigmascope))
        {
            SetLibrarySection(LibrarySection.Sigmascope);
        }

        ImGui.SameLine(0f, 8f);
        if (DrawRoundedButton(
                $"Collections   {collectionSnapshot.Length}",
                "library-tab-collections",
                Ui(142f, 32f),
                active: librarySection == LibrarySection.Collections))
        {
            SetLibrarySection(LibrarySection.Collections);
        }

        var importWidth = Ui(152f);
        var rightEdge = ImGui.GetWindowContentRegionMax().X;
        ImGui.SameLine();
        ImGui.SetCursorPosX(Math.Max(ImGui.GetCursorPosX() + 12f, rightEdge - importWidth));
        var canImport = configImportTask is null && configBackupTask is null;
        if (!canImport)
            ImGui.BeginDisabled();
        if (DrawRoundedButton(
                configImportTask is null ? "Import config backup" : $"Importing {Shorten(importingPluginName, 12)}…",
                "library-import-config-backup",
                new Vector2(importWidth, 32f)))
        {
            OpenConfigBackupPicker();
        }
        if (!canImport)
            ImGui.EndDisabled();
        if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
            ImGui.SetTooltip("Restore a plugin configuration ZIP previously created by Omega. The plugin must already be installed.");

        ImGui.SetCursorPosX(startX);
        ImGui.Spacing();
    }

    private void SetLibrarySection(LibrarySection section)
    {
        if (librarySection == section)
            return;

        librarySection = section;
        detailsOpen = false;
        selectedPlugin = null;
        resetStorefrontScroll = true;
        if (section == LibrarySection.Collections)
            RefreshCollectionsIfNeeded(force: true);
    }

    private bool ShouldDrawMarketplaceFilters()
        => activeView switch
        {
            MarketplaceView.Spotlight => false,
            MarketplaceView.Discover when detailsOpen => false,
            MarketplaceView.Library when librarySection is LibrarySection.Collections or LibrarySection.Sigmascope => false,
            _ => true,
        };

    private void DrawInlineLibraryRuntimeField()
    {
        ImGui.TextDisabled("Status");
        ImGui.SetNextItemWidth(-1f);
        if (!ImGui.BeginCombo("##filter-status", LibraryRuntimeFilterLabel(libraryRuntimeFilter)))
            return;

        foreach (var value in Enum.GetValues<LibraryRuntimeFilter>())
        {
            if (!ImGui.Selectable(LibraryRuntimeFilterLabel(value), libraryRuntimeFilter == value))
                continue;
            libraryRuntimeFilter = value;
            resetStorefrontScroll = true;
        }
        ImGui.EndCombo();
    }

    private static string LibraryRuntimeFilterLabel(LibraryRuntimeFilter value) => value switch
    {
        LibraryRuntimeFilter.Loaded => "Loaded",
        LibraryRuntimeFilter.NotLoaded => "Not loaded",
        _ => "All installed",
    };

    private void DrawLibraryList(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        ImGui.Spacing();
        foreach (var plugin in plugins)
        {
            if (!installed.TryGetValue(plugin.InternalName, out var installedPlugin))
                continue;
            DrawLibraryRow(plugin, installedPlugin, currentApi, currentDalamudVersion);
            ImGui.Spacing();
        }
    }

    private void DrawUpdatesList(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        ImGui.Spacing();
        if (updates.DefinitionsUpdateAvailable)
        {
            DrawDefinitionsUpdateRow();
            ImGui.Spacing();
        }

        foreach (var plugin in plugins)
        {
            if (!installed.TryGetValue(plugin.InternalName, out var installedPlugin))
                continue;
            DrawUpdateRow(plugin, installedPlugin, currentApi, currentDalamudVersion);
            ImGui.Spacing();
        }
    }

    private void DrawLibraryRow(
        MarketplacePlugin plugin,
        IExposedPlugin installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        var rowHeight = Ui(MarketplaceLayoutRules.LibraryRowHeight);
        var rowWidth = Math.Max(Ui(420f), ImGui.GetContentRegionAvail().X);
        ImGui.BeginChild($"library-row-{StableId(plugin.InternalName)}", new Vector2(rowWidth, rowHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        // Library > All is deliberately a pure installed-plugin list. Collection membership
        // is managed only from Library > Collections.
        var artworkY = MarketplaceLayoutRules.CenterY(rowHeight, Ui(54f));
        ImGui.SetCursorPosY(artworkY);
        var artworkClicked = DrawPluginArtwork(
            plugin, installedPlugin, Ui(54f), Ui(54f), currentApi, currentDalamudVersion, showOverlays: false);
        if (artworkClicked)
            OpenPluginDetails(plugin);

        ImGui.SameLine(0f, Ui(12f));
        var textStart = ImGui.GetCursorPosX();
        var textHeight = ImGui.GetTextLineHeightWithSpacing() * 4f;
        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, textHeight));
        ImGui.BeginGroup();
        ImGui.TextUnformatted(Shorten(plugin.Name, 42));
        DrawInstalledAuthorRepositoryLine(plugin, installedPlugin, currentApi);
        ImGui.TextDisabled(Shorten(
            $"{InstalledVersionText(installedPlugin)}  •  {(installedPlugin.IsLoaded ? "Loaded" : "Not loaded")}  •  {BuildCompactCompatibility(plugin, currentApi, currentDalamudVersion)}",
            76));
        ImGui.TextDisabled(BuildLibraryInstallDateLine(plugin.InternalName));
        ImGui.EndGroup();
        if (ImGui.IsItemClicked(ImGuiMouseButton.Left))
            OpenPluginDetails(plugin);
        if (ImGui.IsItemHovered())
            SetReadableTooltip(BuildInstalledMetadataLine(plugin, installedPlugin, currentApi, currentDalamudVersion));

        var toggleWidth = Ui(44f);
        var iconActionSize = Ui(34f);
        var actionWidth = Ui(92f);
        var actionGap = Ui(8f);
        var actionGroupWidth = toggleWidth + (actionGap * 3f) + (iconActionSize * 2f) + actionWidth;
        ImGui.SameLine();
        var actionsX = Math.Max(
            textStart + Ui(240f),
            MarketplaceLayoutRules.RightAlignedX(ImGui.GetWindowContentRegionMax().X, actionGroupWidth));
        ImGui.SetCursorPos(new Vector2(actionsX, MarketplaceLayoutRules.CenterY(rowHeight, Ui(32f))));

        var control = GetPluginDirectControlState(plugin.InternalName);
        var shownState = control.CanDirectToggle ? control.DesiredEnabled : installedPlugin.IsLoaded;
        var isSelf = plugin.InternalName.Equals(Plugin.PluginInterface.InternalName, StringComparison.OrdinalIgnoreCase);
        var canToggleHere = control.CanDirectToggle && !(isSelf && control.DesiredEnabled);
        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, Ui(22f)));
        if (DrawToggleSwitch($"library-plugin-state-{StableId(plugin.InternalName)}", shownState, canToggleHere))
            StartDirectPluginStateChange(plugin, control, !control.DesiredEnabled);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(!canToggleHere && isSelf && control.CanDirectToggle
                ? "Omega cannot disable itself from its own window. Use Dalamud to disable Omega."
                : control.CanDirectToggle
                    ? $"{(control.DesiredEnabled ? "Disable" : "Enable")} {plugin.Name}"
                    : control.Reason);

        ImGui.SameLine(0f, actionGap);
        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, iconActionSize));
        var canOpenSettings = installedPlugin.IsLoaded && installedPlugin.HasConfigUi;
        if (DrawLibraryActionIcon(
                FontAwesomeIcon.Cog,
                $"library-settings-{StableId(plugin.InternalName)}",
                canOpenSettings ? $"Open {plugin.Name} settings" : "No settings UI is currently exposed by this plugin",
                canOpenSettings))
        {
            try
            {
                installedPlugin.OpenConfigUi();
            }
            catch (Exception ex)
            {
                Plugin.Log.Debug(ex, "Unable to open config UI for {Plugin}", plugin.InternalName);
                operationMessage = $"Could not open settings for {plugin.Name}.";
            }
        }

        ImGui.SameLine(0f, actionGap);
        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, iconActionSize));
        var canStartBackup = configBackupTask is null;
        if (DrawLibraryActionIcon(
                FontAwesomeIcon.FileArchive,
                $"library-backup-{StableId(plugin.InternalName)}",
                canStartBackup ? $"Back up {plugin.Name} configuration" : $"Backing up {backingUpPluginName}…",
                canStartBackup))
        {
            StartPluginConfigBackup(plugin);
        }

        ImGui.SameLine(0f, actionGap);
        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, Ui(32f)));
        var canOpen = installedPlugin.IsLoaded && installedPlugin.HasMainUi;
        if (DrawRoundedButton(
                canOpen ? "Open" : "Details",
                $"library-action-{StableId(plugin.InternalName)}",
                new Vector2(actionWidth, Ui(32f))))
        {
            if (canOpen)
            {
                try
                {
                    installedPlugin.OpenMainUi();
                }
                catch (Exception ex)
                {
                    Plugin.Log.Debug(ex, "Unable to open main UI for {Plugin}", plugin.InternalName);
                    OpenPluginDetails(plugin);
                }
            }
            else
            {
                OpenPluginDetails(plugin);
            }
        }

        ImGui.EndChild();
    }

    private void StartPluginConfigBackup(MarketplacePlugin plugin)
    {
        if (configBackupTask is not null)
            return;

        backingUpPluginName = plugin.Name;
        operationMessage = $"Backing up {plugin.Name} configuration…";
        configBackupTask = Task.Run(() => configBackups.Backup(plugin.InternalName, plugin.Name));
    }

    private void CompleteConfigBackupTaskIfReady()
    {
        if (configBackupTask is null || !configBackupTask.IsCompleted)
            return;

        try
        {
            var backup = configBackupTask.GetAwaiter().GetResult();
            if (backup.Success && backup.BackupPath is not null)
            {
                operationMessage = string.Empty;
                RevealBackupInExplorer(backup.BackupPath, backup.BackupDirectory);
            }
            else
            {
                operationMessage = backup.Message;
            }
        }
        catch (Exception ex)
        {
            operationMessage = $"Config backup failed: {ex.GetBaseException().Message}";
        }
        finally
        {
            configBackupTask = null;
            backingUpPluginName = string.Empty;
        }
    }

    private static void RevealBackupInExplorer(string backupPath, string? backupDirectory)
    {
        // Shell-open the containing directory instead of calling explorer.exe directly. This keeps
        // the action compatible with Wine/Proton while still showing the user where the temp backup lives.
        var directory = !string.IsNullOrWhiteSpace(backupDirectory)
            ? backupDirectory
            : Path.GetDirectoryName(Path.GetFullPath(backupPath));
        if (string.IsNullOrWhiteSpace(directory))
            return;

        try
        {
            Process.Start(new ProcessStartInfo(directory) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega could not reveal config backup directory {Directory}", directory);
        }
    }

    private void OpenConfigBackupPicker()
    {
        if (configImportTask is not null || configBackupTask is not null)
            return;

        fileDialogs.OpenFileDialog(
            "Import Omega configuration backup",
            ".zip",
            (accepted, path) =>
            {
                if (!accepted || string.IsNullOrWhiteSpace(path))
                    return;

                var installedNames = Plugin.PluginInterface.InstalledPlugins
                    .Where(x => x is not null && !string.IsNullOrWhiteSpace(x.InternalName))
                    .Select(x => x.InternalName)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var inspection = configBackups.Inspect(path, installedNames);
                if (!inspection.Success)
                {
                    operationMessage = inspection.Message;
                    return;
                }

                pendingConfigImportPath = path;
                pendingConfigImportInspection = inspection;
                requestConfigImportPopup = true;
            });
    }

    private void DrawConfigImportModal()
    {
        if (pendingConfigImportInspection is null && configImportTask is null)
            return;

        ImGui.SetNextWindowSize(UiModalSize(520f, 0f), ImGuiCond.Appearing);
        var keepOpen = true;
        if (!ImGui.BeginPopupModal(
                "Import configuration backup###DalagabOmegaConfigImport",
                ref keepOpen,
                ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoTitleBar))
        {
            if (!keepOpen)
                ClearPendingConfigImport();
            return;
        }

        if (DrawOmegaModalHeader("Import configuration backup", "config-import"))
        {
            ClearPendingConfigImport();
            ImGui.CloseCurrentPopup();
            ImGui.EndPopup();
            return;
        }

        var inspection = pendingConfigImportInspection;
        if (inspection is not null)
        {
            ImGui.TextUnformatted(inspection.DisplayName);
            ImGui.TextDisabled(inspection.InternalName);
            ImGui.Spacing();
            ImGui.TextWrapped(inspection.Message);
            ImGui.Spacing();
            ImGui.TextDisabled("Import replaces this plugin's current config JSON and auxiliary config directory. Omega creates a temporary safety backup first.");
            ImGui.Spacing();
        }

        if (configImportFinished)
        {
            ImGui.TextWrapped(configImportResultMessage);
            ImGui.Spacing();
            if (ImGui.Button("Close", Ui(100f, 34f)))
            {
                ClearPendingConfigImport();
                ImGui.CloseCurrentPopup();
            }
            ImGui.EndPopup();
            return;
        }

        var importing = configImportTask is not null;
        if (importing)
            ImGui.BeginDisabled();
        if (ImGui.Button(importing ? "Importing…" : "Import backup", Ui(150f, 34f)) && inspection is not null)
        {
            importingPluginName = inspection.DisplayName;
            var path = pendingConfigImportPath;
            configImportTask = Task.Run(() => configBackups.Restore(path, inspection));
        }
        if (importing)
            ImGui.EndDisabled();

        ImGui.SameLine(0f, 10f);
        if (importing)
            ImGui.BeginDisabled();
        if (ImGui.Button("Cancel", Ui(100f, 34f)))
        {
            ClearPendingConfigImport();
            ImGui.CloseCurrentPopup();
        }
        if (importing)
            ImGui.EndDisabled();

        ImGui.EndPopup();
        if (!keepOpen && !importing)
            ClearPendingConfigImport();
    }

    private void CompleteConfigImportTaskIfReady()
    {
        if (configImportTask is null || !configImportTask.IsCompleted)
            return;

        try
        {
            var result = configImportTask.GetAwaiter().GetResult();
            configImportFinished = true;
            configImportResultMessage = result.Message;
            operationMessage = result.Success ? string.Empty : result.Message;
        }
        catch (Exception ex)
        {
            operationMessage = $"Config import failed: {ex.GetBaseException().Message}";
        }
        finally
        {
            configImportTask = null;
            importingPluginName = string.Empty;
        }
    }

    private void ClearPendingConfigImport()
    {
        if (configImportTask is not null)
            return;
        pendingConfigImportPath = string.Empty;
        pendingConfigImportInspection = null;
        importingPluginName = string.Empty;
        configImportFinished = false;
        configImportResultMessage = string.Empty;
    }

    private string BuildLibraryInstallDateLine(string internalName)
    {
        var stamp = libraryLedger.GetInstallStamp(internalName);
        if (stamp is null)
            return "Install date unavailable";

        var date = stamp.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd");
        return stamp.ExactInstallTime
            ? $"Installed {date}"
            : $"Installed before Omega tracking  •  first seen {date}";
    }

    private static bool DrawLibraryActionIcon(
        FontAwesomeIcon icon,
        string id,
        string tooltip,
        bool enabled = true)
    {
        var size = Ui(34f);
        if (!enabled)
            ImGui.BeginDisabled();

        var clicked = ImGui.Button($"##{id}", new Vector2(size, size));
        var min = ImGui.GetItemRectMin();
        var max = ImGui.GetItemRectMax();
        var hovered = ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled);
        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = icon.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        ImGui.GetWindowDrawList().AddText(
            min + ((max - min) - glyphSize) * 0.5f,
            enabled ? ImGui.GetColorU32(ImGuiCol.Text) : ImGui.GetColorU32(ImGuiCol.TextDisabled),
            glyph);
        ImGui.PopFont();

        if (!enabled)
            ImGui.EndDisabled();
        if (hovered)
            ImGui.SetTooltip(tooltip);
        return enabled && clicked;
    }

    private void DrawUpdatesToolbar(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        var (automaticPluginUpdates, migrations) = CountUpdateAllCandidates(installed, currentApi, currentDalamudVersion);
        var definitions = updates.DefinitionsUpdateAvailable ? 1 : 0;
        var actionable = automaticPluginUpdates + definitions;
        var busy = updateAllActive || updateTask is not null || updateAllDefinitionsTask is not null || updates.IsRefreshing;
        var buttonWidth = Ui(118f);
        var rightEdge = ImGui.GetWindowContentRegionMax().X;

        ImGui.SameLine();
        ImGui.SetCursorPosX(Math.Max(ImGui.GetCursorPosX() + Ui(16f), rightEdge - buttonWidth));
        if (busy || actionable == 0)
            ImGui.BeginDisabled();
        var label = updateAllActive
            ? $"Updating {Math.Min(updateAllCompleted, updateAllTotal)}/{updateAllTotal}…"
            : "Update all";
        if (DrawRoundedButton(label, "updates-update-all", new Vector2(buttonWidth, Ui(32f))) && !busy && actionable > 0)
            StartUpdateAll(installed, currentApi, currentDalamudVersion);
        if (busy || actionable == 0)
            ImGui.EndDisabled();

        if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
        {
            var tooltip = actionable > 0
                ? $"Update {automaticPluginUpdates} plugin{(automaticPluginUpdates == 1 ? string.Empty : "s")}{(definitions > 0 ? " and Omega Definitions" : string.Empty)}."
                : "No automatic updates are currently available.";
            if (migrations > 0)
                tooltip += $" {migrations} repository migration{(migrations == 1 ? string.Empty : "s")} require individual review and will not be moved silently.";
            ImGui.SetTooltip(tooltip);
        }
    }

    private (int Automatic, int Migrations) CountUpdateAllCandidates(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        var automatic = 0;
        var migrations = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var displayed in catalog.GetMainProjection(currentApi).Plugins)
        {
            if (!seen.Add(displayed.InternalName) || !installed.TryGetValue(displayed.InternalName, out var installedPlugin))
                continue;
            var candidate = GetAvailableUpdateCandidate(displayed.InternalName, installedPlugin, currentApi, currentDalamudVersion);
            if (candidate is null)
                continue;
            if (IsRepositoryMigration(installedPlugin, candidate))
                migrations++;
            else
                automatic++;
        }
        return (automatic, migrations);
    }

    private void DrawDefinitionsUpdateRow()
    {
        var rowHeight = Ui(72f);
        var rowWidth = Math.Max(Ui(420f), ImGui.GetContentRegionAvail().X);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.025f, 0.105f, 0.115f, 0.48f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.08f, 0.34f, 0.36f, 0.42f));
        ImGui.BeginChild("definitions-update-row", new Vector2(rowWidth, rowHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var iconSize = Ui(38f);
        ImGui.SetCursorPos(new Vector2(Ui(10f), MarketplaceLayoutRules.CenterY(rowHeight, iconSize)));
        var iconMin = ImGui.GetCursorScreenPos();
        ImGui.Dummy(new Vector2(iconSize, iconSize));
        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = FontAwesomeIcon.Download.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        ImGui.GetWindowDrawList().AddText(
            iconMin + (new Vector2(iconSize, iconSize) - glyphSize) * 0.5f,
            ImGui.ColorConvertFloat4ToU32(new Vector4(0.45f, 0.82f, 0.84f, 0.90f)),
            glyph);
        ImGui.PopFont();

        ImGui.SameLine(0f, Ui(10f));
        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, ImGui.GetTextLineHeightWithSpacing() * 2f));
        ImGui.BeginGroup();
        ImGui.TextUnformatted("Omega Definitions");
        var current = string.IsNullOrWhiteSpace(catalog.CatalogRevision) ? "current" : catalog.CatalogRevision;
        var available = string.IsNullOrWhiteSpace(updates.AvailableDefinitionsRevision) ? "new revision" : updates.AvailableDefinitionsRevision;
        ImGui.TextDisabled($"{Shorten(current, 30)} → {Shorten(available, 30)}");
        ImGui.EndGroup();

        var actionSize = Ui(38f);
        ImGui.SameLine();
        ImGui.SetCursorPos(new Vector2(
            MarketplaceLayoutRules.RightAlignedX(ImGui.GetWindowContentRegionMax().X, actionSize),
            MarketplaceLayoutRules.CenterY(rowHeight, actionSize)));
        var canUpdate = !updates.IsRefreshing && !updateAllActive && updateAllDefinitionsTask is null && updateTask is null;
        if (DrawUpdateActionIcon("definitions-update-action", canUpdate, "Update Omega Definitions"))
        {
            operationMessage = "Updating Definitions…";
            _ = ApplyDefinitionsUpdateFromUiAsync();
        }

        ImGui.EndChild();
        ImGui.PopStyleColor(2);
    }

    private void DrawUpdateRow(
        MarketplacePlugin plugin,
        IExposedPlugin installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        var rowHeight = Ui(MarketplaceLayoutRules.UpdatesRowHeight);
        var rowWidth = Math.Max(Ui(420f), ImGui.GetContentRegionAvail().X);
        ImGui.BeginChild($"updates-row-{StableId(plugin.InternalName)}", new Vector2(rowWidth, rowHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, Ui(54f)));
        var artworkClicked = DrawPluginArtwork(
            plugin, installedPlugin, Ui(54f), Ui(54f), currentApi, currentDalamudVersion, showOverlays: false);
        if (artworkClicked)
            OpenPluginDetails(plugin);

        ImGui.SameLine(0f, Ui(12f));
        var textStart = ImGui.GetCursorPosX();
        var updateVariant = GetAvailableUpdateCandidate(plugin.InternalName, installedPlugin, currentApi, currentDalamudVersion);
        var offered = GetAvailableUpdateVersion(plugin.InternalName, installedPlugin, currentApi, currentDalamudVersion);
        var migration = updateVariant is not null && IsRepositoryMigration(installedPlugin, updateVariant);
        var textHeight = ImGui.GetTextLineHeightWithSpacing() * 3f;
        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, textHeight));
        ImGui.BeginGroup();
        ImGui.TextUnformatted(Shorten(plugin.Name, 42));
        DrawInstalledAuthorRepositoryLine(plugin, installedPlugin, currentApi);
        if (offered is null)
        {
            ImGui.TextDisabled(Shorten(
                $"{InstalledVersionText(installedPlugin)}  •  {BuildCompactCompatibility(plugin, currentApi, currentDalamudVersion)}",
                76));
        }
        else
        {
            updateVariant ??= plugin;
            ImGui.TextDisabled($"{InstalledVersionText(installedPlugin)} → v{offered}{(migration ? "  •  repository move" : string.Empty)}");
            if (BuildChangelogEntries(updateVariant).Count > 0)
            {
                ImGui.SameLine(0f, 5f);
                DrawInlineChangelogButton(updateVariant, $"update-changelog-{StableId(plugin.InternalName)}", installedPlugin.Version);
            }
            ImGui.SameLine(0f, 6f);
            ImGui.TextDisabled(Shorten($"•  {BuildCompactCompatibility(plugin, currentApi, currentDalamudVersion)}", 44));
        }
        ImGui.EndGroup();
        if (ImGui.IsItemClicked(ImGuiMouseButton.Left))
            OpenPluginDetails(plugin);
        if (ImGui.IsItemHovered())
            SetReadableTooltip(BuildInstalledMetadataLine(plugin, installedPlugin, currentApi, currentDalamudVersion));

        var actionSize = Ui(38f);
        ImGui.SameLine();
        ImGui.SetCursorPos(new Vector2(
            Math.Max(textStart + Ui(240f), MarketplaceLayoutRules.RightAlignedX(ImGui.GetWindowContentRegionMax().X, actionSize)),
            MarketplaceLayoutRules.CenterY(rowHeight, actionSize)));
        var canUpdate = updateVariant is not null && updateTask is null;
        var actionTooltip = migration && updateVariant is not null
            ? $"Migrate to {updateVariant.SourceName} and update through Dalamud"
            : "Update through Dalamud";
        if (DrawUpdateActionIcon($"update-action-{StableId(plugin.InternalName)}", canUpdate, actionTooltip))
            OpenUpdateOrMigration(plugin, installedPlugin, currentApi, currentDalamudVersion);

        ImGui.EndChild();
    }

    private static bool DrawUpdateActionIcon(string id, bool enabled, string tooltip)
    {
        var size = Ui(38f);
        var rounding = Ui(6f);
        var min = ImGui.GetCursorScreenPos();
        if (!enabled)
            ImGui.BeginDisabled();
        ImGui.InvisibleButton($"##{id}", new Vector2(size, size));
        var hovered = ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled);
        var held = enabled && ImGui.IsItemActive();
        var clicked = enabled && ImGui.IsItemClicked();
        if (!enabled)
            ImGui.EndDisabled();
        var draw = ImGui.GetWindowDrawList();

        var background = ImGui.ColorConvertFloat4ToU32(!enabled
            ? new Vector4(0.07f, 0.09f, 0.11f, 0.72f)
            : held
                ? new Vector4(0.02f, 0.34f, 0.36f, 1f)
                : hovered
                    ? new Vector4(0.03f, 0.50f, 0.51f, 1f)
                    : new Vector4(0.02f, 0.40f, 0.42f, 0.96f));
        draw.AddRectFilled(min, min + new Vector2(size, size), background, rounding);

        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = FontAwesomeIcon.SyncAlt.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        draw.AddText(
            min + new Vector2((size - glyphSize.X) * 0.5f, (size - glyphSize.Y) * 0.5f),
            ImGui.GetColorU32(enabled ? ImGuiCol.Text : ImGuiCol.TextDisabled),
            glyph);
        ImGui.PopFont();

        if (hovered)
            ImGui.SetTooltip(enabled ? tooltip : "Another plugin update is already in progress");
        return clicked;
    }

    private static IReadOnlyList<MarketplacePlugin> BuildLibraryProjection(
        IReadOnlyList<MarketplacePlugin> marketplacePlugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed)
    {
        var result = marketplacePlugins.ToList();
        var known = result.Select(x => x.InternalName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var (internalName, installedPlugin) in installed)
        {
            if (known.Contains(internalName))
                continue;

            result.Add(new MarketplacePlugin
            {
                Name = installedPlugin.Name,
                InternalName = internalName,
                AssemblyVersionText = installedPlugin.Version?.ToString() ?? "0.0.0.0",
                SourceName = "Installed",
            });
        }

        return result;
    }

    private string BuildInstalledMetadataLine(
        MarketplacePlugin plugin,
        IExposedPlugin installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        plugin = ResolveInstalledVariant(plugin, installedPlugin);
        var source = !string.IsNullOrWhiteSpace(installedPlugin.Manifest.InstalledFromUrl) && string.IsNullOrWhiteSpace(plugin.SourceUrl)
            ? installedPlugin.Manifest.InstalledFromUrl
            : SourceLabel(plugin);
        var compatibility = plugin.GetCompatibilityText(
            currentApi,
            currentDalamudVersion,
            configuration.PreferTestingBuilds);
        return $"{source}  •  {compatibility}";
    }

    private static string BuildAuthorSourceLine(MarketplacePlugin plugin)
    {
        var author = string.IsNullOrWhiteSpace(plugin.Author) ? "Installed plugin" : plugin.Author;
        return $"{author}  •  {SourceLabel(plugin)}";
    }

    private string BuildCompactCompatibility(
        MarketplacePlugin plugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        var compatible = plugin.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out _) &&
                         (plugin.MinimumDalamudVersion is null || plugin.MinimumDalamudVersion <= currentDalamudVersion);
        var api = compatible ? currentApi : plugin.HighestKnownApiLevel;
        var apiText = api > 0 ? $"API {api}" : "API ?";
        return $"{apiText}  •  {(compatible ? "Compatible" : "Unsupported")}";
    }

    private static string SourceLabel(MarketplacePlugin plugin)
        => plugin.SourceIsOfficial
            ? "Dalamud official"
            : string.IsNullOrWhiteSpace(plugin.SourceName) ? "Source unknown" : plugin.SourceName;

    private static string InstalledVersionText(IExposedPlugin installedPlugin)
        => installedPlugin.Version is { } version ? $"v{version}" : "version pending";

}
