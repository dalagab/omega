using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private StartupAppsSnapshot? startupAppsSnapshot;
    private string startupAppSearch = string.Empty;

    private bool ShowingLibraryStartup
        => activeView == MarketplaceView.Library && librarySection == LibrarySection.Startup;

    private void OpenStartupHealth()
    {
        activeView = MarketplaceView.Library;
        librarySection = LibrarySection.Startup;
        startupAppsSnapshot = null;
        filtersOpen = false;
        detailsOpen = false;
        selectedPlugin = null;
        resetStorefrontScroll = true;
    }

    private void DrawStartupHealthPage(IReadOnlyDictionary<string, IExposedPlugin> installed)
    {
        var snapshot = startupHealth.Snapshot;

        // The marketplace already builds this installed-plugin dictionary for the current frame.
        // Reuse it to invalidate only a stale visible Startup snapshot; this adds no background
        // polling or gameplay diagnostic loop, and also catches plugins removed through Dalamud.
        if (startupAppsSnapshot is not null &&
            (startupAppsSnapshot.Apps.Count != installed.Count ||
             startupAppsSnapshot.Apps.Any(x => !installed.ContainsKey(x.InternalName))))
        {
            startupAppsSnapshot = null;
        }

        if (startupAppsSnapshot is null && snapshot.State != StartupHealthCaptureState.Pending)
            startupAppsSnapshot = StartupAppsProjection.Capture(profileBridge, ResolveStartupAppPlugin, installed);

        ImGui.TextUnformatted("Startup");
        ImGui.TextDisabled("See what loads with FFXIV, what is running now, and what appears to stay active while you play.");
        ImGui.Spacing();

        DrawStartupOverview(snapshot, startupAppsSnapshot);

        if (snapshot.Items.Count > 0 && snapshot.State == StartupHealthCaptureState.Complete)
        {
            ImGui.Spacing();
            ImGui.TextUnformatted("Things to review");
            ImGui.TextDisabled("Omega found these while FFXIV and Dalamud were starting.");
            ImGui.Spacing();
            foreach (var item in snapshot.Items)
                DrawStartupHealthItem(item);
        }

        ImGui.Spacing();
        DrawStartupApps(startupAppsSnapshot, snapshot.State);
    }

    private void DrawStartupOverview(StartupHealthSnapshot snapshot, StartupAppsSnapshot? apps)
    {
        var runningCount = apps?.RunningCount ?? 0;
        var expectedCount = apps?.ExpectedCount ?? 0;
        string title;
        string detail;
        Vector4 background;
        Vector4 border;

        if (snapshot.State == StartupHealthCaptureState.NextStartup)
        {
            title = "Startup report available after restart";
            detail = $"{runningCount} plugin{(runningCount == 1 ? " is" : "s are")} running now. Restart FFXIV to also check what happened during startup.";
            background = new Vector4(0.09f, 0.12f, 0.16f, 0.72f);
            border = new Vector4(0.20f, 0.34f, 0.48f, 0.72f);
        }
        else if (!snapshot.IsComplete)
        {
            title = "Checking this startup";
            detail = "Omega is waiting for plugin loading and automatic updates to settle.";
            background = new Vector4(0.07f, 0.12f, 0.16f, 0.72f);
            border = new Vector4(0.16f, 0.42f, 0.56f, 0.72f);
        }
        else if (snapshot.ActionableCount > 0)
        {
            title = "Startup needs a look";
            detail = $"{snapshot.ActionableCount} thing{(snapshot.ActionableCount == 1 ? "" : "s")} may need attention. {runningCount} plugin{(runningCount == 1 ? " is" : "s are")} running now.";
            background = new Vector4(0.16f, 0.065f, 0.055f, 0.72f);
            border = new Vector4(0.72f, 0.28f, 0.20f, 0.72f);
        }
        else
        {
            title = "Startup looks good";
            detail = expectedCount > 0
                ? $"{runningCount} plugin{(runningCount == 1 ? " is" : "s are")} running now; {expectedCount} {(expectedCount == 1 ? "is" : "are")} set to load automatically."
                : $"{runningCount} plugin{(runningCount == 1 ? " is" : "s are")} running now, and Omega found no startup problem.";
            background = new Vector4(0.055f, 0.15f, 0.105f, 0.72f);
            border = new Vector4(0.16f, 0.55f, 0.34f, 0.72f);
        }

        ImGui.PushStyleColor(ImGuiCol.ChildBg, background);
        ImGui.PushStyleColor(ImGuiCol.Border, border);
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, Ui(8f));
        ImGui.BeginChild(
            "startup-overview",
            new Vector2(0f, Ui(92f)),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        if (ImGui.BeginTable("startup-overview-layout", 2, ImGuiTableFlags.SizingStretchProp))
        {
            ImGui.TableSetupColumn("Summary", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Profiler", ImGuiTableColumnFlags.WidthFixed, Ui(186f));
            ImGui.TableNextRow();
            ImGui.TableSetColumnIndex(0);
            ImGui.TextUnformatted(title);
            ImGui.TextWrapped(detail);

            ImGui.TableSetColumnIndex(1);
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + Ui(11f));
            if (DrawPillButton("Open startup profiler", "startup-open-profiler", Ui(176f, 32f), false))
                Plugin.CommandManager.ProcessCommand("/xlprofiler");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("Open Dalamud's built-in startup timing profiler.");
            ImGui.EndTable();
        }

        ImGui.EndChild();
        ImGui.PopStyleVar();
        ImGui.PopStyleColor(2);
    }

    private void DrawStartupApps(StartupAppsSnapshot? apps, StartupHealthCaptureState captureState)
    {
        ImGui.Separator();
        ImGui.Spacing();
        ImGui.TextUnformatted("Startup apps");
        ImGui.TextDisabled("See which plugins are running, when they join startup, and what kind of activity Omega can identify while you play.");

        if (apps is null)
        {
            ImGui.TextDisabled("The startup app list will appear when this startup check finishes.");
            return;
        }

        if (!string.IsNullOrWhiteSpace(apps.Warning))
        {
            ImGui.TextDisabled("Omega could not read the full startup app list from Dalamud.");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(apps.Warning);
        }
        else
        {
            var summary = $"{apps.RunningCount} running now · {apps.ExpectedCount} set to start automatically";
            if (captureState == StartupHealthCaptureState.NextStartup)
                summary += " · startup problems will be checked after the next restart";
            ImGui.TextDisabled(summary);
        }

        ImGui.Spacing();
        if (apps.Apps.Count == 0)
        {
            ImGui.TextDisabled("No installed plugins were available for the startup list.");
            return;
        }

        ImGui.SetNextItemWidth(Math.Min(Ui(360f), ImGui.GetContentRegionAvail().X));
        ImGui.InputTextWithHint("##startup-app-search", "Search startup apps...", ref startupAppSearch, 128);
        var startupNeedle = startupAppSearch.Trim();
        var shownApps = startupNeedle.Length == 0
            ? apps.Apps.ToArray()
            : apps.Apps.Where(app =>
                    Contains(app.Name, startupNeedle) ||
                    Contains(app.InternalName, startupNeedle) ||
                    Contains(app.NowLabel, startupNeedle) ||
                    Contains(app.StartupLabel, startupNeedle) ||
                    Contains(app.ActivityLabel, startupNeedle) ||
                    Contains(app.StatusLabel, startupNeedle))
                .ToArray();
        if (startupNeedle.Length > 0)
            ImGui.TextDisabled($"{shownApps.Length} of {apps.Apps.Count} startup apps");
        if (shownApps.Length == 0)
        {
            ImGui.TextDisabled("No startup apps match that search.");
            return;
        }

        // GetContentRegionAvail().Y can collapse inside this nested Library child at high UI scale,
        // which made Startup fall back to a short 160px-logical table. Measure against the actual
        // child-window bottom instead so the list owns all remaining vertical space. Startup is
        // bounded by installed plugins, so use native table scrolling rather than a fixed-height
        // clipper: that avoids row-height estimation and the scrollbar jumps it can introduce.
        var windowBottom = ImGui.GetWindowPos().Y + ImGui.GetWindowSize().Y - ImGui.GetStyle().WindowPadding.Y;
        var tableHeight = Math.Max(Ui(160f), windowBottom - ImGui.GetCursorScreenPos().Y - Ui(2f));
        var tableFlags = ImGuiTableFlags.ScrollY | ImGuiTableFlags.RowBg | ImGuiTableFlags.BordersInnerH |
                         ImGuiTableFlags.SizingStretchProp;
        if (!ImGui.BeginTable("omega-startup-apps", 5, tableFlags, new Vector2(0f, tableHeight)))
            return;

        ImGui.TableSetupScrollFreeze(0, 1);
        ImGui.TableSetupColumn("Plugin", ImGuiTableColumnFlags.WidthStretch, 1.45f);
        ImGui.TableSetupColumn("Now", ImGuiTableColumnFlags.WidthFixed, Ui(92f));
        ImGui.TableSetupColumn("Startup", ImGuiTableColumnFlags.WidthStretch, 1.05f);
        ImGui.TableSetupColumn("While playing", ImGuiTableColumnFlags.WidthStretch, 1.25f);
        ImGui.TableSetupColumn("Status", ImGuiTableColumnFlags.WidthFixed, Ui(140f));
        ImGui.TableHeadersRow();

        foreach (var app in shownApps)
            DrawStartupAppRow(app);

        ImGui.EndTable();
    }

    private void DrawStartupAppRow(StartupAppEntry app)
    {
        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        if (ImGui.Selectable(
                $"{app.Name}##startup-app-{StableId(app.InternalName)}",
                false,
                ImGuiSelectableFlags.None,
                new Vector2(0f, 0f)))
        {
            OpenStartupHealthPlugin(app.InternalName);
        }
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Open this plugin in Omega.");

        ImGui.TableSetColumnIndex(1);
        DrawStartupNow(app);

        ImGui.TableSetColumnIndex(2);
        if (app.StartupLabel == "Off")
            ImGui.TextDisabled(app.StartupLabel);
        else
            ImGui.TextUnformatted(app.StartupLabel);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(app.StartupDetail);

        ImGui.TableSetColumnIndex(3);
        ImGui.TextUnformatted(app.ActivityLabel);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip($"{app.ActivityDetail}\n\nThis is based on existing plugin metadata and exact-version SigmaScope observations; Omega is not monitoring gameplay activity.");

        ImGui.TableSetColumnIndex(4);
        DrawStartupStatus(app);
    }

    private static void DrawStartupNow(StartupAppEntry app)
    {
        if (app.NowLabel == "Running")
            ImGui.TextColored(new Vector4(0.42f, 0.80f, 0.55f, 1f), app.NowLabel);
        else if (app.NowLabel == "Failed")
            ImGui.TextColored(new Vector4(0.94f, 0.42f, 0.38f, 1f), app.NowLabel);
        else
            ImGui.TextDisabled(app.NowLabel);

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(app.NowDetail);
    }

    private static void DrawStartupStatus(StartupAppEntry app)
    {
        if (app.StatusLabel == "OK")
            ImGui.TextColored(new Vector4(0.42f, 0.80f, 0.55f, 1f), app.StatusLabel);
        else if (app.StatusLabel == "Off")
            ImGui.TextDisabled(app.StatusLabel);
        else
            ImGui.TextColored(new Vector4(0.94f, 0.42f, 0.38f, 1f), app.StatusLabel);

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(app.StatusDetail);
    }

    private MarketplacePlugin? ResolveStartupAppPlugin(string internalName)
    {
        var installed = Plugin.PluginInterface.InstalledPlugins.FirstOrDefault(x =>
            x.InternalName.Equals(internalName, StringComparison.OrdinalIgnoreCase));
        var installedVersion = installed?.Version?.ToString() ?? string.Empty;

        var candidates = catalog.GetVariants(internalName)
            .Concat(catalog.GetPresentationVariants(internalName))
            .Concat(catalog.Plugins.Where(x => x.InternalName.Equals(internalName, StringComparison.OrdinalIgnoreCase)))
            .Distinct()
            .ToArray();

        if (!string.IsNullOrWhiteSpace(installedVersion))
        {
            var exact = candidates
                .Where(x => x.AssemblyVersionText.Equals(installedVersion, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(x => x.HasCompletedSecurityScan)
                .FirstOrDefault();
            if (exact is not null)
                return exact;
        }

        return candidates
            .OrderByDescending(x => x.HasCompletedSecurityScan)
            .ThenByDescending(x => x.AssemblyVersion)
            .FirstOrDefault();
    }

    private void DrawStartupHealthItem(StartupHealthItem item)
    {
        var background = item.Severity switch
        {
            StartupHealthSeverity.Error => new Vector4(0.16f, 0.055f, 0.055f, 0.68f),
            StartupHealthSeverity.Warning => new Vector4(0.16f, 0.105f, 0.045f, 0.68f),
            _ => new Vector4(0.055f, 0.095f, 0.14f, 0.62f),
        };
        var border = item.Severity switch
        {
            StartupHealthSeverity.Error => new Vector4(0.72f, 0.24f, 0.22f, 0.78f),
            StartupHealthSeverity.Warning => new Vector4(0.76f, 0.48f, 0.16f, 0.76f),
            _ => new Vector4(0.20f, 0.42f, 0.62f, 0.62f),
        };

        var hasAction = item.ActionKind != StartupHealthActionKind.None &&
                        !string.IsNullOrWhiteSpace(item.ActionLabel);

        ImGui.PushStyleColor(ImGuiCol.ChildBg, background);
        ImGui.PushStyleColor(ImGuiCol.Border, border);
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, Ui(8f));
        ImGui.BeginChild(
            $"startup-health-item-{item.Id}",
            new Vector2(0f, Ui(hasAction ? 124f : 92f)),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.TextUnformatted(item.Title);
        ImGui.TextWrapped(item.Summary);
        if (!string.IsNullOrWhiteSpace(item.Detail))
        {
            ImGui.TextDisabled("More details");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(item.Detail);
        }

        if (hasAction)
        {
            ImGui.Spacing();
            var actionWidth = Math.Max(Ui(164f), ImGui.CalcTextSize(item.ActionLabel).X + Ui(28f));
            if (DrawPillButton(item.ActionLabel, $"startup-health-action-{item.Id}", new Vector2(actionWidth, Ui(28f)), false))
                ExecuteStartupHealthAction(item);
        }

        ImGui.EndChild();
        ImGui.PopStyleVar();
        ImGui.PopStyleColor(2);
        ImGui.Spacing();
    }

    private void ExecuteStartupHealthAction(StartupHealthItem item)
    {
        switch (item.ActionKind)
        {
            case StartupHealthActionKind.OpenOmegaPlugin:
                OpenStartupHealthPlugin(item.ActionValue);
                break;
            case StartupHealthActionKind.OpenDalamudPlugins:
                Plugin.PluginInterface.OpenPluginInstallerTo();
                break;
            case StartupHealthActionKind.OpenDalamudSettings:
                Plugin.PluginInterface.OpenDalamudSettingsTo(SettingsOpenKind.Experimental, item.ActionValue);
                break;
            case StartupHealthActionKind.OpenOmegaRepositories:
                settingsSection = SettingsSection.Repositories;
                OpenSettings();
                break;
            case StartupHealthActionKind.OpenDalamudStartupProfiler:
                Plugin.CommandManager.ProcessCommand("/xlprofiler");
                break;
        }
    }

    private void OpenStartupHealthPlugin(string internalName)
    {
        if (string.IsNullOrWhiteSpace(internalName))
            return;

        var plugin = catalog.GetVariants(internalName).FirstOrDefault()
                     ?? catalog.GetPresentationVariants(internalName).FirstOrDefault()
                     ?? catalog.Plugins.FirstOrDefault(x =>
                         x.InternalName.Equals(internalName, StringComparison.OrdinalIgnoreCase));

        if (plugin is null)
        {
            var installed = Plugin.PluginInterface.InstalledPlugins.FirstOrDefault(x =>
                x.InternalName.Equals(internalName, StringComparison.OrdinalIgnoreCase));
            if (installed is not null)
            {
                plugin = new MarketplacePlugin
                {
                    Name = installed.Name,
                    InternalName = installed.InternalName,
                    AssemblyVersionText = installed.Version?.ToString() ?? "0.0.0.0",
                    SourceName = "Installed",
                    SourceUrl = installed.Manifest.InstalledFromUrl ?? string.Empty,
                };
            }
        }

        if (plugin is null)
        {
            operationMessage = $"Omega no longer has a product page for {internalName}.";
            return;
        }

        OpenPluginDetails(plugin);
    }
}
