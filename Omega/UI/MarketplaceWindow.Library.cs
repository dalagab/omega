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

    private void DrawLibraryTabs(int installedCount)
    {
        RefreshCollectionsIfNeeded();
        var startX = ImGui.GetCursorPosX();
        if (DrawRoundedButton(
                $"All   {installedCount}",
                "library-tab-all",
                new Vector2(96f, 32f),
                active: librarySection == LibrarySection.All))
        {
            SetLibrarySection(LibrarySection.All);
        }

        ImGui.SameLine(0f, 8f);
        if (DrawRoundedButton(
                $"Collections   {collectionSnapshot.Length}",
                "library-tab-collections",
                new Vector2(142f, 32f),
                active: librarySection == LibrarySection.Collections))
        {
            SetLibrarySection(LibrarySection.Collections);
        }

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
            MarketplaceView.Library when librarySection == LibrarySection.Collections => false,
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
        const float rowHeight = MarketplaceLayoutRules.LibraryRowHeight;
        var rowWidth = Math.Max(420f, ImGui.GetContentRegionAvail().X);
        ImGui.BeginChild($"library-row-{StableId(plugin.InternalName)}", new Vector2(rowWidth, rowHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        // Library > All is deliberately a pure installed-plugin list. Collection membership
        // is managed only from Library > Collections.
        var artworkY = MarketplaceLayoutRules.CenterY(rowHeight, 54f);
        ImGui.SetCursorPosY(artworkY);
        var artworkClicked = DrawPluginArtwork(
            plugin, installedPlugin, 54f, 54f, currentApi, currentDalamudVersion, showOverlays: false);
        if (artworkClicked)
            OpenPluginDetails(plugin);

        ImGui.SameLine(0f, 12f);
        var textStart = ImGui.GetCursorPosX();
        var textHeight = ImGui.GetTextLineHeightWithSpacing() * 3f;
        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, textHeight));
        ImGui.BeginGroup();
        ImGui.TextUnformatted(Shorten(plugin.Name, 42));
        DrawAuthorRepositoryLine(plugin, currentApi);
        ImGui.TextDisabled(Shorten(
            $"{InstalledVersionText(installedPlugin)}  •  {(installedPlugin.IsLoaded ? "Loaded" : "Not loaded")}  •  {BuildCompactCompatibility(plugin, currentApi, currentDalamudVersion)}",
            76));
        ImGui.EndGroup();
        if (ImGui.IsItemClicked(ImGuiMouseButton.Left))
            OpenPluginDetails(plugin);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(BuildInstalledMetadataLine(plugin, currentApi, currentDalamudVersion));

        const float toggleWidth = 44f;
        const float actionWidth = 92f;
        const float actionGap = 10f;
        var actionGroupWidth = toggleWidth + actionGap + actionWidth;
        ImGui.SameLine();
        var actionsX = Math.Max(
            textStart + 240f,
            MarketplaceLayoutRules.RightAlignedX(ImGui.GetWindowContentRegionMax().X, actionGroupWidth));
        ImGui.SetCursorPos(new Vector2(actionsX, MarketplaceLayoutRules.CenterY(rowHeight, 32f)));

        var control = GetPluginDirectControlState(plugin.InternalName);
        var shownState = control.CanDirectToggle ? control.DesiredEnabled : installedPlugin.IsLoaded;
        var isSelf = plugin.InternalName.Equals(Plugin.PluginInterface.InternalName, StringComparison.OrdinalIgnoreCase);
        var canToggleHere = control.CanDirectToggle && !(isSelf && control.DesiredEnabled);
        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, 22f));
        if (DrawToggleSwitch($"library-plugin-state-{StableId(plugin.InternalName)}", shownState, canToggleHere))
            StartDirectPluginStateChange(plugin, control, !control.DesiredEnabled);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(!canToggleHere && isSelf && control.CanDirectToggle
                ? "Omega cannot disable itself from its own window. Use Dalamud to disable Omega."
                : control.CanDirectToggle
                    ? $"{(control.DesiredEnabled ? "Disable" : "Enable")} {plugin.Name}"
                    : control.Reason);

        ImGui.SameLine(0f, actionGap);
        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, 32f));
        var canOpen = installedPlugin.IsLoaded && installedPlugin.HasMainUi;
        if (DrawRoundedButton(
                canOpen ? "Open" : "Details",
                $"library-action-{StableId(plugin.InternalName)}",
                new Vector2(actionWidth, 32f)))
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

    private void DrawUpdateRow(
        MarketplacePlugin plugin,
        IExposedPlugin installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        const float rowHeight = MarketplaceLayoutRules.LibraryRowHeight;
        var rowWidth = Math.Max(420f, ImGui.GetContentRegionAvail().X);
        ImGui.BeginChild($"updates-row-{StableId(plugin.InternalName)}", new Vector2(rowWidth, rowHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, 54f));
        var artworkClicked = DrawPluginArtwork(
            plugin, installedPlugin, 54f, 54f, currentApi, currentDalamudVersion, showOverlays: false);
        if (artworkClicked)
            OpenPluginDetails(plugin);

        ImGui.SameLine(0f, 12f);
        var textStart = ImGui.GetCursorPosX();
        var offered = GetAvailableUpdateVersion(plugin.InternalName, installedPlugin, currentApi, currentDalamudVersion);
        var textHeight = ImGui.GetTextLineHeightWithSpacing() * 3f;
        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, textHeight));
        ImGui.BeginGroup();
        ImGui.TextUnformatted(Shorten(plugin.Name, 42));
        DrawAuthorRepositoryLine(plugin, currentApi);
        var versionLine = offered is null
            ? $"{InstalledVersionText(installedPlugin)}  •  {BuildCompactCompatibility(plugin, currentApi, currentDalamudVersion)}"
            : $"{InstalledVersionText(installedPlugin)} → v{offered}  •  {BuildCompactCompatibility(plugin, currentApi, currentDalamudVersion)}";
        ImGui.TextDisabled(Shorten(versionLine, 76));
        ImGui.EndGroup();
        if (ImGui.IsItemClicked(ImGuiMouseButton.Left))
            OpenPluginDetails(plugin);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(BuildInstalledMetadataLine(plugin, currentApi, currentDalamudVersion));

        const float actionSize = 38f;
        ImGui.SameLine();
        ImGui.SetCursorPos(new Vector2(
            Math.Max(textStart + 240f, MarketplaceLayoutRules.RightAlignedX(ImGui.GetWindowContentRegionMax().X, actionSize)),
            MarketplaceLayoutRules.CenterY(rowHeight, actionSize)));
        if (DrawUpdateActionIcon($"update-action-{StableId(plugin.InternalName)}"))
            Plugin.PluginInterface.OpenPluginInstallerTo(PluginInstallerOpenKind.UpdateablePlugins, plugin.Name);

        ImGui.EndChild();
    }

    private static bool DrawUpdateActionIcon(string id)
    {
        const float size = 38f;
        const float rounding = 6f;
        var min = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##{id}", new Vector2(size, size));
        var hovered = ImGui.IsItemHovered();
        var held = ImGui.IsItemActive();
        var clicked = ImGui.IsItemClicked();
        var draw = ImGui.GetWindowDrawList();

        var background = ImGui.ColorConvertFloat4ToU32(held
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
            ImGui.GetColorU32(ImGuiCol.Text),
            glyph);
        ImGui.PopFont();

        if (hovered)
            ImGui.SetTooltip("Update through Dalamud");
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
        int currentApi,
        Version currentDalamudVersion)
    {
        var source = SourceLabel(plugin);
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
