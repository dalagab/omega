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
        if (DrawPillButton(
                $"All   {installedCount}",
                "library-tab-all",
                new Vector2(96f, 32f),
                librarySection == LibrarySection.All))
        {
            SetLibrarySection(LibrarySection.All);
        }

        ImGui.SameLine(0f, 8f);
        if (DrawPillButton(
                $"Collections   {collectionSnapshot.Length}",
                "library-tab-collections",
                new Vector2(142f, 32f),
                librarySection == LibrarySection.Collections))
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
            MarketplaceView.Library when librarySection == LibrarySection.Collections => false,
            _ => true,
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
        var rowWidth = Math.Max(420f, ImGui.GetContentRegionAvail().X);
        ImGui.BeginChild($"library-row-{StableId(plugin.InternalName)}", new Vector2(rowWidth, 74f), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var artworkClicked = DrawPluginArtwork(
            plugin, installedPlugin, 48f, 48f, currentApi, currentDalamudVersion, showOverlays: false);
        if (artworkClicked)
            OpenPluginDetails(plugin);

        ImGui.SameLine(0f, 12f);
        var textStart = ImGui.GetCursorPosX();
        ImGui.BeginGroup();
        ImGui.TextUnformatted(Shorten(plugin.Name, 42));
        var author = string.IsNullOrWhiteSpace(plugin.Author) ? "Installed plugin" : plugin.Author;
        ImGui.TextDisabled(Shorten(author, 48));
        ImGui.TextDisabled($"{(installedPlugin.IsLoaded ? "Loaded" : "Installed")}  •  {InstalledVersionText(installedPlugin)}");
        ImGui.EndGroup();

        var actionWidth = 104f;
        ImGui.SameLine();
        ImGui.SetCursorPosX(Math.Max(textStart + 220f, ImGui.GetWindowContentRegionMax().X - actionWidth - 12f));
        var canOpen = installedPlugin.IsLoaded && installedPlugin.HasMainUi;
        if (DrawPillButton(
                canOpen ? "Open" : "Details",
                $"library-action-{StableId(plugin.InternalName)}",
                new Vector2(actionWidth, 32f),
                false))
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
        var rowWidth = Math.Max(420f, ImGui.GetContentRegionAvail().X);
        ImGui.BeginChild($"updates-row-{StableId(plugin.InternalName)}", new Vector2(rowWidth, 74f), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var artworkClicked = DrawPluginArtwork(
            plugin, installedPlugin, 48f, 48f, currentApi, currentDalamudVersion, showOverlays: false);
        if (artworkClicked)
            OpenPluginDetails(plugin);

        ImGui.SameLine(0f, 12f);
        var textStart = ImGui.GetCursorPosX();
        ImGui.BeginGroup();
        ImGui.TextUnformatted(Shorten(plugin.Name, 42));
        var author = string.IsNullOrWhiteSpace(plugin.Author) ? "Installed plugin" : plugin.Author;
        ImGui.TextDisabled(Shorten(author, 48));
        var offered = GetAvailableUpdateVersion(plugin.InternalName, installedPlugin, currentApi, currentDalamudVersion);
        ImGui.TextDisabled(offered is null
            ? $"Installed v{installedPlugin.Version}"
            : $"v{installedPlugin.Version}  →  v{offered}");
        ImGui.EndGroup();

        const float actionWidth = 104f;
        ImGui.SameLine();
        ImGui.SetCursorPosX(Math.Max(textStart + 220f, ImGui.GetWindowContentRegionMax().X - actionWidth - 12f));
        if (DrawPillButton(
                "Update",
                $"update-action-{StableId(plugin.InternalName)}",
                new Vector2(actionWidth, 32f),
                true))
        {
            Plugin.PluginInterface.OpenPluginInstallerTo(PluginInstallerOpenKind.UpdateablePlugins, plugin.Name);
        }
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Update through Dalamud");

        ImGui.EndChild();
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

    private static string InstalledVersionText(IExposedPlugin installedPlugin)
        => installedPlugin.Version is { } version ? $"v{version}" : "version pending";

}
