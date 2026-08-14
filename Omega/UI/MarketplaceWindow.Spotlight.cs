using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private const int SpotlightCardCount = 5;
    private const float SpotlightCardGap = 10f;
    private const float SpotlightCardHeight = 300f;
    private const float SpotlightCardMinWidth = 142f;
    private const float SpotlightCardMaxWidth = 220f;
    private int spotlightSourceRefreshRequested;
    private DateTimeOffset spotlightSourceRefreshNotBeforeUtc;

    private void DrawSpotlightPage(
        IReadOnlyList<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        RequestMissingSpotlightSources(plugins);
        pluginRecency.Observe(plugins);
        DrawSpotlightSections(plugins, installed, currentApi, currentDalamudVersion);
    }

    private void DrawSpotlightCard(
        MarketplacePlugin plugin,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion,
        float cardWidth)
    {
        plugin = ResolveSpotlightVariant(plugin);
        installed.TryGetValue(plugin.InternalName, out var installedPlugin);

        ImGui.BeginChild(
            $"spotlight-card-{plugin.InternalName}",
            new Vector2(cardWidth, SpotlightCardHeight),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var innerWidth = ImGui.GetContentRegionAvail().X;
        var artworkSize = Math.Clamp(cardWidth * 0.52f, 84f, 110f);
        _ = DrawPluginArtwork(
            plugin,
            installedPlugin,
            artworkSize,
            innerWidth,
            currentApi,
            currentDalamudVersion,
            showOverlays: false);

        ImGui.Spacing();
        CenterText(Shorten(plugin.Name, 24));
        CenterText(Shorten(string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author, 26), disabled: true);
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        DrawSpotlightPitch(plugin);
        ImGui.SetCursorPosY(Math.Max(ImGui.GetCursorPosY(), SpotlightCardHeight - 54f));
        DrawSpotlightActionRow(plugin, installedPlugin, currentApi, currentDalamudVersion);

        ImGui.EndChild();
    }

    private MarketplacePlugin ResolveSpotlightVariant(MarketplacePlugin plugin)
    {
        var variants = catalog.GetVariants(plugin.InternalName);
        return variants
                   .Where(x => x.SourceIsOfficial)
                   .OrderByDescending(x => x.AssemblyVersion)
                   .FirstOrDefault()
               ?? ResolveSelectedVariant(plugin);
    }

    private static void DrawSpotlightPitch(MarketplacePlugin plugin)
    {
        var pitch = !string.IsNullOrWhiteSpace(plugin.Punchline)
            ? plugin.Punchline
            : plugin.Description;
        if (string.IsNullOrWhiteSpace(pitch))
            pitch = "Highlighted by Omega.";

        ImGui.TextWrapped(Shorten(pitch.Trim(), 70));
    }

    private void DrawSpotlightActionRow(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        const float gap = 6f;
        const float infoSize = 32f;
        var width = ImGui.GetContentRegionAvail().X;
        var actionWidth = Math.Max(68f, width - infoSize - gap);

        if (installedPlugin is not null)
        {
            DrawSpotlightInstalledPill(new Vector2(actionWidth, 32f));
        }
        else
        {
            var candidates = GetInstallCandidates(plugin.InternalName, currentApi, currentDalamudVersion);
            if (candidates.Count == 0)
                DrawSpotlightUnavailablePill(new Vector2(actionWidth, 32f));
            else if (DrawPillButton("Install", $"spotlight-install-{plugin.InternalName}", new Vector2(actionWidth, 32f), true))
                OpenInstallChooser(plugin);
        }

        ImGui.SameLine(0f, gap);
        if (DrawSpotlightInfoButton(plugin, infoSize))
            OpenSpotlightPluginInDiscover(plugin);
    }

    private static void DrawSpotlightInstalledPill(Vector2 size)
        => DrawSpotlightStatusPill("Installed", size, new Vector4(0.12f, 0.13f, 0.15f, 0.96f));

    private static void DrawSpotlightUnavailablePill(Vector2 size)
        => DrawSpotlightStatusPill("Unavailable", size, new Vector4(0.10f, 0.11f, 0.13f, 0.92f));

    private static void DrawSpotlightStatusPill(string label, Vector2 size, Vector4 background)
    {
        var screen = ImGui.GetCursorScreenPos();
        ImGui.Dummy(size);
        var draw = ImGui.GetWindowDrawList();
        draw.AddRectFilled(screen, screen + size, ImGui.ColorConvertFloat4ToU32(background), size.Y * 0.5f);
        draw.AddRect(
            screen,
            screen + size,
            ImGui.ColorConvertFloat4ToU32(new Vector4(0.30f, 0.32f, 0.35f, 0.62f)),
            size.Y * 0.5f,
            ImDrawFlags.None,
            1f);
        var textSize = ImGui.CalcTextSize(label);
        draw.AddText(
            screen + new Vector2((size.X - textSize.X) * 0.5f, (size.Y - textSize.Y) * 0.5f),
            ImGui.GetColorU32(ImGuiCol.TextDisabled),
            label);
    }

    private static bool DrawSpotlightInfoButton(MarketplacePlugin plugin, float size)
    {
        var screen = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##spotlight-more-{plugin.InternalName}", new Vector2(size, size));
        var hovered = ImGui.IsItemHovered();
        var held = ImGui.IsItemActive();
        var clicked = ImGui.IsItemClicked();
        var draw = ImGui.GetWindowDrawList();
        var bg = held
            ? new Vector4(0.08f, 0.20f, 0.22f, 1f)
            : hovered
                ? new Vector4(0.07f, 0.15f, 0.17f, 0.98f)
                : new Vector4(0.07f, 0.08f, 0.10f, 0.94f);
        var border = new Vector4(0.12f, 0.55f, 0.53f, hovered ? 0.90f : 0.42f);
        draw.AddRectFilled(screen, screen + new Vector2(size, size), ImGui.ColorConvertFloat4ToU32(bg), size * 0.5f);
        draw.AddRect(screen, screen + new Vector2(size, size), ImGui.ColorConvertFloat4ToU32(border), size * 0.5f);

        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        var glyph = FontAwesomeIcon.InfoCircle.ToIconString();
        var glyphSize = ImGui.CalcTextSize(glyph);
        draw.AddText(
            screen + new Vector2((size - glyphSize.X) * 0.5f, (size - glyphSize.Y) * 0.5f),
            ImGui.GetColorU32(ImGuiCol.Text),
            glyph);
        ImGui.PopFont();

        if (hovered)
            ImGui.SetTooltip("More information in Discover");
        return clicked;
    }

    private void OpenSpotlightPluginInDiscover(MarketplacePlugin plugin)
    {
        ResetFilters();
        activeView = MarketplaceView.Discover;
        selectedPlugin = ResolveSpotlightVariant(plugin);
        detailsOpen = true;
        resetStorefrontScroll = true;
        _ = updates.RefreshPluginSourcesAsync(plugin.InternalName);
    }

    private void DrawMissingSpotlightCard(string internalName, float cardWidth)
    {
        ImGui.BeginChild(
            $"spotlight-card-missing-{internalName}",
            new Vector2(cardWidth, SpotlightCardHeight),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.Dummy(new Vector2(1f, 92f));
        CenterText(SpotlightDisplayName(internalName));
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();
        ImGui.TextWrapped("Loading highlighted plugin…");
        ImGui.EndChild();
    }

    private void RequestMissingSpotlightSources(IReadOnlyList<MarketplacePlugin> plugins)
    {
        if (updates.IsRefreshing ||
            DateTimeOffset.UtcNow < spotlightSourceRefreshNotBeforeUtc ||
            Volatile.Read(ref spotlightSourceRefreshRequested) != 0)
        {
            return;
        }

        var missingAetherLove = !plugins.Any(x =>
            x.InternalName.Equals("AetherLovePlugin", StringComparison.OrdinalIgnoreCase));
        var aetherLoveEnabled = configuration.Repositories.Any(x =>
            x.Enabled &&
            x.IsCurated &&
            x.CuratedId.Equals("aetherlove-aetheros", StringComparison.OrdinalIgnoreCase));
        if (!missingAetherLove || !aetherLoveEnabled)
            return;

        if (Interlocked.CompareExchange(ref spotlightSourceRefreshRequested, 1, 0) != 0)
            return;

        spotlightSourceRefreshNotBeforeUtc = DateTimeOffset.UtcNow.AddMinutes(5);
        _ = RefreshMissingSpotlightSourcesAsync();
    }

    private async Task RefreshMissingSpotlightSourcesAsync()
    {
        try
        {
            await updates.RefreshCuratedSourcesAsync(["aetherlove-aetheros"]).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not refresh the missing AetherLove Spotlight source.");
        }
        finally
        {
            Interlocked.Exchange(ref spotlightSourceRefreshRequested, 0);
        }
    }

    private static string SpotlightDisplayName(string internalName) => internalName switch
    {
        "HonseFarm.Client" => "HonseFarm.Client",
        "AetherLovePlugin" => "AetherLove / AetherOS",
        "InventoryTools" => "Allagan Tools",
        "GatherBuddy" => "GatherBuddy",
        "ChatTwo" => "Chat 2",
        _ => internalName,
    };
}
