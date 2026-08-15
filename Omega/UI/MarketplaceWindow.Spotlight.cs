using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private const int SpotlightCardCount = 5;
    private const float SpotlightCardGap = 10f;
    private const float SpotlightCardHeight = 262f;
    private const float SpotlightCardMinWidth = 142f;
    private const float SpotlightCardMaxWidth = 220f;
    private const float SpotlightArtworkSize = 104f;
    // Promoted-card palettes are derived from each highlighted plugin logo rather than Omega branding.
    // They are intentionally darkened so the logo remains the visual focus.
    private static (Vector4 Background, Vector4 Border) SpotlightPromotedCardColors(MarketplacePlugin plugin)
        => plugin.InternalName switch
        {
            // HonseFarm.Client: vivid red mark.
            "HonseFarm.Client" => (new Vector4(0.115f, 0.024f, 0.031f, 0.84f), new Vector4(0.46f, 0.10f, 0.13f, 0.72f)),
            // AetherLove / AetherOS: blue/cyan crystal.
            "AetherLovePlugin" => (new Vector4(0.025f, 0.064f, 0.105f, 0.84f), new Vector4(0.12f, 0.35f, 0.56f, 0.72f)),
            // Allagan Tools: parchment/gold lettering.
            "InventoryTools" => (new Vector4(0.102f, 0.073f, 0.030f, 0.84f), new Vector4(0.43f, 0.30f, 0.10f, 0.72f)),
            // GatherBuddy: earthy/tan emblem.
            "GatherBuddy" => (new Vector4(0.080f, 0.070f, 0.045f, 0.84f), new Vector4(0.31f, 0.26f, 0.15f, 0.72f)),
            // Chat 2: monochrome speech-bubble mark.
            "ChatTwo" => (new Vector4(0.064f, 0.066f, 0.073f, 0.84f), new Vector4(0.26f, 0.27f, 0.31f, 0.72f)),
            _ => (new Vector4(0.045f, 0.052f, 0.064f, 0.82f), new Vector4(0.17f, 0.19f, 0.22f, 0.55f)),
        };
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
        var availabilityStyle = PushUnavailableListingStyle(
            IsListingCurrentlyAvailable(plugin, installedPlugin, currentApi, currentDalamudVersion));

        var cardColors = SpotlightPromotedCardColors(plugin);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, cardColors.Background);
        ImGui.PushStyleColor(ImGuiCol.Border, cardColors.Border);
        ImGui.BeginChild(
            $"spotlight-card-{plugin.InternalName}",
            new Vector2(cardWidth, SpotlightCardHeight),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var contentStartY = ImGui.GetCursorPosY();
        var artworkClicked = DrawPluginArtwork(
            plugin,
            installedPlugin,
            SpotlightArtworkSize,
            ImGui.GetContentRegionAvail().X,
            currentApi,
            currentDalamudVersion,
            showOverlays: false);

        // Security/automation status is important enough to stay visible on Spotlight,
        // using exactly the same icon language and cross-variant aggregation as Discover.
        var afterArtwork = ImGui.GetCursorPos();
        const float statusIconSize = 22f;
        ImGui.SetCursorPos(new Vector2(Math.Max(0f, cardWidth - statusIconSize - 8f), contentStartY));
        DrawPluginRiskIndicator(plugin, statusIconSize);
        ImGui.SetCursorPos(afterArtwork);

        ImGui.SetCursorPosY(contentStartY + 112f);
        CenterText(Shorten(plugin.Name, 24));
        ImGui.SetCursorPosY(contentStartY + 136f);
        CenterText(Shorten(string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author, 26), disabled: true);

        ImGui.SetCursorPosY(contentStartY + 166f);
        ImGui.Separator();
        ImGui.SetCursorPosY(contentStartY + 178f);
        DrawSpotlightPitch(plugin);

        var clicked = ImGui.IsWindowHovered() && ImGui.IsMouseClicked(ImGuiMouseButton.Left);
        if (ImGui.IsWindowHovered())
            ImGui.SetTooltip("Open in Discover");
        ImGui.EndChild();
        ImGui.PopStyleColor(2);
        PopUnavailableListingStyle(availabilityStyle);

        if (artworkClicked || clicked)
            OpenSpotlightPluginInDiscover(plugin);
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

        ImGui.TextWrapped(Shorten(pitch.Trim(), 78));
    }

    private void OpenSpotlightPluginInDiscover(MarketplacePlugin plugin)
    {
        ResetFilters();
        plugin = ResolveSpotlightVariant(plugin);
        OpenPluginDetails(plugin);
    }

    private void DrawMissingSpotlightCard(string internalName, float cardWidth)
    {
        ImGui.BeginChild(
            $"spotlight-card-missing-{internalName}",
            new Vector2(cardWidth, SpotlightCardHeight),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var contentStartY = ImGui.GetCursorPosY();
        ImGui.SetCursorPosY(contentStartY + 112f);
        CenterText(SpotlightDisplayName(internalName), disabled: true);
        ImGui.SetCursorPosY(contentStartY + 166f);
        ImGui.Separator();
        ImGui.SetCursorPosY(contentStartY + 178f);
        ImGui.TextDisabled("Loading highlighted plugin…");
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

        var recoveryTargets = new[]
        {
            (InternalName: "HonseFarm.Client", CuratedId: "honse-farm"),
            (InternalName: "AetherLovePlugin", CuratedId: "aetherlove-aetheros"),
        };
        var missingCuratedIds = recoveryTargets
            .Where(target => !plugins.Any(x =>
                x.InternalName.Equals(target.InternalName, StringComparison.OrdinalIgnoreCase)))
            .Where(target => configuration.Repositories.Any(x =>
                x.Enabled && x.IsCurated &&
                x.CuratedId.Equals(target.CuratedId, StringComparison.OrdinalIgnoreCase)))
            .Select(target => target.CuratedId)
            .ToArray();
        if (missingCuratedIds.Length == 0)
            return;

        if (Interlocked.CompareExchange(ref spotlightSourceRefreshRequested, 1, 0) != 0)
            return;

        spotlightSourceRefreshNotBeforeUtc = DateTimeOffset.UtcNow.AddMinutes(5);
        _ = RefreshMissingSpotlightSourcesAsync(missingCuratedIds);
    }

    private async Task RefreshMissingSpotlightSourcesAsync(IReadOnlyList<string> curatedIds)
    {
        try
        {
            await updates.RefreshCuratedSourcesAsync(curatedIds).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not refresh missing Spotlight sources: {Sources}.", string.Join(", ", curatedIds));
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
