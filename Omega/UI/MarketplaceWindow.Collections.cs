using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private DalamudPluginCollection[] collectionSnapshot = [];
    private DateTimeOffset collectionsLastReadUtc = DateTimeOffset.MinValue;
    private Guid? openCollectionId;
    private Task<DalamudCollectionOperationResult>? collectionOperationTask;

    private void RefreshCollectionsIfNeeded(bool force = false)
    {
        if (!force && DateTimeOffset.UtcNow - collectionsLastReadUtc < TimeSpan.FromSeconds(1))
            return;

        collectionSnapshot = profileBridge.ReadCollections().ToArray();
        collectionsLastReadUtc = DateTimeOffset.UtcNow;
        if (openCollectionId.HasValue && collectionSnapshot.All(x => x.Id != openCollectionId.Value))
            openCollectionId = null;
    }

    private void CompleteCollectionOperationIfReady()
    {
        if (collectionOperationTask is null || !collectionOperationTask.IsCompleted)
            return;

        try
        {
            var result = collectionOperationTask.GetAwaiter().GetResult();
            operationMessage = result.Message;
        }
        catch (Exception ex)
        {
            operationMessage = $"Collection change failed: {ex.Message}";
        }
        finally
        {
            collectionOperationTask = null;
            RefreshCollectionsIfNeeded(force: true);
        }
    }

    private void DrawCollectionsPage(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        RefreshCollectionsIfNeeded();
        if (openCollectionId is Guid id)
        {
            var collection = collectionSnapshot.FirstOrDefault(x => x.Id == id);
            if (collection is not null)
            {
                DrawOpenCollection(collection, installed, currentApi, currentDalamudVersion);
                return;
            }
            openCollectionId = null;
        }

        DrawCollectionFolders();
    }

    private void DrawCollectionFolders()
    {
        ImGui.TextDisabled("Open a collection folder to see its plugins. Toggle named collections directly from the folder.");
        ImGui.Spacing();
        if (collectionSnapshot.Length == 0)
        {
            ImGui.TextDisabled("No Dalamud collections are available yet.");
            return;
        }

        const float tileWidth = 150f;
        const float gap = 18f;
        var available = ImGui.GetContentRegionAvail().X;
        var columns = Math.Max(1, (int)Math.Floor((available + gap) / (tileWidth + gap)));
        for (var index = 0; index < collectionSnapshot.Length; index++)
        {
            DrawCollectionFolder(collectionSnapshot[index], tileWidth);
            if ((index + 1) % columns != 0 && index + 1 < collectionSnapshot.Length)
                ImGui.SameLine(0f, gap);
            else if (index + 1 < collectionSnapshot.Length)
                ImGui.Spacing();
        }
    }

    private void DrawCollectionFolder(DalamudPluginCollection collection, float width)
    {
        ImGui.BeginGroup();
        var startX = ImGui.GetCursorPosX();
        var folderSize = new Vector2(width, 86f);
        var screen = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##collection-folder-{collection.Id}", folderSize);
        var hovered = ImGui.IsItemHovered();
        if (ImGui.IsItemClicked())
            openCollectionId = collection.Id;
        DrawFolderShape(screen, folderSize, collection.IsEnabled, hovered);

        DrawCenteredTileText(Shorten(CollectionDisplayName(collection), 20), width, false);
        DrawCenteredTileText($"{collection.Plugins.Count} plugin{(collection.Plugins.Count == 1 ? string.Empty : "s")}", width, true);
        DrawCollectionToggle(collection, width);
        ImGui.SetCursorPosX(startX);
        ImGui.Dummy(new Vector2(width, 1f));
        ImGui.EndGroup();
    }

    private static void DrawFolderShape(Vector2 min, Vector2 size, bool enabled, bool hovered)
    {
        var draw = ImGui.GetWindowDrawList();
        var bodyMin = min + new Vector2(6f, 22f);
        var bodyMax = min + new Vector2(size.X - 6f, size.Y - 6f);
        var tabMax = min + new Vector2(Math.Min(size.X * 0.48f, 70f), 30f);
        var baseColor = enabled
            ? new Vector4(0.16f, 0.58f, 0.62f, hovered ? 1f : 0.92f)
            : new Vector4(0.20f, 0.24f, 0.30f, hovered ? 0.95f : 0.78f);
        var edgeColor = enabled
            ? new Vector4(0.24f, 0.84f, 0.78f, 0.95f)
            : new Vector4(0.38f, 0.43f, 0.50f, 0.72f);

        draw.AddRectFilled(min + new Vector2(12f, 10f), tabMax, ImGui.ColorConvertFloat4ToU32(baseColor), 7f);
        draw.AddRectFilled(bodyMin, bodyMax, ImGui.ColorConvertFloat4ToU32(baseColor), 10f);
        draw.AddRect(bodyMin, bodyMax, ImGui.ColorConvertFloat4ToU32(edgeColor), 10f, ImDrawFlags.None, 1.4f);
    }

    private void DrawCollectionToggle(DalamudPluginCollection collection, float width)
    {
        var startX = ImGui.GetCursorPosX();
        var label = collection.IsDefault ? "Always on" : collection.IsEnabled ? "On" : "Off";
        var buttonWidth = collection.IsDefault ? 92f : 62f;
        ImGui.SetCursorPosX(startX + Math.Max(0f, (width - buttonWidth) * 0.5f));

        if (collection.IsDefault)
            ImGui.TextDisabled(label);
        else if (DrawPillButton(label, $"collection-toggle-{collection.Id}", new Vector2(buttonWidth, 28f), collection.IsEnabled))
            StartCollectionToggle(collection, !collection.IsEnabled);
        ImGui.SetCursorPosX(startX);
    }

    private void StartCollectionToggle(DalamudPluginCollection collection, bool enabled)
    {
        if (collectionOperationTask is not null)
        {
            operationMessage = "Dalamud is already changing a collection.";
            return;
        }

        operationMessage = $"Turning {CollectionDisplayName(collection)} {(enabled ? "on" : "off")}…";
        collectionOperationTask = Task.Run(() => profileBridge.SetCollectionEnabledAsync(collection.Id, enabled));
    }

    private void DrawOpenCollection(
        DalamudPluginCollection collection,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (DrawPillButton("← Folders", "collections-back", new Vector2(96f, 30f), false))
            openCollectionId = null;
        ImGui.SameLine(0f, 12f);
        ImGui.Text(CollectionDisplayName(collection));
        ImGui.SameLine(0f, 12f);
        DrawCollectionHeaderToggle(collection);
        ImGui.TextDisabled($"{collection.Plugins.Count} plugins in this Dalamud collection");
        ImGui.Spacing();

        DrawCollectionPluginGrid(collection, installed, currentApi, currentDalamudVersion);
    }

    private void DrawCollectionHeaderToggle(DalamudPluginCollection collection)
    {
        if (collection.IsDefault)
        {
            ImGui.TextDisabled("Always on");
            return;
        }

        var label = collection.IsEnabled ? "On" : "Off";
        if (DrawPillButton(label, $"collection-header-toggle-{collection.Id}", new Vector2(62f, 28f), collection.IsEnabled))
            StartCollectionToggle(collection, !collection.IsEnabled);
    }

    private void DrawCollectionPluginGrid(
        DalamudPluginCollection collection,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        var projection = catalog.GetMainProjection(currentApi).Plugins
            .ToDictionary(x => x.InternalName, StringComparer.OrdinalIgnoreCase);
        const float targetWidth = 138f;
        const float gap = 16f;
        var available = ImGui.GetContentRegionAvail().X;
        var columns = Math.Max(1, (int)Math.Floor((available + gap) / (targetWidth + gap)));
        var tileWidth = Math.Max(112f, (available - ((columns - 1) * gap)) / columns);

        for (var index = 0; index < collection.Plugins.Count; index++)
        {
            DrawCollectionPlugin(collection.Plugins[index], projection, installed, currentApi, currentDalamudVersion, tileWidth);
            if ((index + 1) % columns != 0 && index + 1 < collection.Plugins.Count)
                ImGui.SameLine(0f, gap);
            else if (index + 1 < collection.Plugins.Count)
                ImGui.Spacing();
        }
    }

    private void DrawCollectionPlugin(
        DalamudCollectionPlugin entry,
        IReadOnlyDictionary<string, MarketplacePlugin> projection,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion,
        float width)
    {
        var plugin = projection.TryGetValue(entry.InternalName, out var known)
            ? known
            : new MarketplacePlugin { Name = entry.InternalName, InternalName = entry.InternalName, SourceName = "Installed" };
        installed.TryGetValue(entry.InternalName, out var installedPlugin);
        var iconSize = Math.Clamp(width - 12f, 94f, 126f);
        if (DrawPluginArtwork(plugin, installedPlugin, iconSize, width, currentApi, currentDalamudVersion, showOverlays: false))
            OpenPluginDetails(plugin);
        DrawCenteredTileText(Shorten(plugin.Name, 20), width, false);
        DrawCenteredTileText(entry.WantsEnabled ? "Enabled in collection" : "Disabled in collection", width, true);
    }

    private static string CollectionDisplayName(DalamudPluginCollection collection)
        => collection.IsDefault ? "Default plugins" : collection.Name;
}
