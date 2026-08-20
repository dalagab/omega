using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private DalamudPluginCollection[] collectionSnapshot = [];
    private DateTimeOffset collectionsLastReadUtc = DateTimeOffset.MinValue;
    private Guid? openCollectionId;
    private Task<DalamudCollectionOperationResult>? collectionOperationTask;
    private bool collectionAddPickerOpen;
    private string collectionAddSearch = string.Empty;

    private sealed record PluginCollectionMembershipState(
        DalamudPluginCollection Collection,
        DalamudCollectionPlugin Entry);

    private sealed record PluginDirectControlState(
        bool CanDirectToggle,
        bool DesiredEnabled,
        string Reason,
        PluginCollectionMembershipState? DirectMembership,
        IReadOnlyList<PluginCollectionMembershipState> Memberships);

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
        ImGui.Spacing();
        if (collectionSnapshot.Length == 0)
        {
            ImGui.TextDisabled("No Dalamud collections are available yet.");
            return;
        }

        var tileWidth = Ui(166f);
        var gap = Ui(18f);
        var available = ImGui.GetContentRegionAvail().X;
        var columns = ResponsiveColumns(available, 166f, Math.Max(1, collectionSnapshot.Length), 18f);
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
        var folderSize = new Vector2(width, Ui(92f));
        var screen = ImGui.GetCursorScreenPos();
        ImGui.InvisibleButton($"##collection-folder-{collection.Id}", folderSize);
        var hovered = ImGui.IsItemHovered();
        if (ImGui.IsItemClicked())
        {
            openCollectionId = collection.Id;
            collectionAddPickerOpen = false;
            collectionAddSearch = string.Empty;
        }

        DrawFolderShape(screen, folderSize, collection.IsEnabled, hovered);

        DrawCenteredTileText(Shorten(CollectionDisplayName(collection), 22), width, false);
        DrawCenteredTileText($"{collection.Plugins.Count} plugin{(collection.Plugins.Count == 1 ? string.Empty : "s")}", width, true);
        DrawCollectionToggle(collection, width);
        ImGui.SetCursorPosX(startX);
        ImGui.Dummy(new Vector2(width, Ui(1f)));
        ImGui.EndGroup();
    }

    private static void DrawFolderShape(
        Vector2 min,
        Vector2 size,
        bool enabled,
        bool hovered)
    {
        var draw = ImGui.GetWindowDrawList();
        var bodyMin = min + Ui(6f, 22f);
        var bodyMax = min + new Vector2(size.X - Ui(6f), size.Y - Ui(6f));
        var tabMax = min + new Vector2(Math.Min(size.X * 0.48f, Ui(78f)), Ui(30f));
        var baseColor = enabled
            ? new Vector4(0.16f, 0.58f, 0.62f, hovered ? 1f : 0.92f)
            : new Vector4(0.20f, 0.24f, 0.30f, hovered ? 0.95f : 0.78f);
        var edgeColor = enabled
            ? new Vector4(0.24f, 0.84f, 0.78f, 0.95f)
            : new Vector4(0.38f, 0.43f, 0.50f, 0.72f);

        draw.AddRectFilled(min + Ui(12f, 10f), tabMax, ImGui.ColorConvertFloat4ToU32(baseColor), Ui(7f));
        draw.AddRectFilled(bodyMin, bodyMax, ImGui.ColorConvertFloat4ToU32(baseColor), Ui(10f));
        draw.AddRect(bodyMin, bodyMax, ImGui.ColorConvertFloat4ToU32(edgeColor), Ui(10f), ImDrawFlags.None, Ui(1.4f));
    }

    private void DrawCollectionToggle(DalamudPluginCollection collection, float width)
    {
        var startX = ImGui.GetCursorPosX();
        if (collection.IsDefault)
        {
            var label = "Always active";
            var textWidth = ImGui.CalcTextSize(label).X;
            ImGui.SetCursorPosX(startX + Math.Max(0f, (width - textWidth) * 0.5f));
            ImGui.TextDisabled(label);
            ImGui.SetCursorPosX(startX);
            return;
        }

        var switchWidth = Ui(44f);
        var controlsEnabled = collectionOperationTask is null;
        ImGui.SetCursorPosX(startX + Math.Max(0f, (width - switchWidth) * 0.5f));
        if (DrawToggleSwitch($"collection-toggle-{collection.Id}", collection.IsEnabled, controlsEnabled))
            StartCollectionToggle(collection, !collection.IsEnabled);
        if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
            ImGui.SetTooltip(controlsEnabled
                ? (collection.IsEnabled ? "Disable this collection" : "Enable this collection")
                : "Another Dalamud collection change is still being applied.");
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
        var headerY = ImGui.GetCursorPosY();
        if (DrawApplicationIconButton(FontAwesomeIcon.ArrowLeft, "collections-back", "Back to collection folders", false))
            openCollectionId = null;

        ImGui.SameLine(0f, Ui(10f));
        ImGui.SetCursorPosY(headerY + MarketplaceLayoutRules.CenterY(Ui(32f), ImGui.GetTextLineHeight()));
        ImGui.TextDisabled("Library / Collections /");
        ImGui.SameLine(0f, Ui(6f));
        ImGui.TextUnformatted(CollectionDisplayName(collection));

        ImGui.SetCursorPosY(headerY + Ui(38f));
        ImGui.TextDisabled($"{collection.Plugins.Count} plugins in this Dalamud collection");
        ImGui.SameLine(0f, Ui(14f));
        DrawCollectionHeaderToggle(collection);

        ImGui.SetCursorPosY(headerY + Ui(66f));
        if (collection.IsDefault)
        {
            ImGui.TextDisabled("Default membership is automatic.");
        }
        else
        {
            ImGui.TextDisabled("Collection membership");
            ImGui.Spacing();
            var collectionControlsEnabled = collectionOperationTask is null;
            if (DrawRoundedButton(
                    collectionAddPickerOpen ? "Close picker" : "+ Add plugins",
                    $"collection-add-picker-toggle-{collection.Id}",
                    new Vector2(Ui(collectionAddPickerOpen ? 108f : 112f), Ui(30f)),
                    active: collectionAddPickerOpen,
                    enabled: collectionControlsEnabled))
            {
                collectionAddPickerOpen = !collectionAddPickerOpen;
                if (!collectionAddPickerOpen)
                    collectionAddSearch = string.Empty;
            }
            if (!collectionControlsEnabled && ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
                ImGui.SetTooltip("Another Dalamud collection change is still being applied.");
            if (collectionAddPickerOpen)
            {
                ImGui.Spacing();
                DrawCollectionAddPicker(collection, installed, currentApi);
            }
        }
        ImGui.Spacing();

        DrawCollectionDirectoryList(collection, installed, currentApi, currentDalamudVersion);
    }

    private void DrawCollectionHeaderToggle(DalamudPluginCollection collection)
    {
        if (collection.IsDefault)
        {
            ImGui.TextDisabled("Always active");
            return;
        }

        ImGui.TextDisabled("Collection active");
        ImGui.SameLine(0f, Ui(7f));
        ImGui.SetCursorPosY(ImGui.GetCursorPosY() - Ui(2f));
        var controlsEnabled = collectionOperationTask is null;
        if (DrawToggleSwitch($"collection-header-toggle-{collection.Id}", collection.IsEnabled, controlsEnabled))
            StartCollectionToggle(collection, !collection.IsEnabled);
        if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
            ImGui.SetTooltip(controlsEnabled
                ? (collection.IsEnabled ? "Disable this collection" : "Enable this collection")
                : "Another Dalamud collection change is still being applied.");
    }

    private void DrawCollectionAddPicker(
        DalamudPluginCollection collection,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi)
    {
        var pickerHeight = Ui(220f);
        ImGui.BeginChild(
            $"collection-add-picker-{collection.Id}",
            new Vector2(0f, pickerHeight),
            true,
            ImGuiWindowFlags.NoScrollbar);

        ImGui.TextUnformatted("Installed plugins not yet in this collection");
        ImGui.SetNextItemWidth(Math.Min(Ui(360f), Math.Max(Ui(180f), ImGui.GetContentRegionAvail().X - Ui(10f))));
        ImGui.InputTextWithHint(
            $"##collection-add-search-{collection.Id}",
            "Search installed plugins...",
            ref collectionAddSearch,
            128);
        ImGui.Spacing();

        var projection = BuildLibraryProjection(catalog.GetMainProjection(currentApi).Plugins, installed);
        var query = collectionAddSearch.Trim();
        var candidates = projection
            .Where(x => installed.ContainsKey(x.InternalName))
            .Where(x => !CollectionContainsPlugin(collection, x.InternalName))
            .Where(x => string.IsNullOrWhiteSpace(query) ||
                        x.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                        x.InternalName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                        x.Author.Contains(query, StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (candidates.Length == 0)
        {
            ImGui.TextDisabled(string.IsNullOrWhiteSpace(query)
                ? "Every installed plugin is already in this collection."
                : "No installed plugins match this search.");
            ImGui.EndChild();
            return;
        }

        ImGui.BeginChild(
            $"collection-add-picker-list-{collection.Id}",
            Vector2.Zero,
            false,
            ImGuiWindowFlags.AlwaysVerticalScrollbar);
        foreach (var plugin in candidates)
        {
            ImGui.PushID($"collection-add-candidate-{collection.Id}-{StableId(plugin.InternalName)}");
            var startY = ImGui.GetCursorPosY();
            ImGui.TextUnformatted(Shorten(plugin.Name, 48));
            ImGui.TextDisabled(Shorten(plugin.InternalName, 58));

            var addWidth = Ui(64f);
            ImGui.SameLine();
            ImGui.SetCursorPos(new Vector2(
                Math.Max(Ui(220f), ImGui.GetWindowContentRegionMax().X - addWidth - Ui(10f)),
                startY + Ui(4f)));
            var canAdd = collectionOperationTask is null;
            if (DrawRoundedButton("Add", "collection-add-candidate-action", new Vector2(addWidth, Ui(28f)), enabled: canAdd))
                StartAddPluginToCollection(collection, plugin.InternalName, plugin.Name);
            if (!canAdd && ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
                ImGui.SetTooltip("Another Dalamud collection change is still being applied.");

            ImGui.Separator();
            ImGui.PopID();
        }
        ImGui.EndChild();
        ImGui.EndChild();
    }

    private void DrawCollectionDirectoryList(
        DalamudPluginCollection collection,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        var projection = catalog.GetMainProjection(currentApi).Plugins
            .ToDictionary(x => x.InternalName, StringComparer.OrdinalIgnoreCase);

        if (collection.Plugins.Count == 0)
        {
            ImGui.TextDisabled(collection.IsDefault
                ? "No plugins are currently in the default collection."
                : "This folder is empty. Use + Add plugins above to add installed plugins.");
            return;
        }

        foreach (var entry in collection.Plugins.OrderBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase))
        {
            var plugin = projection.TryGetValue(entry.InternalName, out var known)
                ? known
                : new MarketplacePlugin { Name = entry.InternalName, InternalName = entry.InternalName, SourceName = "Installed" };
            installed.TryGetValue(entry.InternalName, out var installedPlugin);
            DrawCollectionDirectoryRow(collection, entry, plugin, installedPlugin, currentApi, currentDalamudVersion);
            ImGui.Spacing();
        }
    }

    private void DrawCollectionDirectoryRow(
        DalamudPluginCollection collection,
        DalamudCollectionPlugin entry,
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        var rowHeight = Ui(MarketplaceLayoutRules.CollectionRowHeight);
        var rowWidth = Math.Max(Ui(420f), ImGui.GetContentRegionAvail().X);
        ImGui.BeginChild($"collection-file-{collection.Id}-{StableId(entry.InternalName)}", new Vector2(rowWidth, rowHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, Ui(48f)));
        var artworkClicked = DrawPluginArtwork(
            plugin, installedPlugin, Ui(48f), Ui(48f), currentApi, currentDalamudVersion, showOverlays: false);
        if (artworkClicked)
            OpenPluginDetails(plugin);

        ImGui.SameLine(0f, Ui(12f));
        var textStart = ImGui.GetCursorPosX();
        var textHeight = ImGui.GetTextLineHeightWithSpacing() * 3f;
        ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, textHeight));
        ImGui.BeginGroup();
        ImGui.TextUnformatted(Shorten(plugin.Name, 44));
        DrawAuthorRepositoryLine(plugin, currentApi);
        ImGui.TextDisabled(entry.WantsEnabled ? "Enabled when this collection is active" : "Disabled in this collection");
        ImGui.EndGroup();
        if (ImGui.IsItemClicked(ImGuiMouseButton.Left))
            OpenPluginDetails(plugin);

        var stateLabelWidth = Ui(62f);
        var switchWidth = Ui(44f);
        var removeWidth = Ui(78f);
        var gap = Ui(8f);
        var actionWidth = stateLabelWidth + gap + switchWidth + (collection.IsDefault ? 0f : gap + removeWidth);
        var actionsX = Math.Max(
            textStart + Ui(270f),
            MarketplaceLayoutRules.RightAlignedX(ImGui.GetWindowContentRegionMax().X, actionWidth));
        var toggleY = MarketplaceLayoutRules.CenterY(rowHeight, Ui(22f));

        ImGui.SetCursorPos(new Vector2(actionsX, toggleY + MarketplaceLayoutRules.CenterY(Ui(22f), ImGui.GetTextLineHeight())));
        ImGui.TextDisabled(entry.WantsEnabled ? "Enabled" : "Disabled");
        ImGui.SameLine(0f, gap);
        ImGui.SetCursorPosY(toggleY);
        var collectionControlsEnabled = collectionOperationTask is null;
        if (DrawToggleSwitch(
                $"collection-plugin-state-{collection.Id}-{StableId(entry.InternalName)}",
                entry.WantsEnabled,
                collectionControlsEnabled))
        {
            StartCollectionPluginStateChange(collection, entry, !entry.WantsEnabled);
        }
        if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
            ImGui.SetTooltip(collectionControlsEnabled
                ? (entry.WantsEnabled ? "Disable this plugin in this collection" : "Enable this plugin in this collection")
                : "Another Dalamud collection change is still being applied.");

        if (!collection.IsDefault)
        {
            ImGui.SameLine(0f, gap);
            ImGui.SetCursorPosY(MarketplaceLayoutRules.CenterY(rowHeight, Ui(30f)));
            if (DrawRoundedButton(
                    "Remove",
                    $"collection-plugin-remove-{collection.Id}-{StableId(entry.InternalName)}",
                    new Vector2(removeWidth, Ui(30f)),
                    enabled: collectionControlsEnabled))
            {
                StartRemovePluginFromCollection(collection, entry, plugin.Name);
            }
            if (!collectionControlsEnabled && ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
                ImGui.SetTooltip("Another Dalamud collection change is still being applied.");
        }

        ImGui.EndChild();
    }

    private void StartAddPluginToCollection(DalamudPluginCollection collection, string internalName, string displayName)
    {
        if (collectionOperationTask is not null)
        {
            operationMessage = "Dalamud is already changing a collection.";
            return;
        }
        if (collection.IsDefault)
        {
            operationMessage = "Default plugins is managed automatically by Dalamud.";
            return;
        }
        if (CollectionContainsPlugin(collection, internalName))
        {
            operationMessage = $"{displayName} is already in {CollectionDisplayName(collection)}.";
            return;
        }

        operationMessage = $"Adding {displayName} to {CollectionDisplayName(collection)}…";
        collectionOperationTask = Task.Run(() => profileBridge.AddPluginToCollectionAsync(collection.Id, internalName));
    }

    private void StartRemovePluginFromCollection(
        DalamudPluginCollection collection,
        DalamudCollectionPlugin entry,
        string displayName)
    {
        if (collectionOperationTask is not null)
        {
            operationMessage = "Dalamud is already changing a collection.";
            return;
        }
        if (collection.IsDefault)
        {
            operationMessage = "Default plugins is managed automatically by Dalamud.";
            return;
        }

        operationMessage = $"Removing {displayName} from {CollectionDisplayName(collection)}…";
        collectionOperationTask = Task.Run(() => profileBridge.RemovePluginFromCollectionAsync(collection.Id, entry.WorkingPluginId));
    }

    private void StartCollectionPluginStateChange(
        DalamudPluginCollection collection,
        DalamudCollectionPlugin entry,
        bool enabled)
    {
        if (collectionOperationTask is not null)
        {
            operationMessage = "Dalamud is already changing a collection.";
            return;
        }

        operationMessage = $"Setting {entry.InternalName} {(enabled ? "enabled" : "disabled")} in {CollectionDisplayName(collection)}…";
        collectionOperationTask = Task.Run(() => profileBridge.SetPluginStateInCollectionAsync(
            collection.Id,
            entry.WorkingPluginId,
            entry.InternalName,
            enabled));
    }

    private PluginDirectControlState GetPluginDirectControlState(string internalName)
    {
        RefreshCollectionsIfNeeded();
        var memberships = collectionSnapshot
            .SelectMany(collection => collection.Plugins
                .Where(entry => string.Equals(entry.InternalName, internalName, StringComparison.OrdinalIgnoreCase))
                .Select(entry => new PluginCollectionMembershipState(collection, entry)))
            .ToArray();

        var named = memberships.Where(x => !x.Collection.IsDefault).ToArray();
        if (named.Length > 0)
        {
            var names = string.Join(", ", named.Select(x => CollectionDisplayName(x.Collection)));
            return new(
                false,
                false,
                $"Managed by collection{(named.Length == 1 ? string.Empty : "s")}: {names}. Open Library > Collections to change its state.",
                null,
                memberships);
        }

        var direct = memberships.FirstOrDefault(x => x.Collection.IsDefault);
        if (direct is null || direct.Entry.WorkingPluginId == Guid.Empty)
        {
            return new(
                false,
                false,
                "Dalamud collection membership is not available for direct control yet.",
                null,
                memberships);
        }

        return new(
            true,
            direct.Entry.WantsEnabled,
            "Controlled through Dalamud's Default plugins collection.",
            direct,
            memberships);
    }

    private void StartDirectPluginStateChange(
        MarketplacePlugin plugin,
        PluginDirectControlState control,
        bool enabled)
    {
        if (!control.CanDirectToggle || control.DirectMembership is null)
        {
            operationMessage = control.Reason;
            return;
        }

        if (plugin.InternalName.Equals(Plugin.PluginInterface.InternalName, StringComparison.OrdinalIgnoreCase) && !enabled)
        {
            operationMessage = "Omega cannot disable itself from its own window. Use Dalamud to disable Omega.";
            return;
        }

        StartCollectionPluginStateChange(
            control.DirectMembership.Collection,
            control.DirectMembership.Entry,
            enabled);
    }

    private void OpenCollectionView(DalamudPluginCollection collection)
    {
        activeView = MarketplaceView.Library;
        librarySection = LibrarySection.Collections;
        openCollectionId = collection.Id;
        collectionAddPickerOpen = false;
        collectionAddSearch = string.Empty;
        detailsOpen = false;
        selectedPlugin = null;
        filtersOpen = false;
        resetStorefrontScroll = true;
        RefreshCollectionsIfNeeded(force: true);
    }

    private static bool CollectionContainsPlugin(DalamudPluginCollection collection, string internalName)
        => collection.Plugins.Any(x => string.Equals(x.InternalName, internalName, StringComparison.OrdinalIgnoreCase));

    private static string CollectionDisplayName(DalamudPluginCollection collection)
        => collection.IsDefault ? "Default plugins" : collection.Name;
}
