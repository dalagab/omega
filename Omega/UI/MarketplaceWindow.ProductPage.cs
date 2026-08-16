using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Plugin;

namespace Dalagab.Omega;

/// <summary>
/// Owns the full-width Microsoft Store-style product page used when a Discover result is selected.
/// Plugin lifecycle actions remain delegated to Dalamud and repository choice remains explicit at install time.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private const float ProductHeroIconSize = 132f;
    private const float ProductHeroMaxWidth = 820f;
    private const float ProductHeroHeight = 310f;
    private const float ProductScreenshotWidth = 360f;
    private const float ProductScreenshotHeight = 210f;
    private const int MaximumProductScreenshots = 5;

    private void DrawDiscoverProductPage(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (!detailsOpen || selectedPlugin is null)
            return;

        // The product page is anchored to the same preferred package shown in green below.
        // Metadata, dependency summaries and the security report therefore describe one baseline artifact.
        var plugin = ResolveProductBaselineVariant(selectedPlugin, currentApi, currentDalamudVersion);
        selectedPlugin = plugin;
        installed.TryGetValue(plugin.InternalName, out var installedPlugin);
        var content = MarketplacePresentationRules.Choose(plugin, catalog.GetPresentationVariants(plugin.InternalName));

        if (ShouldDrawOperationStatus())
        {
            ImGui.TextWrapped(operationMessage);
            ImGui.Spacing();
        }
        DrawProductHero(plugin, content, installedPlugin, currentApi, currentDalamudVersion);
        DrawProductCollectionMembership(plugin, installedPlugin);
        DrawProductScreenshots(content);
        DrawProductInformation(plugin, content, currentApi, currentDalamudVersion);
        DrawProductUsage(content);
        DrawProductChangelog(plugin);
        DrawProductReadme(content);
        DrawProductDependencies(plugin, installed);
        DrawProductSourcePackages(plugin, currentApi, currentDalamudVersion);
        DrawProductSecurity(plugin);
    }

    private void DrawProductHero(
        MarketplacePlugin plugin,
        MarketplacePresentationContent content,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, 10f);
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 1f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.045f, 0.052f, 0.064f, 0.74f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.17f, 0.19f, 0.22f, 0.44f));
        var heroWidth = Math.Min(ProductHeroMaxWidth, ImGui.GetContentRegionAvail().X);
        ImGui.BeginChild("discover-product-hero", new Vector2(heroWidth, ProductHeroHeight), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.SetCursorPos(new Vector2(22f, 24f));
        DrawPluginArtwork(
            plugin,
            installedPlugin,
            ProductHeroIconSize,
            ProductHeroIconSize,
            currentApi,
            currentDalamudVersion,
            showOverlays: false);

        ImGui.SameLine(0f, 24f);
        ImGui.BeginGroup();
        ImGui.SetCursorPosY(27f);
        ImGui.TextUnformatted(plugin.Name);
        DrawProductAuthors(plugin);

        var category = PrimaryPluginCategory(plugin);
        if (!string.IsNullOrWhiteSpace(category))
            ImGui.TextDisabled(category);

        ImGui.Spacing();
        DrawProductBadges(plugin, content);
        ImGui.Spacing();
        DrawProductSecuritySummary(plugin);
        ImGui.Spacing();

        var summary = content.Summary;
        if (!string.IsNullOrWhiteSpace(summary))
        {
            // The hero is a concise summary surface; the complete description lives in About below.
            summary = Shorten(summary.Trim(), 180);
            var available = Math.Max(280f, ImGui.GetContentRegionAvail().X - 24f);
            ImGui.PushTextWrapPos(ImGui.GetCursorPosX() + available);
            ImGui.TextWrapped(summary);
            ImGui.PopTextWrapPos();
        }

        ImGui.Spacing();
        DrawProductPrimaryAction(plugin, installedPlugin, currentApi, currentDalamudVersion);
        ImGui.EndGroup();

        ImGui.EndChild();
        ImGui.PopStyleColor(2);
        ImGui.PopStyleVar(2);
    }

    private readonly HashSet<string> expandedProductCollections = new(StringComparer.OrdinalIgnoreCase);

    private void DrawProductCollectionMembership(MarketplacePlugin plugin, IExposedPlugin? installedPlugin)
    {
        if (installedPlugin is null)
            return;

        RefreshCollectionsIfNeeded();
        var control = GetPluginDirectControlState(plugin.InternalName);
        // Dalamud's Default plugins profile is the direct-control baseline, not a user collection.
        // Product pages only call out named collection membership.
        var memberships = control.Memberships
            .Where(x => !x.Collection.IsDefault)
            .OrderBy(x => CollectionDisplayName(x.Collection), StringComparer.OrdinalIgnoreCase)
            .ToArray();

        ImGui.Dummy(new Vector2(1f, 9f));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, MarketplaceLayoutRules.ControlCornerRadius);
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 1f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.035f, 0.041f, 0.052f, 0.70f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.17f, 0.19f, 0.22f, 0.38f));
        // State/collection ownership is core product information; use the full available content width.
        var panelWidth = Math.Max(320f, ImGui.GetContentRegionAvail().X);
        var panelHeight = ProductCollectionPanelHeight(plugin.InternalName, control, memberships);
        ImGui.BeginChild(
            "discover-product-state-collections",
            new Vector2(panelWidth, panelHeight),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.TextUnformatted("Plugin state");
        ImGui.SameLine(0f, 12f);
        ImGui.TextDisabled(installedPlugin.IsLoaded ? "Running" : "Not running");
        ImGui.SameLine(0f, 12f);

        // Keep the state switch visible in every case. Named collections own state and therefore
        // disable direct control rather than replacing the switch with ambiguous explanatory text.
        var shownState = control.CanDirectToggle ? control.DesiredEnabled : installedPlugin.IsLoaded;
        var isSelf = plugin.InternalName.Equals(Plugin.PluginInterface.InternalName, StringComparison.OrdinalIgnoreCase);
        var canToggleHere = control.CanDirectToggle && !(isSelf && control.DesiredEnabled);
        if (DrawToggleSwitch(
                $"product-plugin-state-{StableId(plugin.InternalName)}",
                shownState,
                canToggleHere))
        {
            StartDirectPluginStateChange(plugin, control, !control.DesiredEnabled);
        }
        if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
        {
            ImGui.SetTooltip(!canToggleHere && isSelf && control.CanDirectToggle
                ? "Omega cannot disable itself from its own window. Use Dalamud to disable Omega."
                : control.CanDirectToggle
                    ? $"{(control.DesiredEnabled ? "Disable" : "Enable")} {plugin.Name}"
                    : control.Reason);
        }

        ImGui.Dummy(new Vector2(1f, 12f));
        ImGui.TextUnformatted("Collections");
        ImGui.Dummy(new Vector2(1f, 6f));

        if (memberships.Length == 0)
        {
            ImGui.TextDisabled("Not in a named collection");
        }
        else
        {
            foreach (var membership in memberships)
                DrawProductCollectionRow(plugin.InternalName, membership);
        }

        ImGui.EndChild();
        ImGui.PopStyleColor(2);
        ImGui.PopStyleVar(2);
    }

    private float ProductCollectionPanelHeight(
        string productInternalName,
        PluginDirectControlState control,
        IReadOnlyList<PluginCollectionMembershipState> memberships)
    {
        const float baseHeight = 130f;
        var height = baseHeight + memberships.Count * MarketplaceLayoutRules.ProductCollectionRowHeight;
        foreach (var membership in memberships)
        {
            if (!expandedProductCollections.Contains(ProductCollectionExpansionKey(productInternalName, membership.Collection.Id)))
                continue;

            var affectedCount = membership.Collection.Plugins.Count;
            height += 8f + Math.Max(1, affectedCount) * MarketplaceLayoutRules.ProductCollectionImpactLineHeight;
        }

        return Math.Max(160f, height);
    }

    private void DrawProductCollectionRow(
        string productInternalName,
        PluginCollectionMembershipState membership)
    {
        var collection = membership.Collection;
        var rowHeight = MarketplaceLayoutRules.ProductCollectionRowHeight;
        var start = ImGui.GetCursorScreenPos();
        var width = ImGui.GetContentRegionAvail().X;
        var expandedKey = ProductCollectionExpansionKey(productInternalName, collection.Id);
        var expanded = expandedProductCollections.Contains(expandedKey);

        var draw = ImGui.GetWindowDrawList();
        var rowMax = start + new Vector2(width, rowHeight - 2f);
        draw.AddRectFilled(start, rowMax, ImGui.ColorConvertFloat4ToU32(new Vector4(0.055f, 0.064f, 0.078f, 0.62f)), MarketplaceLayoutRules.ControlCornerRadius);
        draw.AddRect(start, rowMax, ImGui.ColorConvertFloat4ToU32(new Vector4(0.16f, 0.19f, 0.23f, 0.46f)), MarketplaceLayoutRules.ControlCornerRadius, ImDrawFlags.None, 1f);

        var rowCursor = ImGui.GetCursorPos();
        ImGui.SetCursorPos(new Vector2(rowCursor.X + 8f, rowCursor.Y + MarketplaceLayoutRules.CenterY(rowHeight, ImGui.GetTextLineHeight())));
        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        ImGui.TextUnformatted((expanded ? FontAwesomeIcon.CaretDown : FontAwesomeIcon.CaretRight).ToIconString());
        ImGui.PopFont();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(expanded ? "Hide affected plugins" : "Show affected plugins");
        if (ImGui.IsItemClicked())
        {
            if (expanded)
                expandedProductCollections.Remove(expandedKey);
            else
                expandedProductCollections.Add(expandedKey);
            expanded = !expanded;
        }

        ImGui.SetCursorPos(new Vector2(rowCursor.X + 34f, rowCursor.Y + MarketplaceLayoutRules.CenterY(rowHeight, ImGui.GetTextLineHeight())));
        var label = CollectionDisplayName(collection);
        ImGui.TextUnformatted(label);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip($"Open {label}");
        if (ImGui.IsItemClicked())
        {
            OpenCollectionView(collection);
            return;
        }

        if (collection.IsDefault)
        {
            const string alwaysOn = "Always on";
            var textWidth = ImGui.CalcTextSize(alwaysOn).X;
            ImGui.SetCursorPos(new Vector2(
                rowCursor.X + Math.Max(34f, width - textWidth - 10f),
                rowCursor.Y + MarketplaceLayoutRules.CenterY(rowHeight, ImGui.GetTextLineHeight())));
            ImGui.TextDisabled(alwaysOn);
        }
        else
        {
            const float switchWidth = 44f;
            ImGui.SetCursorPos(new Vector2(
                rowCursor.X + Math.Max(34f, width - switchWidth - 10f),
                rowCursor.Y + MarketplaceLayoutRules.CenterY(rowHeight, 22f)));
            if (DrawToggleSwitch($"product-collection-state-{collection.Id}", collection.IsEnabled))
                StartCollectionToggle(collection, !collection.IsEnabled);
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(collection.IsEnabled ? $"Disable {label}" : $"Enable {label}");
        }

        ImGui.SetCursorPos(new Vector2(rowCursor.X, rowCursor.Y + rowHeight));
        if (!expanded)
            return;

        var affected = collection.Plugins
            .OrderBy(x => ProductCollectionPluginName(x), StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (affected.Length == 0)
        {
            ImGui.Indent(34f);
            ImGui.TextDisabled("No plugins in this collection.");
            ImGui.Unindent(34f);
            ImGui.Dummy(new Vector2(1f, 4f));
            return;
        }

        ImGui.Indent(34f);
        foreach (var entry in affected)
        {
            var name = ProductCollectionPluginName(entry);
            var current = string.Equals(entry.InternalName, productInternalName, StringComparison.OrdinalIgnoreCase);
            ImGui.TextDisabled(current ? $"• {name}  (this plugin)" : $"• {name}");
            if (ImGui.IsItemHovered() && !string.Equals(name, entry.InternalName, StringComparison.OrdinalIgnoreCase))
                ImGui.SetTooltip(entry.InternalName);
        }
        ImGui.Unindent(34f);
        ImGui.Dummy(new Vector2(1f, 4f));
    }

    private string ProductCollectionPluginName(DalamudCollectionPlugin entry)
    {
        var variant = catalog.GetPresentationVariants(entry.InternalName).FirstOrDefault()
                      ?? catalog.GetVariants(entry.InternalName).FirstOrDefault();
        return string.IsNullOrWhiteSpace(variant?.Name) ? entry.InternalName : variant.Name;
    }

    private static string ProductCollectionExpansionKey(string productInternalName, Guid collectionId)
        => $"{productInternalName}\u001f{collectionId:D}";

    private void DrawProductBadges(MarketplacePlugin plugin, MarketplacePresentationContent content)
    {
        var drewAny = false;
        if (catalog.GetVariants(plugin.InternalName).Any(x => x.SourceIsOfficial) || plugin.SourceIsOfficial)
        {
            DrawDalamudOfficialLogoBadge(28f);
            drewAny = true;
        }

        if (content.IsEnhanced)
        {
            if (drewAny)
                ImGui.SameLine(0f, 8f);

            var enhancedUrl = ResolveEnhancedProjectUrl(plugin, content);
            if (!string.IsNullOrWhiteSpace(enhancedUrl))
            {
                DrawProductWebsiteIcon(plugin, enhancedUrl);
                ImGui.SameLine(0f, 5f);
            }

            DrawDiscoverTextBadge("★ Enhanced", new Vector4(0.45f, 0.34f, 0.08f, 0.96f));
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("Omega has richer presentation information for this plugin.");
            drewAny = true;
        }

        if (IsNsfwPlugin(plugin))
        {
            if (drewAny)
                ImGui.SameLine(0f, 8f);
            DrawDiscoverTextBadge("18+", new Vector4(0.56f, 0.16f, 0.22f, 0.96f));
        }
    }

    private void DrawProductPrimaryAction(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (installedPlugin is not null)
        {
            var offeredUpdate = GetAvailableUpdateVersion(
                plugin.InternalName, installedPlugin, currentApi, currentDalamudVersion);
            if (offeredUpdate is not null)
            {
                if (DrawProductActionButton("Update", $"product-update-{plugin.InternalName}", enabled: true, accent: true))
                    Plugin.PluginInterface.OpenPluginInstallerTo(PluginInstallerOpenKind.UpdateablePlugins, plugin.Name);
                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip($"Update to v{offeredUpdate} through Dalamud");
            }
            else if (installedPlugin.HasMainUi && installedPlugin.IsLoaded)
            {
                if (DrawProductActionButton("Open", $"product-open-{plugin.InternalName}", enabled: true, accent: true))
                {
                    try
                    {
                        installedPlugin.OpenMainUi();
                    }
                    catch (Exception ex)
                    {
                        Plugin.Log.Debug(ex, "Omega could not open the main UI for {Plugin}", plugin.InternalName);
                        operationMessage = $"{plugin.Name} did not expose an openable main UI.";
                    }
                }
            }
            else
            {
                DrawProductActionButton("Installed", $"product-installed-{plugin.InternalName}", enabled: false, accent: false);
            }

            ImGui.SameLine(0f, 10f);
            var isSelf = plugin.InternalName.Equals(Plugin.PluginInterface.InternalName, StringComparison.OrdinalIgnoreCase);
            if (uninstallTask is not null && uninstallingInternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase))
            {
                DrawProductUninstallButton("Uninstalling…", $"product-uninstalling-{plugin.InternalName}", enabled: false);
            }
            else if (isSelf)
            {
                DrawProductUninstallButton("Uninstall", $"product-uninstall-self-{plugin.InternalName}", enabled: false);
                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip("Omega cannot uninstall itself while it is running. Use Dalamud to remove Omega.");
            }
            else if (DrawProductUninstallButton("Uninstall", $"product-uninstall-{plugin.InternalName}", enabled: uninstallTask is null))
            {
                OpenUninstallConfirmation(plugin);
            }
            return;
        }

        var candidates = GetInstallCandidates(plugin.InternalName, currentApi, currentDalamudVersion);
        if (candidates.Count == 0)
        {
            DrawProductActionButton("Unavailable", $"product-unavailable-{plugin.InternalName}", enabled: false, accent: false);
            ImGui.SameLine(0f, 10f);
            ImGui.TextDisabled($"No compatible API {currentApi} package is available.");
            return;
        }

        if (installTask is not null && installingInternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase))
        {
            DrawProductActionButton("Installing…", $"product-installing-{plugin.InternalName}", enabled: false, accent: false);
            return;
        }

        if (DrawProductActionButton("Install", $"product-install-{plugin.InternalName}", enabled: true, accent: true))
            OpenInstallChooser(plugin);
    }

    private static bool DrawProductActionButton(string label, string id, bool enabled, bool accent)
    {
        var size = new Vector2(196f, 44f);
        if (!enabled)
            ImGui.BeginDisabled();

        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 6f);
        if (accent)
        {
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.02f, 0.40f, 0.42f, 0.96f));
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.03f, 0.50f, 0.51f, 1f));
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, new Vector4(0.02f, 0.34f, 0.36f, 1f));
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.16f, 0.17f, 0.19f, 0.90f));
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.16f, 0.17f, 0.19f, 0.90f));
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, new Vector4(0.16f, 0.17f, 0.19f, 0.90f));
        }

        var clicked = ImGui.Button($"{label}##{id}", size);
        ImGui.PopStyleColor(3);
        ImGui.PopStyleVar();
        if (!enabled)
            ImGui.EndDisabled();
        return clicked && enabled;
    }


    private static bool DrawProductUninstallButton(string label, string id, bool enabled)
    {
        var size = new Vector2(156f, 44f);
        if (!enabled)
            ImGui.BeginDisabled();

        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 6f);
        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.40f, 0.08f, 0.10f, 0.94f));
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.56f, 0.10f, 0.13f, 1f));
        ImGui.PushStyleColor(ImGuiCol.ButtonActive, new Vector4(0.34f, 0.06f, 0.08f, 1f));
        var clicked = ImGui.Button($"{label}##{id}", size);
        ImGui.PopStyleColor(3);
        ImGui.PopStyleVar();

        if (!enabled)
            ImGui.EndDisabled();
        return clicked && enabled;
    }

    private void DrawProductScreenshots(MarketplacePresentationContent content)
    {
        var screenshots = content.Images.Take(MaximumProductScreenshots).ToArray();
        if (screenshots.Length == 0)
            return;

        ImGui.Spacing();
        ImGui.TextUnformatted("Project images");
        ImGui.Spacing();
        var style = ImGui.GetStyle();
        var stripHeight = ProductScreenshotHeight + (style.WindowPadding.Y * 2f) + style.ScrollbarSize + 4f;
        ImGui.BeginChild("discover-product-screenshots", new Vector2(0f, stripHeight), true,
            ImGuiWindowFlags.HorizontalScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        for (var index = 0; index < screenshots.Length; index++)
        {
            DrawProductScreenshot(screenshots[index], index);
            if (index + 1 < screenshots.Length)
                ImGui.SameLine(0f, 12f);
        }

        ImGui.EndChild();
    }

    private void DrawProductScreenshot(string url, int index)
    {
        var texture = iconCache.GetOrQueue(url);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.025f, 0.030f, 0.038f, 0.88f));
        ImGui.BeginChild($"product-screenshot-{index}-{StableId(url)}",
            new Vector2(ProductScreenshotWidth, ProductScreenshotHeight),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        if (texture is null || texture.Size.X <= 0 || texture.Size.Y <= 0)
        {
            var min = ImGui.GetCursorScreenPos();
            var avail = ImGui.GetContentRegionAvail();
            ImGui.Dummy(avail);
            var text = "Loading image…";
            var textSize = ImGui.CalcTextSize(text);
            ImGui.GetWindowDrawList().AddText(
                min + new Vector2((avail.X - textSize.X) * 0.5f, (avail.Y - textSize.Y) * 0.5f),
                ImGui.GetColorU32(ImGuiCol.TextDisabled),
                text);
        }
        else
        {
            var contentSize = ImGui.GetWindowContentRegionMax() - ImGui.GetWindowContentRegionMin();
            var scale = Math.Min(contentSize.X / texture.Size.X, contentSize.Y / texture.Size.Y);
            var size = texture.Size * scale;
            SetCursorCenteredInCurrentContent(size);
            ImGui.Image(texture.Handle, size);
        }

        var screenshotHovered = ImGui.IsWindowHovered();
        var screenshotClicked = screenshotHovered && ImGui.IsMouseClicked(ImGuiMouseButton.Left);
        if (screenshotHovered)
            ImGui.SetTooltip("View larger image");

        ImGui.EndChild();
        ImGui.PopStyleColor();

        if (screenshotClicked)
            OpenScreenshotViewer(url);
    }

    private void DrawProductInformation(
        MarketplacePlugin plugin,
        MarketplacePresentationContent content,
        int currentApi,
        Version currentDalamudVersion)
    {
        DrawProductSectionHeading("About this plugin");

        ImGui.Indent(14f);
        var description = CleanProductDescriptionForDisplay(content.Description, content.Summary);
        if (!string.IsNullOrWhiteSpace(description))
        {
            ImGui.PushTextWrapPos(ImGui.GetCursorPosX() + Math.Max(320f, Math.Min(940f, ImGui.GetContentRegionAvail().X)));
            ImGui.TextWrapped(description);
            ImGui.PopTextWrapPos();
            ImGui.Dummy(new Vector2(1f, 8f));
        }

        ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(8f, 6f));
        if (ImGui.BeginTable(
                "product-about-metadata",
                2,
                ImGuiTableFlags.SizingFixedFit | ImGuiTableFlags.BordersInnerH | ImGuiTableFlags.RowBg))
        {
            ImGui.TableSetupColumn("Field", ImGuiTableColumnFlags.WidthFixed, 110f);
            ImGui.TableSetupColumn("Value", ImGuiTableColumnFlags.WidthStretch);
            DrawProductMetadataRow("Version", plugin.AssemblyVersionText);
            DrawProductMetadataRow(
                "Compatibility",
                plugin.GetCompatibilityText(currentApi, currentDalamudVersion, configuration.PreferTestingBuilds));
            DrawProductRepositoryMetadataRow(plugin, currentApi);
            if (plugin.Tags.Count > 0)
                DrawProductMetadataRow("Tags", string.Join(", ", plugin.Tags));
            ImGui.EndTable();
        }
        ImGui.PopStyleVar();
        ImGui.Unindent(14f);
    }

    private static string CleanProductDescriptionForDisplay(string description, string summary)
    {
        var candidate = (description ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(candidate) || candidate.Equals(summary, StringComparison.Ordinal))
            return string.Empty;

        // Aggregated community manifests often append a provenance line such as
        // "Plugin from https://...". Source identity is already shown as metadata below,
        // so omit that transport detail from the human-readable About copy only.
        var lines = candidate.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n')
            .Select(line => line.TrimEnd())
            .Where(line => !line.TrimStart().StartsWith("Plugin from http://", StringComparison.OrdinalIgnoreCase) &&
                           !line.TrimStart().StartsWith("Plugin from https://", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        return string.Join("\n", lines).Trim();
    }

    private static void DrawProductMetadataRow(string label, string value)
    {
        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        ImGui.TextDisabled(label);
        ImGui.TableSetColumnIndex(1);
        ImGui.TextWrapped(string.IsNullOrWhiteSpace(value) ? "—" : value);
    }

    private static void DrawProductSectionHeading(string title)
    {
        ImGui.Dummy(new Vector2(1f, 14f));
        var x = ImGui.GetCursorPosX();
        var markerMin = ImGui.GetCursorScreenPos();
        var markerMax = markerMin + new Vector2(3f, 22f);
        ImGui.GetWindowDrawList().AddRectFilled(
            markerMin,
            markerMax,
            ImGui.ColorConvertFloat4ToU32(new Vector4(0.08f, 0.58f, 0.59f, 0.92f)),
            2f);

        ImGui.SetCursorPosX(x + 12f);
        ImGui.TextUnformatted(title);
        ImGui.SetCursorPosX(x);
        ImGui.Dummy(new Vector2(1f, 8f));
    }

    private static bool IsNsfwPlugin(MarketplacePlugin plugin)
        => plugin.OmegaIsAdultContent || plugin.Tags.Concat(plugin.EffectiveCategories).Any(IsContentRatingTag);

    private static bool IsContentRatingTag(string value)
    {
        var tag = (value ?? string.Empty).Trim().ToLowerInvariant();
        return tag is "nsfw" or "adult" or "18+" or "18plus" or "explicit" or "sexual-content" or "mature";
    }
}
