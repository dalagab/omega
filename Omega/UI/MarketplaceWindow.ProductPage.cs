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
        var sourcePackages = BuildProductSourcePackages(plugin, currentApi, currentDalamudVersion);

        if (ShouldDrawOperationStatus())
        {
            ImGui.TextWrapped(operationMessage);
            ImGui.Spacing();
        }
        DrawProductPackageBaselineWarning(plugin, sourcePackages, currentApi, currentDalamudVersion);
        DrawProductHero(plugin, content, installedPlugin, currentApi, currentDalamudVersion);
        DrawProductUpdateFailure(plugin, installedPlugin, currentApi, currentDalamudVersion);
        DrawProductProjectLinks(plugin);
        DrawProductCollectionMembership(plugin, installedPlugin);
        DrawProductScreenshots(content);
        DrawProductInformation(plugin, content, currentApi, currentDalamudVersion);
        DrawProductUsage(content);
        DrawProductChangelog(plugin);
        DrawProductReadme(content);
        DrawProductDependencies(plugin, installed);
        DrawProductSourcePackages(plugin, sourcePackages, currentApi, currentDalamudVersion);
        DrawProductSigmascope(plugin);
    }

    private void DrawProductHero(
        MarketplacePlugin plugin,
        MarketplacePresentationContent content,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        var heroWidth = Math.Max(Ui(1f), ImGui.GetContentRegionAvail().X);
        var heroHeight = Ui(ProductHeroHeight);

        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, Ui(10f));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 0f);
        // The banner itself should own the top product surface. Keep the child nearly transparent
        // and paint the repository artwork as the hero background instead of as an inset panel.
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0f, 0f, 0f, 0.03f));
        ImGui.BeginChild("discover-product-hero", new Vector2(heroWidth, heroHeight), false,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        DrawProductHeroBanner(plugin, heroWidth, heroHeight);

        ImGui.SetCursorPos(Ui(22f, 24f));
        DrawPluginArtwork(
            plugin,
            installedPlugin,
            Ui(ProductHeroIconSize),
            Ui(ProductHeroIconSize),
            currentApi,
            currentDalamudVersion,
            showOverlays: false);

        ImGui.SameLine(0f, Ui(24f));
        ImGui.BeginGroup();
        ImGui.SetCursorPosY(Ui(27f));
        ImGui.TextUnformatted(plugin.Name);
        DrawProductAuthors(plugin);

        var category = PrimaryPluginCategory(plugin);
        if (!string.IsNullOrWhiteSpace(category))
            ImGui.TextDisabled(category);

        ImGui.Spacing();
        DrawProductBadges(plugin, content);
        ImGui.Spacing();
        DrawProductSigmascopeSummary(plugin);
        ImGui.Spacing();

        var summary = MarketplaceReadmeMarkup.ToInlineText(content.Summary);
        if (!string.IsNullOrWhiteSpace(summary))
        {
            // The hero is a concise summary surface; the complete description lives in About below.
            summary = Shorten(summary.Trim(), 180);
            var available = Math.Max(Ui(240f), ImGui.GetContentRegionAvail().X - Ui(28f));
            ImGui.PushTextWrapPos(ImGui.GetCursorPosX() + available);
            ImGui.TextWrapped(summary);
            ImGui.PopTextWrapPos();
        }

        ImGui.Spacing();
        DrawProductPrimaryAction(plugin, installedPlugin, currentApi, currentDalamudVersion);
        ImGui.EndGroup();

        ImGui.EndChild();
        ImGui.PopStyleColor();
        ImGui.PopStyleVar(2);
    }

    private void DrawProductHeroBanner(MarketplacePlugin plugin, float heroWidth, float heroHeight)
    {
        var draw = ImGui.GetWindowDrawList();
        var heroMin = ImGui.GetWindowPos();
        var heroMax = heroMin + new Vector2(heroWidth, heroHeight);
        var rounding = Ui(10f);
        var clipMax = heroMax;

        draw.AddRectFilled(heroMin, heroMax, ImGui.GetColorU32(new Vector4(0.05f, 0.06f, 0.08f, 0.98f)), rounding);

        if (!string.IsNullOrWhiteSpace(plugin.OmegaBannerUrl))
        {
            var texture = iconCache.GetOrQueue(plugin.OmegaBannerUrl);
            if (texture is not null)
            {
                // .omega banners are wide artwork. Fill the whole top product area and crop to cover
                // so the banner reads as the page background rather than as a separate inset card.
                const float recommendedAspect = 16f / 9f;
                var imageHeight = Math.Max(heroHeight, heroWidth / recommendedAspect);
                var imageMin = new Vector2(heroMin.X, heroMin.Y - Math.Max(0f, (imageHeight - heroHeight) * 0.5f));
                var imageMax = imageMin + new Vector2(heroWidth, imageHeight);
                draw.PushClipRect(heroMin, clipMax, true);
                draw.AddImage(
                    texture.Handle,
                    imageMin,
                    imageMax,
                    Vector2.Zero,
                    Vector2.One,
                    ImGui.GetColorU32(new Vector4(1f, 1f, 1f, 0.94f)));
                draw.PopClipRect();
            }
        }

        // Darken the left and lower areas so text and actions remain readable on bright banners.
        draw.AddRectFilledMultiColor(
            heroMin,
            heroMax,
            ImGui.GetColorU32(new Vector4(0.01f, 0.02f, 0.03f, 0.80f)),
            ImGui.GetColorU32(new Vector4(0.01f, 0.02f, 0.03f, 0.18f)),
            ImGui.GetColorU32(new Vector4(0.01f, 0.02f, 0.03f, 0.42f)),
            ImGui.GetColorU32(new Vector4(0.01f, 0.02f, 0.03f, 0.72f)));
        draw.AddRectFilledMultiColor(
            heroMin,
            heroMax,
            ImGui.GetColorU32(new Vector4(0f, 0f, 0f, 0f)),
            ImGui.GetColorU32(new Vector4(0f, 0f, 0f, 0f)),
            ImGui.GetColorU32(new Vector4(0f, 0f, 0f, 0.62f)),
            ImGui.GetColorU32(new Vector4(0f, 0f, 0f, 0.62f)));
        draw.AddRect(heroMin, heroMax, ImGui.GetColorU32(new Vector4(0.17f, 0.19f, 0.22f, 0.36f)), rounding, ImDrawFlags.None, 1f);
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

        ImGui.Dummy(Ui(1f, 9f));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, Ui(MarketplaceLayoutRules.ControlCornerRadius));
        ImGui.PushStyleVar(ImGuiStyleVar.ChildBorderSize, 1f);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.035f, 0.041f, 0.052f, 0.70f));
        ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0.17f, 0.19f, 0.22f, 0.38f));
        // State/collection ownership is core product information; use the full available content width.
        var panelWidth = Math.Max(Ui(1f), ImGui.GetContentRegionAvail().X);
        var panelHeight = ProductCollectionPanelHeight(plugin.InternalName, control, memberships);
        ImGui.BeginChild(
            "discover-product-state-collections",
            new Vector2(panelWidth, panelHeight),
            true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.TextUnformatted("Plugin state");
        ImGui.SameLine(0f, Ui(12f));
        ImGui.TextDisabled(installedPlugin.IsLoaded ? "Running" : "Not running");
        ImGui.SameLine(0f, Ui(12f));

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

        if (memberships.Length > 0)
        {
            ImGui.Dummy(Ui(1f, 12f));
            ImGui.TextUnformatted("Collections");
            ImGui.Dummy(Ui(1f, 6f));

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
        // A plugin with no named memberships only needs the compact state row.
        // Do not reserve vertical space for an empty Collections subsection.
        if (memberships.Count == 0)
            return Ui(68f);

        var baseHeight = Ui(130f);
        var height = baseHeight + memberships.Count * Ui(MarketplaceLayoutRules.ProductCollectionRowHeight);
        foreach (var membership in memberships)
        {
            if (!expandedProductCollections.Contains(ProductCollectionExpansionKey(productInternalName, membership.Collection.Id)))
                continue;

            var affectedCount = membership.Collection.Plugins.Count;
            height += Ui(8f) + Math.Max(1, affectedCount) * Ui(MarketplaceLayoutRules.ProductCollectionImpactLineHeight);
        }

        return Math.Max(Ui(160f), height);
    }

    private void DrawProductCollectionRow(
        string productInternalName,
        PluginCollectionMembershipState membership)
    {
        var collection = membership.Collection;
        var rowHeight = Ui(MarketplaceLayoutRules.ProductCollectionRowHeight);
        var start = ImGui.GetCursorScreenPos();
        var width = ImGui.GetContentRegionAvail().X;
        var expandedKey = ProductCollectionExpansionKey(productInternalName, collection.Id);
        var expanded = expandedProductCollections.Contains(expandedKey);

        var draw = ImGui.GetWindowDrawList();
        var rowMax = start + new Vector2(width, rowHeight - Ui(2f));
        draw.AddRectFilled(start, rowMax, ImGui.ColorConvertFloat4ToU32(new Vector4(0.055f, 0.064f, 0.078f, 0.62f)), Ui(MarketplaceLayoutRules.ControlCornerRadius));
        draw.AddRect(start, rowMax, ImGui.ColorConvertFloat4ToU32(new Vector4(0.16f, 0.19f, 0.23f, 0.46f)), Ui(MarketplaceLayoutRules.ControlCornerRadius), ImDrawFlags.None, Ui(1f));

        var rowCursor = ImGui.GetCursorPos();
        ImGui.SetCursorPos(new Vector2(rowCursor.X + Ui(8f), rowCursor.Y + MarketplaceLayoutRules.CenterY(rowHeight, ImGui.GetTextLineHeight())));
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

        ImGui.SetCursorPos(new Vector2(rowCursor.X + Ui(34f), rowCursor.Y + MarketplaceLayoutRules.CenterY(rowHeight, ImGui.GetTextLineHeight())));
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
                rowCursor.X + Math.Max(Ui(34f), width - textWidth - Ui(10f)),
                rowCursor.Y + MarketplaceLayoutRules.CenterY(rowHeight, ImGui.GetTextLineHeight())));
            ImGui.TextDisabled(alwaysOn);
        }
        else
        {
            var switchWidth = Ui(44f);
            ImGui.SetCursorPos(new Vector2(
                rowCursor.X + Math.Max(Ui(34f), width - switchWidth - Ui(10f)),
                rowCursor.Y + MarketplaceLayoutRules.CenterY(rowHeight, Ui(22f))));
            var collectionControlsEnabled = collectionOperationTask is null;
            if (DrawToggleSwitch($"product-collection-state-{collection.Id}", collection.IsEnabled, collectionControlsEnabled))
                StartCollectionToggle(collection, !collection.IsEnabled);
            if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
                ImGui.SetTooltip(collectionControlsEnabled
                    ? (collection.IsEnabled ? $"Disable {label}" : $"Enable {label}")
                    : "Another Dalamud collection change is still being applied.");
        }

        ImGui.SetCursorPos(new Vector2(rowCursor.X, rowCursor.Y + rowHeight));
        if (!expanded)
            return;

        var affected = collection.Plugins
            .OrderBy(x => ProductCollectionPluginName(x), StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (affected.Length == 0)
        {
            ImGui.Indent(Ui(34f));
            ImGui.TextDisabled("No plugins in this collection.");
            ImGui.Unindent(Ui(34f));
            ImGui.Dummy(Ui(1f, 4f));
            return;
        }

        ImGui.Indent(Ui(34f));
        foreach (var entry in affected)
        {
            var name = ProductCollectionPluginName(entry);
            var current = string.Equals(entry.InternalName, productInternalName, StringComparison.OrdinalIgnoreCase);
            ImGui.TextDisabled(current ? $"• {name}  (this plugin)" : $"• {name}");
            if (ImGui.IsItemHovered() && !string.Equals(name, entry.InternalName, StringComparison.OrdinalIgnoreCase))
                ImGui.SetTooltip(entry.InternalName);
        }
        ImGui.Unindent(Ui(34f));
        ImGui.Dummy(Ui(1f, 4f));
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
            DrawDalamudOfficialLogoBadge(Ui(28f));
            drewAny = true;
        }

        if (content.IsEnhanced)
        {
            if (drewAny)
                ImGui.SameLine(0f, Ui(8f));

            DrawDiscoverTextBadge("★ Enhanced", new Vector4(0.45f, 0.34f, 0.08f, 0.96f));
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("Omega has richer presentation information for this plugin.");
            drewAny = true;
        }

        if (IsNsfwPlugin(plugin))
        {
            if (drewAny)
                ImGui.SameLine(0f, Ui(8f));
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
            var updateCandidate = GetAvailableUpdateCandidate(
                plugin.InternalName, installedPlugin, currentApi, currentDalamudVersion);
            var offeredUpdate = GetAvailableUpdateVersion(
                plugin.InternalName, installedPlugin, currentApi, currentDalamudVersion);
            if (offeredUpdate is not null && updateCandidate is not null)
            {
                var migration = IsRepositoryMigration(installedPlugin, updateCandidate);
                var updateBusy = updateTask is not null;
                var hasPreviousFailure = updateFailures.ContainsKey(plugin.InternalName);
                var label = updatingInternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase)
                    ? "Updating…"
                    : migration ? "Migrate & update" : hasPreviousFailure ? "Retry update" : "Update";
                if (DrawProductActionButton(label, $"product-update-{plugin.InternalName}", enabled: !updateBusy, accent: true))
                    OpenUpdateOrMigration(plugin, installedPlugin, currentApi, currentDalamudVersion);
                if (ImGui.IsItemHovered(ImGuiHoveredFlags.AllowWhenDisabled))
                {
                    ImGui.SetTooltip(migration
                        ? $"Move from the installed repository to {updateCandidate.SourceName} and update to v{offeredUpdate}"
                        : $"Update to v{offeredUpdate} through Dalamud");
                }
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

            ImGui.SameLine(0f, Ui(10f));
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
            ImGui.SameLine(0f, Ui(10f));
            ImGui.TextDisabled(DescribeInstallUnavailability(plugin.InternalName, currentApi, currentDalamudVersion));
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
        var size = Ui(196f, 44f);
        if (!enabled)
            ImGui.BeginDisabled();

        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, Ui(6f));
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
        var size = Ui(156f, 44f);
        if (!enabled)
            ImGui.BeginDisabled();

        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, Ui(6f));
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
        var stripHeight = Ui(ProductScreenshotHeight) + (style.WindowPadding.Y * 2f) + style.ScrollbarSize + Ui(4f);
        ImGui.BeginChild("discover-product-screenshots", new Vector2(0f, stripHeight), true,
            ImGuiWindowFlags.HorizontalScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        for (var index = 0; index < screenshots.Length; index++)
        {
            DrawProductScreenshot(screenshots[index], index);
            if (index + 1 < screenshots.Length)
                ImGui.SameLine(0f, Ui(12f));
        }

        ImGui.EndChild();
    }

    private void DrawProductScreenshot(string url, int index)
    {
        var texture = iconCache.GetOrQueue(url);
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.025f, 0.030f, 0.038f, 0.88f));
        ImGui.BeginChild($"product-screenshot-{index}-{StableId(url)}",
            Ui(ProductScreenshotWidth, ProductScreenshotHeight),
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

        ImGui.Indent(Ui(14f));
        var description = CleanProductDescriptionForDisplay(content.Description, content.Summary);
        if (!string.IsNullOrWhiteSpace(description))
        {
            DrawMarketplaceMarkupText(description, "description", maximumBlocks: 100);
            ImGui.Dummy(Ui(1f, 8f));
        }

        ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, Ui(8f, 6f));
        if (ImGui.BeginTable(
                "product-about-metadata",
                2,
                ImGuiTableFlags.SizingFixedFit | ImGuiTableFlags.BordersInnerH | ImGuiTableFlags.RowBg))
        {
            ImGui.TableSetupColumn("Field", ImGuiTableColumnFlags.WidthFixed, Ui(110f));
            ImGui.TableSetupColumn("Value", ImGuiTableColumnFlags.WidthStretch);
            DrawProductMetadataRow("Version", plugin.AssemblyVersionText);
            DrawProductMetadataRow("Downloads / installations", plugin.DownloadCount > 0 ? plugin.DownloadCount.ToString("N0") : "—");
            DrawProductPopularityMetadataRow(plugin, currentApi);
            DrawProductMetadataRow(
                "Compatibility",
                plugin.GetCompatibilityText(currentApi, currentDalamudVersion, configuration.PreferTestingBuilds));
            DrawProductRepositoryMetadataRow(plugin, currentApi);
            if (plugin.Tags.Count > 0)
                DrawProductMetadataRow("Tags", string.Join(", ", plugin.Tags));
            ImGui.EndTable();
        }
        ImGui.PopStyleVar();
        ImGui.Unindent(Ui(14f));
    }

    private static string CleanProductDescriptionForDisplay(string description, string summary)
    {
        var candidate = MarketplaceReadmeMarkup.NormalizeHtml(description ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(candidate) ||
            MarketplaceReadmeMarkup.ToInlineText(candidate).Equals(MarketplaceReadmeMarkup.ToInlineText(summary), StringComparison.Ordinal))
            return string.Empty;

        // Aggregated community manifests can append a source transport line. The repository is
        // already shown in metadata, so omit that duplicate line from the visible description.
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
        ImGui.Dummy(Ui(1f, 14f));
        var x = ImGui.GetCursorPosX();
        var markerMin = ImGui.GetCursorScreenPos();
        var markerMax = markerMin + Ui(3f, 22f);
        ImGui.GetWindowDrawList().AddRectFilled(
            markerMin,
            markerMax,
            ImGui.ColorConvertFloat4ToU32(new Vector4(0.08f, 0.58f, 0.59f, 0.92f)),
            Ui(2f));

        ImGui.SetCursorPosX(x + Ui(12f));
        ImGui.TextUnformatted(title);
        ImGui.SetCursorPosX(x);
        ImGui.Dummy(Ui(1f, 8f));
    }

    private static bool IsNsfwPlugin(MarketplacePlugin plugin)
        => plugin.OmegaIsAdultContent || plugin.Tags.Concat(plugin.EffectiveCategories).Any(IsContentRatingTag);

    private static bool IsContentRatingTag(string value)
    {
        var tag = (value ?? string.Empty).Trim().ToLowerInvariant();
        return tag is "nsfw" or "adult" or "18+" or "18plus" or "explicit" or "sexual-content" or "mature";
    }
}
