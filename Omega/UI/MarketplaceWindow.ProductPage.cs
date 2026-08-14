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

        var plugin = ResolveSelectedVariant(selectedPlugin);
        selectedPlugin = plugin;
        installed.TryGetValue(plugin.InternalName, out var installedPlugin);
        var content = MarketplacePresentationRules.Choose(plugin, catalog.GetPresentationVariants(plugin.InternalName));

        if (DrawApplicationIconButton(FontAwesomeIcon.ArrowLeft, "discover-product-back", "Back to Discover", false))
        {
            detailsOpen = false;
            selectedPlugin = null;
            resetDiscoverListScroll = false;
            return;
        }

        if (!string.IsNullOrWhiteSpace(operationMessage))
            ImGui.TextWrapped(operationMessage);
        ImGui.Spacing();
        DrawProductHero(plugin, content, installedPlugin, currentApi, currentDalamudVersion);
        DrawProductScreenshots(content);
        DrawProductInformation(plugin, content, currentApi, currentDalamudVersion);
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
        ImGui.BeginChild("discover-product-hero", new Vector2(0f, 265f), true,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        ImGui.SetCursorPos(new Vector2(22f, 24f));
        DrawPluginArtwork(
            plugin,
            installedPlugin,
            ProductHeroIconSize,
            ProductHeroIconSize,
            currentApi,
            currentDalamudVersion,
            showOverlays: false,
            useFallbackTexture: false);

        ImGui.SameLine(0f, 24f);
        ImGui.BeginGroup();
        ImGui.SetCursorPosY(27f);
        ImGui.TextUnformatted(plugin.Name);
        ImGui.TextDisabled(string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author);

        var category = PrimaryPluginCategory(plugin);
        if (!string.IsNullOrWhiteSpace(category))
            ImGui.TextDisabled(category);

        ImGui.Spacing();
        DrawProductBadges(plugin, content);
        ImGui.Spacing();

        var summary = content.Summary;
        if (!string.IsNullOrWhiteSpace(summary))
        {
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

    private void DrawProductBadges(MarketplacePlugin plugin, MarketplacePresentationContent content)
    {
        var drewAny = false;
        if (catalog.GetVariants(plugin.InternalName).Any(x => x.SourceIsOfficial))
        {
            DrawDiscoverTextBadge("Dalamud official", new Vector4(0.09f, 0.38f, 0.44f, 0.94f));
            drewAny = true;
        }

        if (content.IsEnhanced)
        {
            if (drewAny)
                ImGui.SameLine(0f, 8f);
            DrawDiscoverTextBadge("★ Enhanced", new Vector4(0.45f, 0.34f, 0.08f, 0.96f));
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("Omega indexed presentation metadata from this plugin's public project page.");
            drewAny = true;
        }

        if (IsNsfwPlugin(plugin))
        {
            if (drewAny)
                ImGui.SameLine(0f, 8f);
            DrawDiscoverTextBadge("NSFW", new Vector4(0.56f, 0.16f, 0.22f, 0.96f));
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
        ImGui.TextUnformatted("Screenshots");
        ImGui.Spacing();
        ImGui.BeginChild("discover-product-screenshots", new Vector2(0f, ProductScreenshotHeight + 28f), true,
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
            var text = "Loading screenshot…";
            var textSize = ImGui.CalcTextSize(text);
            ImGui.GetWindowDrawList().AddText(
                min + new Vector2((avail.X - textSize.X) * 0.5f, (avail.Y - textSize.Y) * 0.5f),
                ImGui.GetColorU32(ImGuiCol.TextDisabled),
                text);
        }
        else
        {
            var available = ImGui.GetContentRegionAvail();
            var scale = Math.Min(available.X / texture.Size.X, available.Y / texture.Size.Y);
            var size = texture.Size * scale;
            ImGui.SetCursorPos(new Vector2(
                Math.Max(0f, (available.X - size.X) * 0.5f),
                Math.Max(0f, (available.Y - size.Y) * 0.5f)));
            ImGui.Image(texture.Handle, size);
        }

        ImGui.EndChild();
        ImGui.PopStyleColor();
    }

    private void DrawProductInformation(
        MarketplacePlugin plugin,
        MarketplacePresentationContent content,
        int currentApi,
        Version currentDalamudVersion)
    {
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();
        ImGui.TextUnformatted("About this plugin");
        if (!string.IsNullOrWhiteSpace(content.Description) &&
            !content.Description.Equals(content.Summary, StringComparison.Ordinal))
        {
            ImGui.Spacing();
            ImGui.TextWrapped(content.Description);
        }

        ImGui.Spacing();
        ImGui.TextDisabled($"Version {plugin.AssemblyVersionText}  •  {plugin.GetCompatibilityText(currentApi, currentDalamudVersion, configuration.PreferTestingBuilds)}");
        ImGui.TextDisabled($"Source: {plugin.SourceName}");
        if (content.IsEnhanced && !string.IsNullOrWhiteSpace(content.Variant.OmegaWebsiteUrl))
            ImGui.TextDisabled($"Enhanced from: {content.Variant.OmegaWebsiteUrl}");
        if (plugin.Tags.Count > 0)
            ImGui.TextDisabled("Tags: " + string.Join(", ", plugin.Tags));

        ImGui.Spacing();
        DrawDetailsLinks(plugin);
    }

    private static bool IsNsfwPlugin(MarketplacePlugin plugin)
        => plugin.Tags.Concat(plugin.EffectiveCategories).Any(IsContentRatingTag);

    private static bool IsContentRatingTag(string value)
    {
        var tag = (value ?? string.Empty).Trim().ToLowerInvariant();
        return tag is "nsfw" or "adult" or "18+" or "18plus" or "explicit" or "sexual-content" or "mature";
    }
}
