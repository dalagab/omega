using System.Buffers.Binary;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Dalagab.Omega;

namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestArtworkIconOverlayContract()
    {
        var ui = ReadMarketplaceWindowSource();
        Contains(ui, "FontAwesomeIcon.InfoCircle", "information action uses an icon glyph");
        Contains(ui, "FontAwesomeIcon.Download", "install action uses an icon glyph");
        Contains(ui, "UiBuilder.IconFontFixedWidth", "fixed-width Dalamud icon font keeps action glyphs aligned");
        Contains(ui, "overlayMin = ImGui.GetCursorScreenPos()", "overlay origin follows the rendered image, not the outer tile");
        Contains(ui, "overlaySize = drawSize", "overlay bounds follow the rendered artwork dimensions");
        Contains(ui, "artworkMax = artworkMin + artworkSize", "overlays share one artwork rectangle");
        Contains(ui, "artworkMax.X - badgeWidth - inset", "API badge is inset from the artwork top-right");
        Contains(ui, "actionCount = canInstall ? 2 : 1", "action row packs according to visible actions");
        Contains(ui, "infoX = artworkMax.X - inset - rowWidth", "single info action remains right-aligned");
        Contains(ui, "draw.PushClipRect(clipMin, clipMax, true)", "overlay drawing is clipped to artwork bounds");

        var artwork = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Artwork.cs"));
        var topLayerCall = artwork.IndexOf("DrawArtworkTopLayer(plugin", StringComparison.Ordinal);
        var childEnd = artwork.IndexOf("ImGui.EndChild();", topLayerCall, StringComparison.Ordinal);
        True(topLayerCall >= 0 && childEnd > topLayerCall, "badge and actions are submitted before the artwork child ends so they remain on top");
        False(ui.Contains("primaryLabel = \"Prepare\"", StringComparison.Ordinal), "prepare must not be user-facing on artwork");
        False(ui.Contains("DrawArtworkActionButton(\"Info\"", StringComparison.Ordinal), "text Info pill must not return");
    }

    internal static void TestMarketplaceChromeOwnershipContract()
    {
        var ui = ReadMarketplaceWindowSource();
        False(ui.Contains("CenterText(\"OMEGA\")", StringComparison.Ordinal), "header product title is removed");
        False(ui.Contains("CenterText(\"Dalagab Group\"", StringComparison.Ordinal), "header organization name is removed");
        False(ui.Contains("sidebar-filters", StringComparison.Ordinal), "global sidebar Filters control is removed");
        False(ui.Contains("content-reload", StringComparison.Ordinal), "general header Reload control is removed");
        False(ui.Contains("sidebar-refresh-sources", StringComparison.Ordinal), "manual source refresh no longer lives beside the navigation rail");
        Contains(ui, "FontAwesomeIcon.Cog", "Settings uses an icon-only navigation button");
        Contains(ui, "const float rounding = 6f", "icon rail uses small-radius square navigation hit areas");
        Contains(ui, "##omega-nav-{id}", "icon rail owns dedicated borderless navigation hit boxes");
        Contains(ui, "no pill background and no border", "resting navigation blends into the sidebar panel");
        False(ui.Contains("DrawPillButton(icon.ToIconString()", StringComparison.Ordinal), "sidebar navigation must not regress to rounded pill buttons");
        Contains(ui, "OpenSettings()", "Settings owns source-management entry");
        Contains(ui, "RefreshSources()", "Settings refresh uses the dedicated source-refresh action");
        Contains(ui, "updates.RefreshAsync()", "source refresh still delegates to the catalog update coordinator");
        Contains(ui, "ImGui.TextDisabled(BuildInfo.Version)", "version remains visible at the icon-rail footer");
        Contains(ui, "panel-filters-{activeView}", "advanced Filters control belongs to the active content panel");
        Contains(ui, "omega-application-bar", "window chrome is owned by one shared application top bar");
        Contains(ui, "##omega-application-mark", "application bar keeps a small Omega mark at top-left");
        Contains(ui, "##omega-global-search", "application bar owns the centered global plugin search");
        Contains(ui, "ActivateGlobalSearch", "global search routes every page into Discover results");
        Contains(ui, "##omega-appbar-{id}", "application-bar controls use dedicated borderless icon hit boxes");
        Contains(ui, "DrawApplicationIconButton(FontAwesomeIcon.Minus, \"minimize\"", "top-right minimize uses the shared Dalamud icon font");
        Contains(ui, "DrawApplicationIconButton(FontAwesomeIcon.Times, \"close\"", "top-right close uses the shared Dalamud icon font");
        False(ui.Contains("content-minimize", StringComparison.Ordinal), "retired pill-style content minimize control must not return");
        False(ui.Contains("DrawPillButton(\"—\"", StringComparison.Ordinal), "window controls must not regress to pill buttons");
        Contains(ui, "##omega-minimized-icon", "minimized state is one icon-sized interaction");
        Contains(ui, "omegaIconTexture", "minimized state renders the Omega product icon");
        Contains(ui, "ImGui.IsMouseDragging(ImGuiMouseButton.Left, 3f)", "holding and dragging moves the minimized icon");
        Contains(ui, "ImGui.SetWindowPos(ImGui.GetWindowPos() + delta", "minimized drag repositions the icon window");
        Contains(ui, "ImGuiWindowFlags.NoBackground", "minimized icon has no surrounding application panel");
        Contains(ui, "RestoreFromMinimizedMode", "clicking the icon restores the full marketplace");
        var chrome = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Chrome.cs"));
        var minimizeBody = Capture(chrome, @"private void EnterMinimizedMode\(\)\s*\{(.*?)\n    \}");
        False(minimizeBody.Contains("ImGui.GetWindowSize()", StringComparison.Ordinal), "minimize must not snapshot the application-bar child width as the restore width");
        False(minimizeBody.Contains("ImGui.GetWindowPos()", StringComparison.Ordinal), "minimize must not snapshot the application-bar child position as the restore position");
        Contains(ui, "CaptureExpandedWindowState();", "expanded geometry is captured before entering the application-bar child");
        Contains(ui, "expandedWindowSize = ImGui.GetWindowSize();", "expanded size is captured while the top-level Omega window is current");
        Contains(ui, "if (expandedWindowSize.Y > 96f)", "legacy app-bar-height geometry is detected and repaired");
        Contains(ui, "expandedWindowSize = DefaultExpandedWindowSize;", "corrupt collapsed geometry falls back to Omega's default expanded size");
        Contains(ui, "ImGui.SetWindowSize(expandedWindowSize, ImGuiCond.Always);", "restore reapplies the remembered expanded size");
        False(ui.Contains("minimized-close", StringComparison.Ordinal), "minimized state must not add extra controls beside the icon");
    }

    internal static void TestInstallRepositoryChooserContract()
    {
        var ui = ReadMarketplaceWindowSource();
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginInstallCoordinator.cs"));
        var installer = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudInstallerBridge.cs"));

        Contains(ui, "Choose repository###DalagabOmegaInstall", "repository chooser popup");
        Contains(ui, "Choose which repository to use", "repository choice explanation");
        Contains(ui, "GetInstallCandidates", "compatible repository variants");
        Contains(ui, "ImGui.Button(\"Install\")", "single user-facing install action");
        Contains(ui, "StartSelectedInstall", "selected source install flow");
        False(ui.Contains("Prepare this repository", StringComparison.Ordinal), "prepare wording hidden from marketplace user");

        Contains(coordinator, "EnsureRepositoryReadyAsync", "hidden source preparation coordinator");
        Contains(coordinator, "EnsureIntegratedAsync", "Dalamud repository integration before install");
        Contains(coordinator, "SetManagedEnabledAsync", "Omega-managed disabled source recovery");
        Contains(coordinator, "EnableExistingForExplicitInstallAsync", "explicit install may enable a user-managed source without taking ownership");
        Contains(coordinator, "installer.InstallAsync", "coordinator delegates installation");
        Contains(installer, "InstallPluginAsync", "Dalamud remains package installation authority");

        var repositoryBridge = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudRepositoryBridge.cs"));
        Contains(repositoryBridge, "EnableExistingForExplicitInstallAsync", "explicit repository-enable bridge");
        Contains(repositoryBridge, "OwnedByOmega: false", "explicit enable does not steal repository ownership");
    }

    internal static void TestEngineeringStandardsContract()
    {
        var contributing = File.ReadAllText(Path.Combine(Root, "CONTRIBUTING.md"));
        Contains(contributing, "400 lines", "source-file target documented");
        Contains(contributing, "one clear responsibility", "function responsibility guidance documented");
        Contains(contributing, "regression guard", "regression expectations documented");
        Contains(contributing, "Dalamud remains responsible", "runtime ownership boundary documented");

        var sourceFiles = Directory.EnumerateFiles(Path.Combine(Root, "Omega"), "*.cs", SearchOption.AllDirectories)
            .Concat(Directory.EnumerateFiles(Path.Combine(Root, "Omega.RegressionTests"), "*.cs", SearchOption.AllDirectories))
            .Where(x => !x.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
            .Where(x => !x.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        foreach (var file in sourceFiles)
        {
            var lineCount = File.ReadLines(file).Count();
            True(lineCount <= 400, $"source file exceeds current 400-line target: {Path.GetRelativePath(Root, file)} ({lineCount})");
        }

        foreach (var file in Directory.EnumerateFiles(Path.Combine(Root, "Omega", "UI"), "MarketplaceWindow*.cs"))
        {
            var lineCount = File.ReadLines(file).Count();
            True(lineCount <= 400, $"marketplace UI partial exceeds 400-line target: {Path.GetFileName(file)} ({lineCount})");
        }

        foreach (var service in new[]
        {
            "PluginInstallCoordinator.cs",
            "DalamudDefaultCatalogBridge.cs",
            "DalamudProfileBridge.cs",
            "CatalogUpdateCoordinator.cs",
            "MarketplaceCatalogService.cs",
            "OnlineCatalogClient.cs",
            "CatalogDatabase.cs",
            "RepositoryClient.cs",
            "DalamudRepositoryBridge.cs",
            "DalamudInstallerBridge.cs",
        })
        {
            Contains(
                File.ReadAllText(Path.Combine(Root, "Omega", "Services", service)),
                "/// <summary>",
                $"{service} functionality description");
        }
    }
}
