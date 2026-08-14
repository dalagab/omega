namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestCanonicalPluginNavigationAndLifecycleContract()
    {
        var artwork = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Artwork.cs"));
        var discover = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Discover.cs"));
        var library = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Library.cs"));
        var spotlight = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Spotlight.cs"));
        var collections = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Collections.cs"));
        var details = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Details.cs"));
        var product = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.ProductPage.cs"));
        var popups = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.UninstallAndSources.cs"));
        var chrome = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Chrome.cs"));
        var coordinator = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "PluginInstallCoordinator.cs"));
        var installer = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "DalamudInstallerBridge.cs"));

        Contains(artwork, "activeView = MarketplaceView.Discover", "canonical plugin selection always enters Discover");
        Contains(artwork, "selectedPlugin = ResolveSelectedVariant(plugin)", "canonical plugin selection resolves the product-page variant");
        Contains(discover, "OpenPluginDetails(plugin)", "Discover selections use canonical product navigation");
        Contains(library, "OpenPluginDetails(plugin)", "Library and Updates selections use canonical product navigation");
        Contains(spotlight, "OpenPluginDetails(plugin)", "Spotlight selections use canonical product navigation");
        Contains(collections, "OpenPluginDetails(plugin)", "Collection selections use canonical product navigation");

        Contains(details, "Process.Start(new ProcessStartInfo(projectUrl) { UseShellExecute = true })", "Project opens the system browser");
        Contains(details, "requestSourcePopup = true", "Copy source opens the known-source chooser");
        False(details.Contains("ImGui.SetClipboardText(plugin.SourceUrl)", StringComparison.Ordinal), "Copy source must not silently choose one repository");
        Contains(popups, "Known sources###DalagabOmegaKnownSources", "known-source popup is present");
        Contains(popups, "catalog.GetVariants(plugin.InternalName)", "known-source popup enumerates all catalog variants");
        Contains(popups, "ImGui.SetClipboardText(source.SourceUrl)", "source is copied only after explicit selection");

        Contains(product, "GetAvailableUpdateVersion", "Discover product pages detect newer compatible installed-plugin versions");
        Contains(product, "DrawProductActionButton(\"Update\"", "installed Discover products replace Installed/Open with Update when an update exists");
        Contains(product, "PluginInstallerOpenKind.UpdateablePlugins", "Discover product Update delegates to Dalamud's update surface");
        Contains(product, "OpenUninstallConfirmation(plugin)", "installed product pages expose uninstall");
        Contains(popups, "Uninstall plugin###DalagabOmegaUninstall", "uninstall is explicitly confirmed");
        Contains(coordinator, "installer.UninstallAsync", "uninstall coordinator delegates lifecycle work");
        Contains(installer, "pluginInterface.InternalName", "uninstall blocks Omega self-removal");
        Contains(installer, "exposed.IsDev", "uninstall protects dev plugins");
        Contains(installer, "UnloadAsync", "loaded plugins are unloaded through Dalamud first");
        Contains(installer, "ScheduleDeletion", "Dalamud deletion scheduling is used");
        Contains(installer, "RemovePlugin", "Dalamud installed-plugin manager remains removal authority");

        Contains(chrome, "notificationCount: counts.Updates", "Updates badge receives the actual pending-update count");
        Contains(chrome, "notificationCount > 99 ? \"99+\" : notificationCount.ToString()", "Updates badge remains compact while preserving useful counts");
        Contains(chrome, "const float badgeHeight = 15f", "Updates badge stays compact on the icon rail");
        Contains(chrome, "0.50f, 0.10f, 0.13f, 0.94f", "Updates counter uses a subdued red rather than alarm-bright red");
        Contains(discover, "queueIfVisible: true", "visible Discover cards queue their real plugin icons");
        Contains(discover, "showOverlays: false", "Discover card identity icons remain clean and overlay-free");
        Contains(discover, "var cardMin = ImGui.GetWindowPos();", "Discover hover outline anchors to the card window instead of padded content");
        Contains(discover, "cardMax - new Vector2(0.5f, 0.5f)", "Discover hover outline remains aligned to the card bounds");
    }
    internal static void TestRepositoryClientResponseLifetimeContract()
    {
        var repositoryClient = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "RepositoryClient.cs"));

        Contains(repositoryClient, "using var response = await httpClient.SendAsync", "repository fetch declares and owns the HTTP response");
        Contains(repositoryClient, "HttpCompletionOption.ResponseHeadersRead", "repository fetch streams response bodies instead of eagerly buffering them");
        Contains(repositoryClient, "response.EnsureSuccessStatusCode()", "repository fetch rejects unsuccessful HTTP responses");
        Contains(repositoryClient, "response.Content.ReadAsStreamAsync", "repository fetch reads from the declared response");
    }

}
