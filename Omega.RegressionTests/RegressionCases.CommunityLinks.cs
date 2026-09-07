namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestCommunityLinksContract()
    {
        var window = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.cs"));
        Contains(window, "Community,", "Settings exposes a dedicated Community section");

        var sources = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Sources.cs"));
        Contains(sources, "settings-tab-community", "Settings renders the Community tab in the fixed tab strip");
        Contains(sources, "case SettingsSection.Community:", "Settings routes Community to its own panel");
        Contains(sources, "DrawSettingsCommunityTab();", "Community panel remains explicitly wired");

        var community = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Community.cs"));
        Contains(community, "https://github.com/dalagab/omega/tree/omega", "Community links Omega to the client branch");
        Contains(community, "https://github.com/dalagab/omega/tree/sigmascope", "Community links SigmaScope to its branch");
        Contains(community, "https://github.com/dalagab/omega/tree/deltascope", "Community links DeltaScope to its standalone branch");
        Contains(community, "https://github.com/dalagab/omega/tree/rift", "Community links Rift to its branch");
        Contains(community, "https://discord.gg/rMBHbJTjp", "Community links the current Omega Discord invite");
        Contains(community, "FontAwesomeIcon.CodeBranch", "About uses an icon for GitHub");
        Contains(community, "FontAwesomeIcon.Comments", "About and Community use an icon for Discord");
        Contains(community, "UseShellExecute = true", "community destinations open through the operating-system browser");
        Contains(community, "Delete all Omega local data", "Settings exposes an explicit local first-install reset");
        Contains(community, "OmegaDataResetService.Request", "local reset is queued safely for the next plugin reload");
        var normalizedCommunity = community.Replace("\r\n", "\n", StringComparison.Ordinal);
        Contains(normalizedCommunity, "\"omega\",\n            OmegaClientGitHubUrl", "Community labels the Omega client branch correctly");

        var reset = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "OmegaDataResetService.cs"));
        Contains(reset, ".omega-reset-requested", "reset uses a durable restart marker");
        Contains(reset, "SearchOption.TopDirectoryOnly", "reset stays bounded to Omega's own configuration directory");
        Contains(reset, "Path.GetTempPath()", "reset also clears Omega temporary backup data");
        Contains(reset, "third-party plugin configuration", "reset contract explicitly excludes other plugin data");

        var plugin = File.ReadAllText(Path.Combine(Root, "Omega", "Plugin.cs"));
        Contains(plugin, "OmegaDataResetService.ApplyPendingReset", "pending reset executes before Omega reads its saved configuration");

        var about = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Security.cs"));
        Contains(about, "var versionValueX = ImGui.GetCursorPosX();", "About remembers the version-value alignment");
        Contains(about, "DrawAboutCommunityShortcuts(versionValueX);", "About keeps GitHub and Discord shortcuts directly beneath the version value");

    }
}
