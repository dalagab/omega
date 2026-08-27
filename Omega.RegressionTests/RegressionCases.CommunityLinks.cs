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
        Contains(community, "https://github.com/dalagab/omega/tree/main", "Community links Omega to the client branch");
        Contains(community, "https://github.com/dalagab/omega/tree/sigmascope", "Community links SigmaScope to its branch");
        Contains(community, "https://github.com/dalagab/omega/tree/deltascope", "Community links DeltaScope to its standalone branch");
        Contains(community, "https://github.com/dalagab/omega/tree/rift", "Community links Rift to its branch");
        Contains(community, "https://discord.gg/rMBHbJTjp", "Community links the current Omega Discord invite");
        Contains(community, "FontAwesomeIcon.CodeBranch", "About uses an icon for GitHub");
        Contains(community, "FontAwesomeIcon.Comments", "About and Community use an icon for Discord");
        Contains(community, "UseShellExecute = true", "community destinations open through the operating-system browser");

        var about = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.Security.cs"));
        Contains(about, "var versionValueX = ImGui.GetCursorPosX();", "About remembers the version-value alignment");
        Contains(about, "DrawAboutCommunityShortcuts(versionValueX);", "About keeps GitHub and Discord shortcuts directly beneath the version value");

    }
}
