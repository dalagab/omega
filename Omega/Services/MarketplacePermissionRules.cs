namespace Dalagab.Omega;

internal enum MarketplacePermissionKind
{
    BotLikeAutomation,
    CameraControl,
    ChatControl,
    MenuControl,
}

internal readonly record struct MarketplacePermissionConcern(
    MarketplacePermissionKind Kind,
    string Label,
    string Explanation);

/// <summary>
/// Maps scanner/catalog capability observations to the small, user-facing install permission model.
/// This is an install-time warning layer, not an API sandbox: Dalamud does not expose per-plugin
/// capability revocation to Omega after another plugin is loaded.
/// </summary>
internal static class MarketplacePermissionRules
{
    public static IReadOnlyList<MarketplacePermissionConcern> FindBlockedCapabilities(
        MarketplacePlugin plugin,
        Configuration configuration)
    {
        var result = new List<MarketplacePermissionConcern>(4);
        var text = BuildSearchText(plugin);

        if (configuration.WarnOnBotLikeAutomation && HasBotLikeAutomation(plugin, text))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.BotLikeAutomation,
                "Automate gameplay",
                "Can control your character or play parts of the game for you."));

        if (configuration.WarnOnCameraControl && ContainsAny(text,
                "camera", "freecam", "free camera", "gpose", "look-at", "lookat"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.CameraControl,
                "Control the camera",
                "Can move or change the in-game camera."));

        if (configuration.WarnOnChatControl && ContainsAny(text,
                "chat", "send message", "send-message", "chat message", "tell", "party chat",
                "alliance chat", "shout", "yell", "say channel"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.ChatControl,
                "Send or change chat messages",
                "Can send, change, or automate messages in game chat."));

        if (configuration.WarnOnMenuControl && HasMenuAutomation(plugin, text))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.MenuControl,
                "Control game menus",
                "Can click, select, or move through game windows and menus for you."));

        return result;
    }

    private static bool HasBotLikeAutomation(MarketplacePlugin plugin, string text)
        => AutomationRank(plugin.SecurityAutomationLevel) >= 3 ||
           plugin.SecurityAutomationCapabilities.Any(x => AutomationRank(x.AutomationLevel) >= 3) ||
           ContainsAny(text,
               "botting", "bot-like", "full gameplay automation", "character automation",
               "character control", "combat automation", "gathering automation", "crafting automation");

    private static bool HasMenuAutomation(MarketplacePlugin plugin, string text)
        => AutomationRank(plugin.SecurityAutomationLevel) == 2 ||
           plugin.SecurityAutomationCapabilities.Any(x => AutomationRank(x.AutomationLevel) == 2) ||
           ContainsAny(text,
               "ui automation", "ui-automation", "menu automation", "menu control", "addon control",
               "selectstring", "select yesno", "context menu", "click game ui", "game ui/menu");

    private static int AutomationRank(string? level)
        => (level ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "full-gameplay-automation" => 4,
            "character-automation" => 3,
            "ui-automation" => 2,
            "observational" => 1,
            _ => 0,
        };

    private static string BuildSearchText(MarketplacePlugin plugin)
    {
        var parts = new List<string>();
        parts.AddRange(plugin.SecurityCapabilities);
        parts.Add(plugin.SecurityAutomationLevel);
        foreach (var capability in plugin.SecurityAutomationCapabilities)
        {
            parts.Add(capability.CapabilityId);
            parts.Add(capability.Label);
            parts.Add(capability.AutomationLevel);
            parts.Add(capability.Reason);
            parts.AddRange(capability.Evidence);
        }

        return string.Join(" ", parts.Where(x => !string.IsNullOrWhiteSpace(x))).ToLowerInvariant();
    }

    private static bool ContainsAny(string text, params string[] needles)
        => needles.Any(needle => text.Contains(needle, StringComparison.Ordinal));
}
