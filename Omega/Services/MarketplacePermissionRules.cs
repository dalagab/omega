using System.Text.RegularExpressions;

namespace Dalagab.Omega;

internal enum MarketplacePermissionKind
{
    NoOmegaScan,
    BotLikeAutomation,
    CameraControl,
    ChatRead,
    ChatControl,
    NetworkAccess,
    LocalListener,
    ClipboardAccess,
    ExternalFileAccess,
    ProcessExecution,
    ShellExecution,
    CredentialAccess,
    ProcessMemoryAccess,
    RemoteThreadCreation,
    DynamicCodeLoading,
    BundledExecutable,
    WritableExecutableSection,
    RegistryAccess,
    NativeInterop,
    GameMemoryAccess,
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
    private static readonly Regex UriPortRegex = new(
        @"(?i)(?:https?|wss?)://[^\s/]+:(?<port>\d{1,5})(?:[/\s]|$)",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex NamedListenerPortRegex = new(
        @"(?i)\b(?:port|listen(?:ing)?\s+(?:on|at)|bind(?:ing)?\s+(?:to|on)|server\s+(?:port|on))\b[^\r\n\d]{0,20}(?<port>\d{1,5})\b",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex ListenerConstructorPortRegex = new(
        @"(?i)\b(?:TcpListener|IPEndPoint)\s*\([^,\r\n]{0,96},\s*(?<port>\d{1,5})\b|\b(?:ListenLocalhost|ListenAnyIP)\s*\(\s*(?<port2>\d{1,5})\b",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static IReadOnlyList<MarketplacePermissionConcern> FindBlockedCapabilities(
        MarketplacePlugin plugin,
        Configuration configuration)
    {
        var result = new List<MarketplacePermissionConcern>(21);
        var text = BuildSearchText(plugin);

        if (configuration.WarnWhenNoOmegaScan && string.IsNullOrWhiteSpace(plugin.SecurityStatus))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.NoOmegaScan,
                "No Omega scan yet",
                "Omega has no published analysis for this exact plugin version and repository yet."));

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

        if (configuration.WarnOnChatRead && HasChatRead(text))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.ChatRead,
                "Read game chat",
                "Can observe messages from the in-game chat log."));

        if (configuration.WarnOnChatControl && HasChatControl(text))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.ChatControl,
                "Send or change chat messages",
                "Can send, change, or automate messages in game chat."));

        // Inbound listeners are split from ordinary network-client capability because they change
        // the machine's listening surface and users often care about the concrete local port.
        if (configuration.WarnOnLocalListener && HasObservedCapability(plugin, "network.listener", "local.listener"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.LocalListener,
                "Start a local/network server",
                DescribeLocalListener(plugin)));

        if (configuration.WarnOnNetworkAccess && HasObservedCapability(plugin,
                "network.http", "network.outbound", "network.socket"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.NetworkAccess,
                "Use outbound network connections",
                "Can communicate with external services or other network endpoints."));

        if (configuration.WarnOnClipboardAccess && HasObservedCapability(plugin, "privacy.clipboard"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.ClipboardAccess,
                "Access the clipboard",
                "Can read or change text and other data in your clipboard."));

        if (configuration.WarnOnExternalFileAccess && HasObservedCapability(plugin, "filesystem.external-path"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.ExternalFileAccess,
                "Access external files",
                "Can access hard-coded file paths outside normal FFXIV/Dalamud locations."));

        if (configuration.WarnOnProcessExecution && HasObservedCapability(plugin,
                "process.execute", "process.launch", "behavior.download-execute"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.ProcessExecution,
                "Start other programs",
                "Can launch another executable, process, or command."));

        if (configuration.WarnOnShellExecution && HasObservedCapability(plugin, "shell.powershell"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.ShellExecution,
                "Run a shell or PowerShell",
                "Can invoke a command shell or PowerShell. This is more specific than ordinary process launching."));

        if (configuration.WarnOnCredentialAccess && HasObservedCapability(plugin, "privacy.credentials"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.CredentialAccess,
                "Access protected credentials",
                "Can use credential-manager, password-vault, or protected-data APIs."));

        if (configuration.WarnOnProcessMemoryAccess && HasObservedCapability(plugin, "memory.process"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.ProcessMemoryAccess,
                "Access another process's memory",
                "Can open another process and read or write its memory."));

        if (configuration.WarnOnRemoteThreadCreation && HasObservedCapability(plugin, "memory.remote-thread"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.RemoteThreadCreation,
                "Start code inside another process",
                "Can create or queue execution in another process."));

        if (configuration.WarnOnDynamicCodeLoading && HasObservedCapability(plugin, "dynamic.code", "dynamic.assembly"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.DynamicCodeLoading,
                "Load or generate code dynamically",
                "Can load assemblies/code at runtime or generate executable code dynamically."));

        if (configuration.WarnOnBundledExecutable && HasObservedCapability(plugin, "artifact.bundled-executable"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.BundledExecutable,
                "Include another executable",
                "The plugin package contains one or more executable program files in addition to the plugin itself."));

        if (configuration.WarnOnWritableExecutableSection && HasObservedCapability(plugin,
                "native.writable-executable-section", "native.pe.writable-executable-section"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.WritableExecutableSection,
                "Contain writable executable native memory",
                "A bundled native binary has a section that is both writable and executable."));

        if (configuration.WarnOnRegistryAccess && HasObservedCapability(plugin, "registry.access"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.RegistryAccess,
                "Access the Windows Registry",
                "Can read or modify Windows Registry values. This option is off by default because legitimate integrations also use the Registry."));

        if (configuration.WarnOnNativeInterop && HasObservedCapability(plugin, "native.interop", "native.pinvoke"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.NativeInterop,
                "Call native/unmanaged code",
                "Can call native libraries or unmanaged operating-system APIs. This is common in advanced plugins, so the warning is optional."));

        if (configuration.WarnOnGameMemoryAccess && HasObservedCapability(plugin, "game.memory.read", "game.hooking"))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.GameMemoryAccess,
                "Use game-memory or hooking facilities",
                "Can use game structures, signature scanning, or hooking facilities. Many advanced Dalamud plugins need this, so the warning is optional."));

        if (configuration.WarnOnMenuControl && HasMenuAutomation(plugin, text))
            result.Add(new MarketplacePermissionConcern(
                MarketplacePermissionKind.MenuControl,
                "Control game menus",
                "Can click, select, or move through game windows and menus for you."));

        return result;
    }

    private static string DescribeLocalListener(MarketplacePlugin plugin)
    {
        var ports = FindObservedListenerPorts(plugin);
        if (ports.Count == 0)
            return "Can start an inbound local/network listener. SigmaScope could not determine a fixed port from the client-visible static evidence; it may be configured or chosen at runtime.";

        var portText = string.Join(", ", ports);
        return $"Can start an inbound local/network listener. Static evidence mentions {(ports.Count == 1 ? "port" : "ports")} {portText}. The configured/runtime port can still differ.";
    }

    internal static IReadOnlyList<int> FindObservedListenerPorts(MarketplacePlugin plugin)
    {
        if (!HasObservedCapability(plugin, "network.listener", "local.listener"))
            return [];

        var ports = new SortedSet<int>();
        foreach (var finding in plugin.SecurityFindings)
        {
            var heading = string.Join(" ", finding.RuleId, finding.Category, finding.Title, finding.Description)
                .ToLowerInvariant();
            if (!ContainsAny(heading,
                    "listener", "local server", "loopback", "private-or-loopback", "localhost", "network endpoint"))
                continue;

            AddPorts(ports, finding.Description);
            foreach (var evidence in finding.Evidence)
                AddPorts(ports, evidence);
        }

        return ports.Take(12).ToArray();
    }

    private static void AddPorts(SortedSet<int> ports, string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return;

        foreach (Match match in UriPortRegex.Matches(text))
            AddPort(ports, match.Groups["port"].Value);
        foreach (Match match in NamedListenerPortRegex.Matches(text))
            AddPort(ports, match.Groups["port"].Value);
        foreach (Match match in ListenerConstructorPortRegex.Matches(text))
        {
            AddPort(ports, match.Groups["port"].Value);
            AddPort(ports, match.Groups["port2"].Value);
        }
    }

    private static void AddPort(SortedSet<int> ports, string value)
    {
        if (int.TryParse(value, out var port) && port is >= 1 and <= 65535)
            ports.Add(port);
    }

    private static bool HasBotLikeAutomation(MarketplacePlugin plugin, string text)
        => AutomationRank(plugin.SecurityAutomationLevel) >= 3 ||
           plugin.SecurityAutomationCapabilities.Any(x => AutomationRank(x.AutomationLevel) >= 3) ||
           ContainsAny(text,
               "botting", "bot-like", "full gameplay automation", "character automation",
               "character control", "combat automation", "gathering automation", "crafting automation");

    private static bool HasChatRead(string text)
        => ContainsAny(text,
            "game.chat.read", "game chat read", "chat.read", "chat-read", "chat read", "read chat",
            "chat log read", "read chat log", "chatlog read", "chat message read",
            "chat receive", "receive chat", "chat listener", "chat event");

    private static bool HasChatControl(string text)
        => ContainsAny(text,
            "send chat", "chat.send", "chat-send", "send message", "send-message",
            "send chat message", "change chat", "modify chat", "chat write", "chat.write",
            "chat automation", "tell send", "party chat send", "alliance chat send",
            "shout send", "yell send", "say channel send");

    private static bool HasObservedCapability(MarketplacePlugin plugin, params string[] ids)
    {
        var observed = plugin.SecurityCapabilities
            .Concat(plugin.SecurityAutomationCapabilities.Select(x => x.CapabilityId))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return ids.Any(observed.Contains);
    }

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
