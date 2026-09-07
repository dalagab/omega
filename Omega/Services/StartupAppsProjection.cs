using System.Collections;
using System.Reflection;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed record StartupAppEntry(
    string InternalName,
    string Name,
    string NowLabel,
    string NowDetail,
    bool IsLoaded,
    string StartupLabel,
    string StartupDetail,
    int StartupOrder,
    string ActivityLabel,
    string ActivityDetail,
    string StatusLabel,
    string StatusDetail,
    bool ExpectedToStart,
    bool NeedsAttention);

internal sealed record StartupAppsSnapshot(
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<StartupAppEntry> Apps,
    string Warning = "")
{
    public int ExpectedCount => Apps.Count(x => x.ExpectedToStart);

    public int RunningCount => Apps.Count(x => x.IsLoaded);

    public int AttentionCount => Apps.Count(x => x.NeedsAttention);
}

/// <summary>
/// Builds a user-facing snapshot of Dalamud plugin startup state.
///
/// This is deliberately not a gameplay monitor. Capture is invoked only when the user opens
/// Library > Startup (and once after a pending startup check completes), reads existing Dalamud
/// manifest/profile state plus exact-version SigmaScope observations already present in Omega's
/// catalog, returns an immutable snapshot, and then does nothing.
/// </summary>
internal static class StartupAppsProjection
{
    private const BindingFlags AllInstance = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
    private const BindingFlags AllStatic = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;

    public static StartupAppsSnapshot Capture(
        DalamudProfileBridge profileBridge,
        Func<string, MarketplacePlugin?> resolveCatalogPlugin,
        IReadOnlyDictionary<string, IExposedPlugin> exposed)
    {
        try
        {
            var namedCollections = BuildNamedCollectionMap(profileBridge.ReadCollections());
            var assembly = typeof(IDalamudPluginInterface).Assembly;
            var serviceOpenType = RequireType(assembly, "Dalamud.Service`1");
            var pluginManagerType = RequireType(assembly, "Dalamud.Plugin.Internal.PluginManager");
            var pluginManager = GetInternalService(serviceOpenType, pluginManagerType);
            var apps = new List<StartupAppEntry>();

            if (Get(pluginManager, "InstalledPlugins") is not IEnumerable installed)
                return new(DateTimeOffset.UtcNow, [], "Dalamud did not expose the installed plugin list.");

            foreach (var candidate in installed.Cast<object>())
            {
                var internalName = Text(Get(candidate, "InternalName"));
                if (string.IsNullOrWhiteSpace(internalName))
                    continue;

                // The public installed-plugin list is the user-facing authority. Dalamud can keep
                // internal LocalPlugin objects around briefly while deletion/cleanup settles; those
                // must not reappear in Omega's Startup list after the user has uninstalled them.
                var manifest = Get(candidate, "Manifest");
                if (Bool(Get(manifest, "ScheduledForDeletion")) || !exposed.ContainsKey(internalName))
                    continue;

                var name = Text(Get(candidate, "Name"), internalName);
                var state = Text(Get(candidate, "State"));
                var isLoaded = Bool(Get(candidate, "IsLoaded"));
                var wanted = NullableBool(Get(candidate, "IsWantedByAnyProfile")) ?? isLoaded;
                var isDev = Bool(Get(candidate, "IsDev"));
                var isBanned = Bool(Get(candidate, "IsBanned"));
                var isOutdated = Bool(Get(candidate, "IsOutdated"));
                var isOrphaned = Bool(Get(candidate, "IsOrphaned"));
                var isDecommissioned = Bool(Get(candidate, "IsDecommissioned"));
                var dllFile = Get(candidate, "DllFile") as FileInfo;
                var loadSync = Bool(Get(manifest, "LoadSync"));
                var loadRequiredState = NullableInt(Get(manifest, "LoadRequiredState"));

                namedCollections.TryGetValue(internalName, out var memberships);
                memberships ??= [];

                var (nowLabel, nowDetail) = BuildNowLabel(isLoaded, state);
                var (startupLabel, startupDetail, startupOrder) = BuildStartupLabel(
                    wanted,
                    memberships,
                    loadRequiredState,
                    loadSync);

                exposed.TryGetValue(internalName, out var exposedPlugin);
                var catalogPlugin = resolveCatalogPlugin(internalName);
                var (activityLabel, activityDetail) = BuildActivityLabel(
                    catalogPlugin,
                    exposedPlugin?.HasMainUi == true,
                    exposedPlugin?.HasConfigUi == true);

                var (statusLabel, statusDetail, needsAttention) = BuildStatus(
                    wanted,
                    isLoaded,
                    isDev,
                    isBanned,
                    isOutdated,
                    isOrphaned,
                    isDecommissioned,
                    state,
                    dllFile);

                apps.Add(new StartupAppEntry(
                    internalName,
                    name,
                    nowLabel,
                    nowDetail,
                    isLoaded,
                    startupLabel,
                    startupDetail,
                    startupOrder,
                    activityLabel,
                    activityDetail,
                    statusLabel,
                    statusDetail,
                    wanted,
                    needsAttention));
            }

            var ordered = apps
                .OrderByDescending(x => x.NeedsAttention)
                .ThenByDescending(x => x.IsLoaded)
                .ThenByDescending(x => x.ExpectedToStart)
                .ThenBy(x => x.StartupOrder)
                .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return new(DateTimeOffset.UtcNow, ordered);
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega could not build the on-demand Startup apps snapshot.");
            return new(DateTimeOffset.UtcNow, [], RootMessage(ex));
        }
    }

    private static Dictionary<string, StartupCollectionMembership[]> BuildNamedCollectionMap(
        IReadOnlyList<DalamudPluginCollection> collections)
        => collections
            .Where(x => !x.IsDefault)
            .SelectMany(collection => collection.Plugins.Select(plugin => new
            {
                plugin.InternalName,
                Membership = new StartupCollectionMembership(
                    collection.Name,
                    collection.IsEnabled,
                    plugin.WantsEnabled),
            }))
            .GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => group.Select(x => x.Membership)
                    .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                StringComparer.OrdinalIgnoreCase);

    private static (string Label, string Detail) BuildNowLabel(bool isLoaded, string state)
    {
        if (state.Equals("LoadError", StringComparison.OrdinalIgnoreCase) ||
            state.Equals("DependencyResolutionFailed", StringComparison.OrdinalIgnoreCase))
            return ("Failed", "Dalamud tried to load this plugin, but the load did not complete successfully.");

        if (isLoaded)
            return ("Running", "This plugin is loaded in the current Dalamud session.");

        return ("Not loaded", "This plugin is installed but is not loaded in the current Dalamud session.");
    }

    private static (string Label, string Detail, int Order) BuildStartupLabel(
        bool wanted,
        IReadOnlyList<StartupCollectionMembership> memberships,
        int? loadRequiredState,
        bool loadSync)
    {
        if (!wanted)
        {
            var offOwnership = CollectionOwnershipText(memberships);
            var offDetail = "This plugin is installed, but Dalamud is not currently set to load it automatically.";
            if (!string.IsNullOrWhiteSpace(offOwnership))
                offDetail += $" {offOwnership}";
            return ("Off", offDetail, 9);
        }

        var (label, friendlyStage, order) = loadRequiredState switch
        {
            2 => ("At launch", "Dalamud can start loading it immediately.", 0),
            1 => ("As game starts", "Dalamud waits until the game loop is running.", 1),
            _ => ("After UI is ready", "Dalamud waits until plugin UI services are ready.", 2),
        };

        var detail = friendlyStage;
        var ownership = CollectionOwnershipText(memberships);
        if (!string.IsNullOrWhiteSpace(ownership))
            detail += $" {ownership}";

        detail += loadSync
            ? " This plugin is part of a startup step that Dalamud waits on before that step can finish."
            : " Dalamud does not need to wait for this plugin to finish before continuing that startup step.";

        return (label, detail, order);
    }

    private static string CollectionOwnershipText(IReadOnlyList<StartupCollectionMembership> memberships)
    {
        if (memberships.Count == 0)
            return string.Empty;

        var active = memberships
            .Where(x => x.CollectionEnabled && x.WantsEnabled)
            .Select(x => x.Name)
            .ToArray();
        if (active.Length == 1)
            return $"It is currently enabled through the {active[0]} collection.";
        if (active.Length > 1)
            return $"It is currently enabled through these collections: {string.Join(", ", active)}.";

        var names = string.Join(", ", memberships.Select(x => x.Name));
        return $"It also belongs to these named collections: {names}.";
    }

    private static (string Label, string Detail) BuildActivityLabel(
        MarketplacePlugin? plugin,
        bool hasMainUi,
        bool hasConfigUi)
    {
        if (plugin is null || !plugin.HasCompletedSecurityScan)
        {
            if (hasMainUi || hasConfigUi)
                return (
                    "UI available",
                    "The plugin exposes an interface, but Omega does not have enough exact-version static evidence to say whether it also stays active in the background.");
            return (
                "Not classified",
                "Omega does not have enough exact-version static evidence to describe what keeps this plugin active while you play.");
        }

        var evidence = BuildBehaviorEvidence(plugin);
        if (ContainsAny(
                evidence,
                "trigger.periodic",
                "periodic",
                "timer",
                "background",
                "local/network listener",
                "network listener",
                "listener.accept",
                "framework.update",
                "framework update",
                "update callback",
                "polling"))
        {
            return (
                "Background activity",
                "SigmaScope found a periodic, listener, polling, or similar background trigger in this exact plugin version. It can stay active without you opening its UI.");
        }

        if (ContainsAny(
                evidence,
                "trigger.",
                "event-triggered",
                "callback",
                "hook",
                "game chat read",
                "game state read",
                "game input/key state read",
                "game ui read",
                "game memory/hooks",
                "territory",
                "login event",
                "event handler"))
        {
            return (
                "Reacts to events",
                "SigmaScope found callbacks, hooks, or game-event/state observations in this exact plugin version. It can remain loaded and react when those conditions occur.");
        }

        if (plugin.SecurityAutomationCapabilities.Count > 0 ||
            !plugin.SecurityAutomationLevel.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            return (
                "When triggered",
                "SigmaScope found automation/control capability in this exact plugin version, but no continuous background trigger was identified. The capability is expected to act when invoked or when its own conditions are met.");
        }

        if (plugin.SecurityDependencies.Any(IsIpcRelationship))
        {
            return (
                "Plugin-to-plugin",
                "SigmaScope found an IPC/plugin relationship. Some activity may happen when this plugin or another plugin calls across that connection.");
        }

        if (hasMainUi || hasConfigUi)
        {
            return (
                "UI available",
                "The plugin exposes an interface. SigmaScope did not identify a stronger continuous or event-driven trigger in this exact version; that does not prove the plugin only runs while its UI is open.");
        }

        return (
            "No trigger identified",
            "SigmaScope completed an exact-version static scan, but Omega did not identify a continuous, event-driven, automation, or IPC trigger that can be summarized here.");
    }

    private static string BuildBehaviorEvidence(MarketplacePlugin plugin)
    {
        var parts = new List<string>();
        parts.AddRange(plugin.SecurityCapabilities);
        parts.Add(plugin.SecurityAutomationLevel);

        foreach (var capability in plugin.SecurityAutomationCapabilities)
        {
            parts.Add(capability.CapabilityId);
            parts.Add(capability.Label);
            parts.Add(capability.Reason);
            parts.AddRange(capability.Evidence);
        }

        foreach (var finding in plugin.SecurityFindings)
        {
            parts.Add(finding.RuleId);
            parts.Add(finding.Category);
            parts.Add(finding.Title);
            parts.Add(finding.Description);
            parts.AddRange(finding.Evidence);
        }

        foreach (var dependency in plugin.SecurityDependencies)
        {
            parts.Add(dependency.Kind);
            parts.Add(dependency.Type);
            parts.Add(dependency.Relationship);
            parts.Add(dependency.RelationshipReason);
        }

        return string.Join("\n", parts).ToLowerInvariant();
    }

    private static bool IsIpcRelationship(MarketplaceDependency dependency)
        => dependency.Type.Equals("ipc", StringComparison.OrdinalIgnoreCase) ||
           dependency.Kind.Contains("ipc", StringComparison.OrdinalIgnoreCase) ||
           dependency.RelationshipReason.Contains("ipc", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAny(string value, params string[] needles)
        => needles.Any(value.Contains);

    private static (string Label, string Detail, bool NeedsAttention) BuildStatus(
        bool wanted,
        bool isLoaded,
        bool isDev,
        bool isBanned,
        bool isOutdated,
        bool isOrphaned,
        bool isDecommissioned,
        string state,
        FileInfo? dllFile)
    {
        if (state.Equals("LoadError", StringComparison.OrdinalIgnoreCase))
            return ("Failed to start", "Dalamud recorded a load error for this plugin.", true);
        if (state.Equals("DependencyResolutionFailed", StringComparison.OrdinalIgnoreCase))
            return ("Dependency missing", "Dalamud could not load one of this plugin's required components.", true);
        if (state.Equals("UnloadError", StringComparison.OrdinalIgnoreCase))
            return ("Needs restart", "This plugin is in an inconsistent unload state and may need a restart.", true);
        if (isDev && dllFile is not null && !dllFile.Exists)
            return ("Development file missing", "The configured development plugin file no longer exists.", true);
        if (isBanned)
            return ("Blocked", "Dalamud currently blocks this plugin from loading.", true);
        if (isOutdated)
            return ("Update required", "This plugin targets an older Dalamud API and cannot start normally.", true);
        if (!isDev && isOrphaned)
            return ("Repository missing", "The installed plugin no longer has an associated repository.", true);
        if (!isDev && isDecommissioned)
            return ("No longer published", "Its repository is available, but this plugin is no longer listed there.", true);
        if (!wanted)
            return ("Off", "This plugin is installed but is not currently enabled for automatic startup.", false);
        if (!isLoaded)
            return ("Didn't start", "This plugin was expected to start but is not loaded now.", true);
        return ("OK", "The plugin is loaded and Omega found no startup problem for it.", false);
    }

    private static object? Get(object? target, string property)
    {
        if (target is null)
            return null;
        try
        {
            return target.GetType().GetProperty(property, AllInstance)?.GetValue(target);
        }
        catch
        {
            return null;
        }
    }

    private static string Text(object? value, string fallback = "")
        => value?.ToString() is { Length: > 0 } text ? text : fallback;

    private static bool Bool(object? value) => value is bool flag && flag;

    private static bool? NullableBool(object? value) => value is bool flag ? flag : null;

    private static int? NullableInt(object? value)
        => value is null ? null : value is int integer ? integer : int.TryParse(value.ToString(), out var parsed) ? parsed : null;

    private static object GetInternalService(Type serviceOpenType, Type serviceType)
    {
        var closed = serviceOpenType.MakeGenericType(serviceType);
        var get = closed.GetMethod("Get", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMethodException($"Dalamud service locator could not resolve {serviceType.Name}.");
        return get.Invoke(null, null)
               ?? throw new InvalidOperationException($"Dalamud service {serviceType.Name} was null.");
    }

    private static Type RequireType(Assembly assembly, string fullName)
        => assembly.GetType(fullName, throwOnError: false)
           ?? throw new TypeLoadException($"Dalamud internal type changed: {fullName}");

    private static string RootMessage(Exception ex)
    {
        while (ex.InnerException is not null)
            ex = ex.InnerException;
        return ex.Message;
    }

    private sealed record StartupCollectionMembership(string Name, bool CollectionEnabled, bool WantsEnabled);
}
