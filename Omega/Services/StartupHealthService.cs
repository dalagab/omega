using System.Collections;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal enum StartupHealthCaptureState
{
    Pending,
    Complete,
    NextStartup,
}

internal enum StartupHealthSeverity
{
    Information,
    Warning,
    Error,
}

internal enum StartupHealthActionKind
{
    None,
    OpenOmegaPlugin,
    OpenDalamudPlugins,
    OpenDalamudSettings,
    OpenOmegaRepositories,
    OpenDalamudStartupProfiler,
}

internal sealed record StartupHealthItem(
    string Id,
    StartupHealthSeverity Severity,
    string Title,
    string Summary,
    string Detail,
    StartupHealthActionKind ActionKind = StartupHealthActionKind.None,
    string ActionLabel = "",
    string ActionValue = "");

internal sealed record StartupHealthSnapshot(
    StartupHealthCaptureState State,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset? CapturedAtUtc,
    bool AutoUpdateComplete,
    bool OmegaCatalogReady,
    int InspectedPluginCount,
    int InspectedRepositoryCount,
    int InspectedDevLocationCount,
    IReadOnlyList<StartupHealthItem> Items)
{
    public bool IsComplete => State == StartupHealthCaptureState.Complete;

    public int ActionableCount
        => Items.Count(x => x.Severity is StartupHealthSeverity.Warning or StartupHealthSeverity.Error);

    public int ErrorCount => Items.Count(x => x.Severity == StartupHealthSeverity.Error);

    public static StartupHealthSnapshot Pending(DateTimeOffset startedAtUtc)
        => new(
            StartupHealthCaptureState.Pending,
            startedAtUtc,
            null,
            false,
            false,
            0,
            0,
            0,
            []);

    public static StartupHealthSnapshot NextStartup(DateTimeOffset startedAtUtc)
        => new(
            StartupHealthCaptureState.NextStartup,
            startedAtUtc,
            null,
            false,
            false,
            0,
            0,
            0,
            []);
}

/// <summary>
/// Captures one bounded startup-health snapshot and then goes completely idle.
///
/// This deliberately does not subscribe to Framework.Update, tail logs, profile frames,
/// or inspect gameplay. Automatic capture only runs for PluginLoadReason.Boot, waits for
/// Dalamud's startup auto-update phase to settle, takes one in-memory/reflection snapshot,
/// and stops until the next game/Dalamud startup.
/// </summary>
internal sealed class StartupHealthService : IDisposable
{
    private const BindingFlags AllInstance = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan AutoUpdatePollInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan MaxAutoUpdateWait = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan PostAutoUpdateSettleDelay = TimeSpan.FromSeconds(8);
    private const long MaxStartupLogBytes = 2L * 1024 * 1024;
    private const double StartupHitchThresholdMs = 250.0;

    private static readonly Regex MissingDevPathLogPattern = new(
        "Dev plugin path \"(?<path>[^\"]+)\" does not exist",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex InvalidAssemblyVersionLogPattern = new(
        "Plugin \"(?<plugin>[^\"]+)\" in \"(?<url>[^\"]+)\" has an invalid AssemblyVersion",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex UiBuilderHitchLogPattern = new(
        @"\[HITCH\]\s+Long ""UiBuilder\((?<plugin>[^)]+)\)"" detected,\s*(?<ms>\d+(?:\.\d+)?)ms",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private readonly MarketplaceCatalogService catalog;
    private readonly CancellationTokenSource cancellation = new();
    private readonly DateTimeOffset startedAtUtc = DateTimeOffset.UtcNow;
    private readonly string? startupLogPath;
    private readonly long startupLogOffset;
    private StartupHealthSnapshot snapshot;
    private Task? captureTask;

    public StartupHealthService(MarketplaceCatalogService catalog)
    {
        this.catalog = catalog;
        var bootCapture = Plugin.PluginInterface.Reason.HasFlag(PluginLoadReason.Boot);
        snapshot = bootCapture
            ? StartupHealthSnapshot.Pending(startedAtUtc)
            : StartupHealthSnapshot.NextStartup(startedAtUtc);

        if (bootCapture)
            (startupLogPath, startupLogOffset) = CaptureStartupLogBoundary();
    }

    public StartupHealthSnapshot Snapshot => Volatile.Read(ref snapshot);

    public void Start()
    {
        if (captureTask is not null || Snapshot.State == StartupHealthCaptureState.NextStartup)
            return;

        captureTask = CaptureAfterStartupAsync(cancellation.Token);
    }

    public void Dispose()
    {
        cancellation.Cancel();
        cancellation.Dispose();
    }

    private async Task CaptureAfterStartupAsync(CancellationToken token)
    {
        try
        {
            await Task.Delay(InitialDelay, token).ConfigureAwait(false);

            var deadline = DateTimeOffset.UtcNow + MaxAutoUpdateWait;
            while ((!Plugin.PluginInterface.IsAutoUpdateComplete || !DalamudPluginsReady()) &&
                   DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(AutoUpdatePollInterval, token).ConfigureAwait(false);
            }

            // Give repository/plugin state a short quiet period after Dalamud says plugin loading and
            // automatic updates are complete. This is still startup-only work and happens exactly once.
            await Task.Delay(PostAutoUpdateSettleDelay, token).ConfigureAwait(false);

            var captured = await Plugin.Framework.RunOnTick(
                    CaptureSnapshot,
                    cancellationToken: token)
                .ConfigureAwait(false);

            Volatile.Write(ref snapshot, captured);

            Plugin.Log.Information(
                "Omega startup health captured once; actionable={Actionable}; errors={Errors}; plugins={Plugins}; repositories={Repositories}; devLocations={DevLocations}; autoUpdateComplete={AutoUpdateComplete}",
                captured.ActionableCount,
                captured.ErrorCount,
                captured.InspectedPluginCount,
                captured.InspectedRepositoryCount,
                captured.InspectedDevLocationCount,
                captured.AutoUpdateComplete);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega startup health capture failed.");
            Volatile.Write(
                ref snapshot,
                new StartupHealthSnapshot(
                    StartupHealthCaptureState.Complete,
                    startedAtUtc,
                    DateTimeOffset.UtcNow,
                    Plugin.PluginInterface.IsAutoUpdateComplete,
                    catalog.HasLoaded,
                    0,
                    0,
                    0,
                    [
                        new StartupHealthItem(
                            "omega.startup-inspection-limited",
                            StartupHealthSeverity.Warning,
                            "Startup inspection was limited",
                            "Omega could not read the final Dalamud startup state.",
                            RootMessage(ex))
                    ]));
        }
    }

    private StartupHealthSnapshot CaptureSnapshot()
    {
        var stopwatch = Stopwatch.StartNew();
        var items = new List<StartupHealthItem>();
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var inspectedPlugins = 0;
        var inspectedRepositories = 0;
        var inspectedDevLocations = 0;

        if (!catalog.HasLoaded)
        {
            Add(
                items,
                ids,
                new StartupHealthItem(
                    "omega.catalog-unavailable",
                    StartupHealthSeverity.Error,
                    "Omega marketplace data is unavailable",
                    "Omega did not have a usable local marketplace catalog at the end of startup.",
                    "Open Omega Settings and check the repository/Definitions state.",
                    StartupHealthActionKind.OpenOmegaRepositories,
                    "Open Omega repositories"));
        }

        try
        {
            InspectDalamud(
                items,
                ids,
                ref inspectedPlugins,
                ref inspectedRepositories,
                ref inspectedDevLocations);
        }
        catch (Exception ex)
        {
            Add(
                items,
                ids,
                new StartupHealthItem(
                    "omega.dalamud-inspection-limited",
                    StartupHealthSeverity.Warning,
                    "Some startup checks were unavailable",
                    "Dalamud's internal startup state changed or could not be read.",
                    RootMessage(ex)));
        }

        InspectStartupLog(items, ids);

        var autoUpdateComplete = Plugin.PluginInterface.IsAutoUpdateComplete;
        var pluginsReady = DalamudPluginsReady();
        if (!autoUpdateComplete || !pluginsReady)
        {
            Add(
                items,
                ids,
                new StartupHealthItem(
                    "dalamud.auto-update-timeout",
                    StartupHealthSeverity.Information,
                    "Startup was still settling",
                    "Some plugin or repository information may still have been changing when Omega finished its startup check.",
                    "The report is still useful, but a restart may give a more complete result."));
        }

        stopwatch.Stop();
        var sorted = items
            .OrderByDescending(x => x.Severity)
            .ThenBy(x => x.Title, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Plugin.Log.Debug(
            "Omega startup health one-shot inspection completed in {ElapsedMs:F1}ms.",
            stopwatch.Elapsed.TotalMilliseconds);

        return new StartupHealthSnapshot(
            StartupHealthCaptureState.Complete,
            startedAtUtc,
            DateTimeOffset.UtcNow,
            autoUpdateComplete,
            catalog.HasLoaded,
            inspectedPlugins,
            inspectedRepositories,
            inspectedDevLocations,
            sorted);
    }

    private static void InspectDalamud(
        List<StartupHealthItem> items,
        HashSet<string> ids,
        ref int inspectedPlugins,
        ref int inspectedRepositories,
        ref int inspectedDevLocations)
    {
        var assembly = typeof(IDalamudPluginInterface).Assembly;
        var serviceOpenType = RequireType(assembly, "Dalamud.Service`1");
        var pluginManagerType = RequireType(assembly, "Dalamud.Plugin.Internal.PluginManager");
        var configurationType = RequireType(assembly, "Dalamud.Configuration.Internal.DalamudConfiguration");

        var pluginManager = GetInternalService(serviceOpenType, pluginManagerType);
        var configuration = GetInternalService(serviceOpenType, configurationType);

        if (Get(pluginManager, "InstalledPlugins") is IEnumerable installed)
        {
            foreach (var candidate in installed.Cast<object>())
            {
                inspectedPlugins++;
                InspectPlugin(candidate, items, ids);
            }
        }

        if (Get(pluginManager, "Repos") is IEnumerable repositories)
        {
            foreach (var repository in repositories.Cast<object>())
            {
                inspectedRepositories++;
                InspectRepository(repository, items, ids);
            }
        }

        if (Get(configuration, "DevPluginLoadLocations") is IEnumerable locations)
        {
            foreach (var location in locations.Cast<object>())
            {
                inspectedDevLocations++;
                InspectDevLocation(location, items, ids);
            }
        }
    }

    private static void InspectPlugin(
        object plugin,
        List<StartupHealthItem> items,
        HashSet<string> ids)
    {
        var internalName = Text(Get(plugin, "InternalName"), "Unknown plugin");
        var name = Text(Get(plugin, "Name"), internalName);
        var state = Text(Get(plugin, "State"));
        var isDev = Bool(Get(plugin, "IsDev"));
        var dllFile = Get(plugin, "DllFile") as FileInfo;

        if (state.Equals("LoadError", StringComparison.OrdinalIgnoreCase))
        {
            Add(
                items,
                ids,
                PluginIssue(
                    internalName,
                    StartupHealthSeverity.Error,
                    $"{name} failed to load",
                    "Dalamud recorded a plugin load error during startup.",
                    $"State: {state}{PathDetail(dllFile)}"));
            return;
        }

        if (state.Equals("DependencyResolutionFailed", StringComparison.OrdinalIgnoreCase))
        {
            Add(
                items,
                ids,
                PluginIssue(
                    internalName,
                    StartupHealthSeverity.Error,
                    $"{name} is missing a dependency",
                    "Dalamud could not resolve one of this plugin's dependencies during startup.",
                    $"State: {state}{PathDetail(dllFile)}"));
            return;
        }

        if (state.Equals("UnloadError", StringComparison.OrdinalIgnoreCase))
        {
            Add(
                items,
                ids,
                PluginIssue(
                    internalName,
                    StartupHealthSeverity.Error,
                    $"{name} has an unload error",
                    "Dalamud reports this plugin in an inconsistent unload-error state.",
                    $"State: {state}{PathDetail(dllFile)}"));
            return;
        }

        if (isDev && dllFile is not null && !dllFile.Exists)
        {
            Add(
                items,
                ids,
                new StartupHealthItem(
                    $"dev-plugin:{dllFile.FullName}",
                    StartupHealthSeverity.Error,
                    $"{name} development build is missing",
                    "Dalamud still knows this development plugin, but its DLL no longer exists.",
                    dllFile.FullName,
                    StartupHealthActionKind.OpenDalamudSettings,
                    "Open Dev Plugin Locations",
                    "Dev Plugin Locations"));
            return;
        }

        if (Bool(Get(plugin, "IsBanned")))
        {
            Add(
                items,
                ids,
                PluginIssue(
                    internalName,
                    StartupHealthSeverity.Warning,
                    $"{name} is blocked by Dalamud",
                    "Dalamud currently marks this plugin as banned and will not load it.",
                    Text(Get(plugin, "BanReason"), "No ban reason was exposed.")));
            return;
        }

        if (!isDev && Bool(Get(plugin, "IsOrphaned")))
        {
            Add(
                items,
                ids,
                PluginIssue(
                    internalName,
                    StartupHealthSeverity.Warning,
                    $"{name} lost its repository",
                    "The installed plugin no longer has an associated Dalamud repository.",
                    "Open the plugin in Omega before updating or reinstalling it."));
            return;
        }

        if (!isDev && Bool(Get(plugin, "IsDecommissioned")))
        {
            Add(
                items,
                ids,
                PluginIssue(
                    internalName,
                    StartupHealthSeverity.Warning,
                    $"{name} is no longer published",
                    "Its repository loaded successfully, but this installed plugin is no longer present there.",
                    "Review the plugin and source before making changes."));
        }
    }

    private static StartupHealthItem PluginIssue(
        string internalName,
        StartupHealthSeverity severity,
        string title,
        string summary,
        string detail)
        => new(
            $"plugin:{internalName}:{title}",
            severity,
            title,
            summary,
            detail,
            StartupHealthActionKind.OpenOmegaPlugin,
            "Open in Omega",
            internalName);

    private static void InspectRepository(
        object repository,
        List<StartupHealthItem> items,
        HashSet<string> ids)
    {
        if (!Bool(Get(repository, "IsEnabled")))
            return;

        var state = Text(Get(repository, "State"));
        if (!state.Equals("Fail", StringComparison.OrdinalIgnoreCase))
            return;

        var url = Text(Get(repository, "PluginMasterUrl"), "Unknown repository");
        var thirdParty = Bool(Get(repository, "IsThirdParty"));
        var label = RepositoryLabel(url);

        Add(
            items,
            ids,
            new StartupHealthItem(
                $"repository:{url}",
                StartupHealthSeverity.Warning,
                $"{label} failed to load",
                thirdParty
                    ? "A configured community repository ended startup in a failed state."
                    : "Dalamud's official plugin repository ended startup in a failed state.",
                url,
                thirdParty
                    ? StartupHealthActionKind.OpenOmegaRepositories
                    : StartupHealthActionKind.OpenDalamudPlugins,
                thirdParty ? "Open Omega repositories" : "Open Dalamud plugins",
                url));
    }

    private static void InspectDevLocation(
        object location,
        List<StartupHealthItem> items,
        HashSet<string> ids)
    {
        if (!Bool(Get(location, "IsEnabled")))
            return;

        var path = Text(Get(location, "Path"));
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            return;

        if (File.Exists(path) || Directory.Exists(path))
            return;

        var nickname = Text(Get(location, "Nickname"));
        var title = string.IsNullOrWhiteSpace(nickname)
            ? "Development plugin location is missing"
            : $"{nickname} development location is missing";

        Add(
            items,
            ids,
            new StartupHealthItem(
                $"dev-location:{path}",
                StartupHealthSeverity.Error,
                title,
                "Dalamud is configured to scan this development plugin location, but it no longer exists.",
                path,
                StartupHealthActionKind.OpenDalamudSettings,
                "Open Dev Plugin Locations",
                "Dev Plugin Locations"));
    }

    private void InspectStartupLog(
        List<StartupHealthItem> items,
        HashSet<string> ids)
    {
        if (string.IsNullOrWhiteSpace(startupLogPath) || !File.Exists(startupLogPath))
            return;

        string text;
        try
        {
            using var stream = new FileStream(
                startupLogPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);

            var end = stream.Length;
            var start = startupLogOffset >= 0 && startupLogOffset <= end ? startupLogOffset : 0L;
            if (end - start > MaxStartupLogBytes)
                start = end - MaxStartupLogBytes;
            if (end <= start)
                return;

            stream.Position = start;
            using var reader = new StreamReader(
                stream,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true,
                bufferSize: 8192,
                leaveOpen: false);
            text = reader.ReadToEnd();
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega startup health could not read the bounded startup log slice.");
            return;
        }

        foreach (Match match in MissingDevPathLogPattern.Matches(text))
        {
            var path = match.Groups["path"].Value.Trim();
            if (string.IsNullOrWhiteSpace(path))
                continue;

            Add(
                items,
                ids,
                new StartupHealthItem(
                    $"dev-location:{path}",
                    StartupHealthSeverity.Error,
                    "Development plugin location is missing",
                    "Dalamud reported a configured development plugin path that no longer exists.",
                    path,
                    StartupHealthActionKind.OpenDalamudSettings,
                    "Open Dev Plugin Locations",
                    "Dev Plugin Locations"));
        }

        foreach (Match match in InvalidAssemblyVersionLogPattern.Matches(text))
        {
            var plugin = match.Groups["plugin"].Value.Trim();
            var url = match.Groups["url"].Value.Trim();
            if (string.IsNullOrWhiteSpace(plugin) || string.IsNullOrWhiteSpace(url))
                continue;

            Add(
                items,
                ids,
                new StartupHealthItem(
                    $"invalid-assembly-version:{url}:{plugin}",
                    StartupHealthSeverity.Warning,
                    $"{plugin} has a malformed repository entry",
                    "This repository entry has an invalid version number, so Dalamud skipped it.",
                    url,
                    StartupHealthActionKind.OpenOmegaRepositories,
                    "Open Omega repositories",
                    url));
        }

        var hitches = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in UiBuilderHitchLogPattern.Matches(text))
        {
            var plugin = match.Groups["plugin"].Value.Trim();
            if (string.IsNullOrWhiteSpace(plugin) ||
                !double.TryParse(
                    match.Groups["ms"].Value,
                    System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var milliseconds) ||
                milliseconds < StartupHitchThresholdMs)
            {
                continue;
            }

            if (!hitches.TryGetValue(plugin, out var existing) || milliseconds > existing)
                hitches[plugin] = milliseconds;
        }

        if (hitches.Count > 0)
        {
            var top = hitches
                .OrderByDescending(x => x.Value)
                .Take(5)
                .Select(x => $"{x.Key} {x.Value:0} ms")
                .ToArray();
            var summary = hitches.Count == 1
                ? "One plugin paused the UI for more than 250 ms during startup."
                : $"{hitches.Count} plugins paused the UI for more than 250 ms during startup.";

            Add(
                items,
                ids,
                new StartupHealthItem(
                    "startup.ui-hitches",
                    StartupHealthSeverity.Warning,
                    "Startup pauses were recorded",
                    summary,
                    string.Join(" • ", top),
                    StartupHealthActionKind.OpenDalamudStartupProfiler,
                    "Open startup profiler"));
        }
    }

    private static bool DalamudPluginsReady()
    {
        try
        {
            var assembly = typeof(IDalamudPluginInterface).Assembly;
            var serviceOpenType = RequireType(assembly, "Dalamud.Service`1");
            var pluginManagerType = RequireType(assembly, "Dalamud.Plugin.Internal.PluginManager");
            var pluginManager = GetInternalService(serviceOpenType, pluginManagerType);
            return Bool(Get(pluginManager, "PluginsReady"));
        }
        catch
        {
            // If Dalamud changes this internal readiness signal, keep the bounded startup
            // check usable rather than waiting the full deadline on every launch.
            return true;
        }
    }

    private static (string? Path, long Offset) CaptureStartupLogBoundary()
    {
        try
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (string.IsNullOrWhiteSpace(appData))
                return (null, 0L);

            var path = Path.Combine(appData, "XIVLauncher", "dalamud.log");
            if (!File.Exists(path))
                return (null, 0L);

            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            return (path, stream.Length);
        }
        catch
        {
            return (null, 0L);
        }
    }

    private static string PathDetail(FileInfo? dllFile)
        => dllFile is null ? string.Empty : $"{Environment.NewLine}Plugin: {dllFile.FullName}";

    private static string RepositoryLabel(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
            return uri.Host;
        return "Plugin repository";
    }

    private static void Add(
        List<StartupHealthItem> items,
        HashSet<string> ids,
        StartupHealthItem item)
    {
        if (ids.Add(item.Id))
            items.Add(item);
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
}
