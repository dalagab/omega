using System.Collections;
using System.Reflection;
using Dalamud.Interface.ImGuiNotification;
using Dalamud.Interface.ImGuiNotification.EventArgs;
using Dalamud.Plugin.Services;

namespace Dalagab.Omega;

/// <summary>
/// Narrow bridge for Dalamud's own "plugin updates available" notification. Dalamud does not expose
/// global notification enumeration through the public plugin API, so Omega reflects only the current
/// notification manager collection and only attaches a body-click handler to the AutoUpdateManager's
/// availability notification. The existing Dalamud action buttons remain untouched.
/// </summary>
internal sealed class DalamudUpdateNotificationBridge : IDisposable
{
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromMilliseconds(500);

    private readonly Configuration configuration;
    private readonly INotificationManager pluginNotifications;
    private readonly IFramework framework;
    private readonly Action openUpdates;
    private readonly Dictionary<long, HookedNotification> hooked = [];

    private DateTimeOffset nextProbeUtc;
    private object? globalNotificationManager;
    private FieldInfo? activeNotificationsField;
    private FieldInfo? pendingNotificationsField;
    private FieldInfo? initiatorPluginField;
    private FieldInfo? drawActionsField;
    private bool reflectionFailureLogged;
    private bool disposed;

    public DalamudUpdateNotificationBridge(
        Configuration configuration,
        INotificationManager pluginNotifications,
        IFramework framework,
        Action openUpdates)
    {
        this.configuration = configuration;
        this.pluginNotifications = pluginNotifications;
        this.framework = framework;
        this.openUpdates = openUpdates;
        framework.Update += OnFrameworkUpdate;
    }

    private void OnFrameworkUpdate(IFramework _)
    {
        if (disposed)
            return;

        if (!configuration.RouteDalamudUpdateNotificationsToOmega)
        {
            UnhookAll();
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (now < nextProbeUtc)
            return;
        nextProbeUtc = now + ProbeInterval;

        try
        {
            if (!EnsureReflection())
                return;

            var seen = new HashSet<long>();
            foreach (var candidate in EnumerateNotifications())
            {
                if (candidate is not IActiveNotification notification || notification.DismissReason is not null)
                    continue;
                seen.Add(notification.Id);
                if (hooked.ContainsKey(notification.Id) || !IsDalamudPluginUpdateAvailabilityNotification(candidate, notification))
                    continue;
                Hook(notification);
            }

            foreach (var stale in hooked.Keys.Where(id => !seen.Contains(id)).ToArray())
                Unhook(stale);
        }
        catch (Exception ex)
        {
            if (!reflectionFailureLogged)
            {
                reflectionFailureLogged = true;
                Plugin.Log.Debug(ex, "Omega could not attach to Dalamud's plugin-update notification; Dalamud notifications remain unchanged.");
            }
        }
    }

    private bool EnsureReflection()
    {
        if (globalNotificationManager is not null && activeNotificationsField is not null)
            return true;

        var scopedType = pluginNotifications.GetType();
        var managerField = scopedType.GetField("notificationManagerService", BindingFlags.Instance | BindingFlags.NonPublic);
        var manager = managerField?.GetValue(pluginNotifications);
        if (manager is null)
            return false;

        var managerType = manager.GetType();
        var active = managerType.GetField("notifications", BindingFlags.Instance | BindingFlags.NonPublic);
        if (active is null)
            return false;

        globalNotificationManager = manager;
        activeNotificationsField = active;
        pendingNotificationsField = managerType.GetField("pendingNotifications", BindingFlags.Instance | BindingFlags.NonPublic);
        return true;
    }

    private IEnumerable<object> EnumerateNotifications()
    {
        if (globalNotificationManager is null)
            yield break;

        foreach (var candidate in EnumerateField(activeNotificationsField))
            yield return candidate;
        foreach (var candidate in EnumerateField(pendingNotificationsField))
            yield return candidate;

        IEnumerable<object> EnumerateField(FieldInfo? field)
        {
            if (field?.GetValue(globalNotificationManager) is not IEnumerable values)
                yield break;
            foreach (var value in values)
            {
                if (value is not null)
                    yield return value;
            }
        }
    }

    private bool IsDalamudPluginUpdateAvailabilityNotification(object candidate, IActiveNotification notification)
    {
        var type = candidate.GetType();
        initiatorPluginField ??= type.GetField("initiatorPlugin", BindingFlags.Instance | BindingFlags.NonPublic);
        if (initiatorPluginField is not null && initiatorPluginField.GetValue(candidate) is not null)
            return false;

        drawActionsField ??= type.GetField("DrawActions", BindingFlags.Instance | BindingFlags.NonPublic);
        if (drawActionsField?.GetValue(candidate) is Delegate drawActions)
        {
            foreach (var invocation in drawActions.GetInvocationList())
            {
                var signature = $"{invocation.Method.DeclaringType?.FullName} {invocation.Method.Name}";
                if (signature.Contains("AutoUpdateManager", StringComparison.Ordinal) &&
                    signature.Contains("NotifyUpdatesAreAvailable", StringComparison.Ordinal))
                    return true;
            }
        }

        return false;
    }

    private void Hook(IActiveNotification notification)
    {
        Action<INotificationClickArgs> click = _ =>
        {
            try
            {
                openUpdates();
                notification.DismissNow();
            }
            catch (Exception ex)
            {
                Plugin.Log.Debug(ex, "Omega could not open Updates from Dalamud's plugin-update notification.");
            }
        };
        Action<INotificationDismissArgs> dismiss = _ => Unhook(notification.Id);
        notification.Click += click;
        notification.Dismiss += dismiss;
        hooked[notification.Id] = new HookedNotification(notification, click, dismiss);
    }

    private void Unhook(long id)
    {
        if (!hooked.Remove(id, out var item))
            return;
        try { item.Notification.Click -= item.Click; } catch { }
        try { item.Notification.Dismiss -= item.Dismiss; } catch { }
    }

    private void UnhookAll()
    {
        foreach (var id in hooked.Keys.ToArray())
            Unhook(id);
    }

    public void Dispose()
    {
        if (disposed)
            return;
        disposed = true;
        framework.Update -= OnFrameworkUpdate;
        UnhookAll();
    }

    private sealed record HookedNotification(
        IActiveNotification Notification,
        Action<INotificationClickArgs> Click,
        Action<INotificationDismissArgs> Dismiss);
}
