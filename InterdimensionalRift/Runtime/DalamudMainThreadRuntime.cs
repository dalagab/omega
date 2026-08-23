using System.Reflection;
using InterdimensionalRift.Instrumentation;

namespace InterdimensionalRift.Runtime;

/// <summary>
/// Mirrors only Dalamud's trusted main-thread identity while Rift deliberately
/// invokes a callback as synthetic framework work. Real Dalamud keeps this state
/// in Dalamud.Utility.ThreadSafety via a ThreadStatic flag; IFramework's own
/// synthetic flag is not sufficient for libraries such as KamiToolKit that call
/// ThreadSafety.AssertMainThread directly.
/// </summary>
internal static class DalamudMainThreadRuntime
{
    private static readonly object Gate = new();
    private static bool resolved;
    private static PropertyInfo? isMainThreadProperty;
    private static MethodInfo? markMainThreadMethod;
    private static FieldInfo? threadStaticIsMainThreadField;
    private static string? dalamudVersion;

    public static IDisposable Enter(AccessTracker tracker)
    {
        EnsureResolved();

        var previous = ReadIsMainThread();
        if (!previous)
            markMainThreadMethod!.Invoke(null, null);

        if (!ReadIsMainThread())
            throw new InvalidOperationException("Rift could not enter the trusted Dalamud main-thread scope.");

        tracker.Exercise("Dalamud.Utility.ThreadSafety", "main_thread_scope", "entered",
            parameters: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["dalamud_version"] = dalamudVersion,
                ["previous_main_thread"] = previous ? "true" : "false",
                ["current_main_thread"] = "true",
                ["thread_id"] = Environment.CurrentManagedThreadId.ToString(),
                ["mechanism"] = "trusted_dalamud_threadstatic",
                ["real_game_thread"] = "false",
            });

        return new Scope(() =>
        {
            // ThreadStatic reflection reads/writes the slot for the current thread,
            // which is exactly the callback worker on which Enter was called.
            threadStaticIsMainThreadField!.SetValue(null, previous);
            var restored = ReadIsMainThread();
            tracker.Exercise("Dalamud.Utility.ThreadSafety", "main_thread_scope", "restored",
                parameters: new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    ["dalamud_version"] = dalamudVersion,
                    ["restored_main_thread"] = restored ? "true" : "false",
                    ["expected_main_thread"] = previous ? "true" : "false",
                    ["thread_id"] = Environment.CurrentManagedThreadId.ToString(),
                    ["mechanism"] = "trusted_dalamud_threadstatic",
                    ["real_game_thread"] = "false",
                });

            if (restored != previous)
                throw new InvalidOperationException("Rift failed to restore Dalamud main-thread identity after synthetic framework work.");
        });
    }

    private static void EnsureResolved()
    {
        if (resolved)
            return;

        lock (Gate)
        {
            if (resolved)
                return;

            var dalamud = DalamudContract.TryResolveTrusted(new AssemblyName("Dalamud"))
                ?? throw new InvalidOperationException("Frozen trusted Dalamud assembly is unavailable for main-thread fidelity.");
            var threadSafety = dalamud.GetType("Dalamud.Utility.ThreadSafety", throwOnError: true)
                ?? throw new TypeLoadException("Dalamud.Utility.ThreadSafety");

            isMainThreadProperty = threadSafety.GetProperty("IsMainThread", BindingFlags.Public | BindingFlags.Static)
                ?? throw new MissingMemberException(threadSafety.FullName, "IsMainThread");
            markMainThreadMethod = threadSafety.GetMethod("MarkMainThread", BindingFlags.NonPublic | BindingFlags.Static)
                ?? throw new MissingMethodException(threadSafety.FullName, "MarkMainThread");
            threadStaticIsMainThreadField = threadSafety.GetField("threadStaticIsMainThread", BindingFlags.NonPublic | BindingFlags.Static)
                ?? throw new MissingFieldException(threadSafety.FullName, "threadStaticIsMainThread");

            if (isMainThreadProperty.PropertyType != typeof(bool))
                throw new InvalidOperationException("Dalamud.Utility.ThreadSafety.IsMainThread is not Boolean in the frozen contract.");
            if (markMainThreadMethod.ReturnType != typeof(void) || markMainThreadMethod.GetParameters().Length != 0)
                throw new InvalidOperationException("Dalamud.Utility.ThreadSafety.MarkMainThread has an unexpected frozen-contract signature.");
            if (threadStaticIsMainThreadField.FieldType != typeof(bool) ||
                !threadStaticIsMainThreadField.IsDefined(typeof(ThreadStaticAttribute), inherit: false))
                throw new InvalidOperationException("Dalamud main-thread backing field is not the expected ThreadStatic Boolean.");

            dalamudVersion = dalamud.GetName().Version?.ToString();
            resolved = true;
        }
    }

    private static bool ReadIsMainThread() =>
        (bool)(isMainThreadProperty?.GetValue(null)
            ?? throw new InvalidOperationException("Dalamud main-thread property was not resolved."));

    private sealed class Scope : IDisposable
    {
        private Action? onDispose;
        public Scope(Action onDispose) => this.onDispose = onDispose;
        public void Dispose() => Interlocked.Exchange(ref onDispose, null)?.Invoke();
    }
}
