using System.Diagnostics;
using System.Reflection;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Runtime;

/// <summary>
/// Deterministically exercises callbacks a plugin registered during startup.
/// The safe-v1 profile intentionally uses an empty world/no-player state and
/// never enables real rendering, game memory, network, or native hook behavior.
/// </summary>
internal static class PostInitExerciseEngine
{
    public const string SafeProfile = "post-init-safe-v1";
    public const string DisabledProfile = "none";

    private static readonly TimeSpan CallbackTimeout = TimeSpan.FromMilliseconds(750);
    private const int MaxCommands = 4;
    private const int MaxIpcCallbacks = 8;
    private const int MaxFrameworkCallbacks = 16;
    private const int MaxTotalInvocations = 48;

    public static ExerciseSummary Run(RuntimeServiceRegistry registry, AccessTracker tracker, string profile, int frameworkTicks)
    {
        if (string.Equals(profile, DisabledProfile, StringComparison.OrdinalIgnoreCase))
            return ExerciseSummary.NotRun(DisabledProfile, "exercise disabled", frameworkTicks);

        if (!string.Equals(profile, SafeProfile, StringComparison.OrdinalIgnoreCase))
            return ExerciseSummary.NotRun(profile, "unknown exercise profile", frameworkTicks);

        var summaries = new Dictionary<string, ExerciseRegistrationSummary>(StringComparer.Ordinal);
        var invocations = 0;
        var commands = 0;
        var ipc = 0;
        var frameworkCallbacks = 0;
        var haltedAfterTimeout = false;

        using (tracker.PushPhase("exercise.inventory"))
        {
            tracker.Exercise("exercise_engine", "inventory", "begin", parameters: new Dictionary<string, string?>
            {
                ["profile"] = SafeProfile,
                ["framework_ticks"] = frameworkTicks.ToString(),
                ["empty_world"] = "true",
                ["local_player"] = "absent",
                ["real_game_memory"] = "false",
                ["native_patch"] = "false",
                ["network_boundary"] = "isolated",
            });
        }

        var initial = registry.SnapshotExerciseCandidates(frameworkTicks);
        foreach (var candidate in initial)
            summaries[candidate.Id] = Summary(candidate);
        foreach (var scheduled in registry.SnapshotScheduledCallbacks())
            summaries.TryAdd(scheduled.Id, Summary(scheduled));

        var frameworkUpdates = initial
            .Where(x => x.Kind == "event" && x.Component == "IFramework" && x.Operation == "Update")
            .OrderBy(x => x.Id, StringComparer.Ordinal)
            .ToArray();

        // The synthetic framework is a bounded tick horizon. Startup-deferred work
        // is released only when its due tick is reached; delayed work beyond the
        // horizon stays visible as unexercised instead of being run prematurely.
        for (var tick = 1; tick <= frameworkTicks && !haltedAfterTimeout && invocations < MaxTotalInvocations; tick++)
        {
            using var frameworkScope = registry.EnterSyntheticFrameworkTick(tick);

            var remainingFrameworkBudget = MaxFrameworkCallbacks - frameworkCallbacks;
            if (remainingFrameworkBudget > 0)
            {
                foreach (var scheduled in registry.DequeueScheduledCallbacksDue(tick, remainingFrameworkBudget))
                {
                    if (invocations >= MaxTotalInvocations) break;
                    frameworkCallbacks++;
                    if (!summaries.TryGetValue(scheduled.Id, out var summary))
                    {
                        summary = Summary(scheduled);
                        summaries[scheduled.Id] = summary;
                    }
                    if (!Invoke(registry, scheduled, tracker, summary, summary.Invocations + 1, tick))
                        haltedAfterTimeout = true;
                    invocations++;
                    if (haltedAfterTimeout) break;
                }
            }

            if (haltedAfterTimeout) break;

            foreach (var candidate in frameworkUpdates)
            {
                if (invocations >= MaxTotalInvocations)
                {
                    MarkSkipped(summaries[candidate.Id], "total_exercise_budget_exhausted");
                    break;
                }
                if (!registry.IsRegistrationActive(candidate))
                {
                    MarkSkipped(summaries[candidate.Id], "registration_removed_before_invocation");
                    continue;
                }
                if (!Invoke(registry, candidate, tracker, summaries[candidate.Id], tick, tick))
                    haltedAfterTimeout = true;
                invocations++;
                if (haltedAfterTimeout) break;
            }
        }

        // Explicit non-rendering scenario order. This is deterministic but avoids
        // treating alphabetical event names as a meaningful UI lifecycle.
        var nonFramework = initial
            .Where(x => !(x.Kind == "event" && x.Component == "IFramework" && x.Operation == "Update"))
            .OrderBy(ScenarioOrder)
            .ThenBy(x => x.Operation, StringComparer.Ordinal)
            .ThenBy(x => x.Id, StringComparer.Ordinal)
            .ToArray();

        foreach (var candidate in nonFramework)
        {
            if (!candidate.EnabledByProfile)
                continue;
            if (haltedAfterTimeout)
            {
                MarkSkipped(summaries[candidate.Id], "exercise_halted_after_timeout");
                continue;
            }
            if (!registry.IsRegistrationActive(candidate))
            {
                MarkSkipped(summaries[candidate.Id], "registration_removed_before_invocation");
                continue;
            }
            if (candidate.Kind == "command" && commands >= MaxCommands)
            {
                MarkSkipped(summaries[candidate.Id], "command_budget_exhausted");
                continue;
            }
            if (candidate.Kind == "ipc" && ipc >= MaxIpcCallbacks)
            {
                MarkSkipped(summaries[candidate.Id], "ipc_budget_exhausted");
                continue;
            }
            if (invocations >= MaxTotalInvocations)
            {
                MarkSkipped(summaries[candidate.Id], "total_exercise_budget_exhausted");
                continue;
            }

            if (candidate.Kind == "command") commands++;
            if (candidate.Kind == "ipc") ipc++;
            if (!Invoke(registry, candidate, tracker, summaries[candidate.Id], 1, frameworkTick: null))
                haltedAfterTimeout = true;
            invocations++;
        }

        // Anything still scheduled is explicit evidence. Distinguish callbacks that
        // were outside the tick horizon from work blocked only by a callback budget.
        foreach (var candidate in registry.SnapshotScheduledCallbacks())
        {
            if (!summaries.TryGetValue(candidate.Id, out var summary))
            {
                summary = Summary(candidate);
                summaries[candidate.Id] = summary;
            }
            if (summary.Status == "exercised") continue;
            summary.Status = "unexercised";
            summary.Reason = haltedAfterTimeout
                ? "exercise_halted_after_timeout"
                : candidate.UnexercisedReason
                  ?? (candidate.DueTick > frameworkTicks
                    ? "synthetic_tick_horizon_not_reached"
                    : frameworkCallbacks >= MaxFrameworkCallbacks
                        ? "framework_callback_budget_exhausted"
                        : "total_exercise_budget_exhausted");
        }

        // Inventory registrations created while exercising. They are deliberately
        // not recursively triggered by safe-v1.
        foreach (var candidate in registry.SnapshotExerciseCandidates(frameworkTicks))
        {
            if (!summaries.ContainsKey(candidate.Id))
            {
                var summary = Summary(candidate);
                summary.Status = "unexercised";
                summary.Reason = "registered_during_exercise";
                summaries[candidate.Id] = summary;
            }
        }

        var ordered = summaries.Values.OrderBy(x => x.Id, StringComparer.Ordinal).ToList();
        var exercised = ordered.Count(x => x.Status == "exercised");
        var unexercised = ordered.Count - exercised;
        var byKind = ordered.GroupBy(x => x.Kind, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

        using (tracker.PushPhase("exercise.summary"))
        {
            tracker.Exercise("exercise_engine", "summary", "completed", parameters: new Dictionary<string, string?>
            {
                ["profile"] = SafeProfile,
                ["registrations_discovered"] = ordered.Count.ToString(),
                ["registrations_exercised"] = exercised.ToString(),
                ["registrations_unexercised"] = unexercised.ToString(),
                ["callback_invocations"] = invocations.ToString(),
                ["framework_callbacks"] = frameworkCallbacks.ToString(),
                ["halted_after_timeout"] = haltedAfterTimeout ? "true" : "false",
            });
        }

        return new ExerciseSummary
        {
            Profile = SafeProfile,
            Status = haltedAfterTimeout ? "partial" : "completed",
            FrameworkTicksRequested = frameworkTicks,
            RegistrationsDiscovered = ordered.Count,
            RegistrationsExercised = exercised,
            RegistrationsUnexercised = unexercised,
            ByKind = byKind,
            Registrations = ordered,
        };
    }

    private static int ScenarioOrder(ExerciseCandidate candidate)
    {
        if (candidate.Kind == "event" && candidate.Component == "IUiBuilder")
        {
            return candidate.Operation switch
            {
                "ShowUi" => 10,
                "OpenMainUi" => 11,
                "OpenConfigUi" => 12,
                "HideUi" => 13,
                _ => 19,
            };
        }
        return candidate.Kind switch
        {
            "event" => 20,
            "command" => 30,
            "ipc" => 40,
            _ => 90,
        };
    }

    private static ExerciseRegistrationSummary Summary(ExerciseCandidate candidate) => new()
    {
        Id = candidate.Id,
        Kind = candidate.Kind,
        Component = candidate.Component,
        Operation = candidate.Operation,
        Target = candidate.Target,
        Status = "unexercised",
        Reason = candidate.EnabledByProfile ? null : candidate.UnexercisedReason,
        PlannedInvocations = Math.Max(0, candidate.Repeat),
        DueTick = candidate.DueTick > 0 ? candidate.DueTick : null,
    };

    private static void MarkSkipped(ExerciseRegistrationSummary summary, string reason)
    {
        if (summary.Status == "exercised")
        {
            summary.Reason = "partially_exercised_" + reason;
            return;
        }
        summary.Status = "unexercised";
        summary.Reason = reason;
    }

    private static bool Invoke(RuntimeServiceRegistry registry, ExerciseCandidate candidate, AccessTracker tracker, ExerciseRegistrationSummary summary, int ordinal, int? frameworkTick)
    {
        using var phase = tracker.PushPhase($"exercise.{candidate.Kind}");
        using var activity = tracker.PushActivity(candidate.Kind, candidate.Id, ordinal);
        var parameters = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["registration_id"] = candidate.Id,
            ["registration_kind"] = candidate.Kind,
            ["invocation"] = ordinal.ToString(),
            ["synthetic_trigger"] = "true",
            ["empty_world"] = "true",
            ["local_player"] = "absent",
            ["framework_tick"] = frameworkTick?.ToString(),
            ["due_tick"] = candidate.DueTick > 0 ? candidate.DueTick.ToString() : null,
        };
        tracker.Exercise(candidate.Component, candidate.Operation, "begin", candidate.Target, parameters: parameters);

        var deadline = Stopwatch.StartNew();
        try
        {
            var invocation = Task.Run(() =>
            {
                using var frameworkInvocation = frameworkTick.HasValue ? registry.EnterFrameworkInvocation() : null;
                using var dalamudMainThread = frameworkTick.HasValue ? DalamudMainThreadRuntime.Enter(tracker) : null;
                return candidate.Handler.DynamicInvoke(candidate.Arguments);
            });
            if (!WaitWithinDeadline(invocation, deadline))
                return Timeout(candidate, tracker, summary, parameters, "callback_timeout");

            object? result;
            try
            {
                result = invocation.GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                throw Unwrap(ex);
            }

            var returnedTask = AsTask(result);
            if (returnedTask is not null)
            {
                if (!WaitWithinDeadline(returnedTask, deadline))
                    return Timeout(candidate, tracker, summary, parameters, "returned_async_timeout");
                returnedTask.GetAwaiter().GetResult();
            }

            summary.Status = "exercised";
            summary.Reason = null;
            summary.Invocations++;
            tracker.Exercise(candidate.Component, candidate.Operation, "completed", candidate.Target, parameters: parameters);
            return true;
        }
        catch (Exception ex)
        {
            var actual = Unwrap(ex);
            summary.Status = "exercised";
            summary.Reason = "callback_threw";
            summary.Invocations++;
            tracker.Exercise(candidate.Component, candidate.Operation, "threw", candidate.Target, actual, parameters);
            return true;
        }
    }

    private static bool WaitWithinDeadline(Task task, Stopwatch elapsed)
    {
        var remaining = CallbackTimeout - elapsed.Elapsed;
        return remaining > TimeSpan.Zero && task.Wait(remaining);
    }

    private static bool Timeout(
        ExerciseCandidate candidate,
        AccessTracker tracker,
        ExerciseRegistrationSummary summary,
        Dictionary<string, string?> parameters,
        string reason)
    {
        summary.Status = "exercised";
        summary.Reason = reason;
        summary.Invocations++;
        tracker.Exercise(candidate.Component, candidate.Operation, "timeout", candidate.Target,
            parameters: new Dictionary<string, string?>(parameters, StringComparer.Ordinal)
            {
                ["timeout_ms"] = ((int)CallbackTimeout.TotalMilliseconds).ToString(),
                ["timeout_reason"] = reason,
            });
        return false;
    }

    private static Task? AsTask(object? result)
    {
        if (result is Task task)
            return task;
        if (result is ValueTask valueTask)
            return valueTask.AsTask();
        if (result is null)
            return null;

        var type = result.GetType();
        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ValueTask<>))
            return type.GetMethod("AsTask", BindingFlags.Public | BindingFlags.Instance)?.Invoke(result, null) as Task;
        return null;
    }

    private static Exception Unwrap(Exception ex)
    {
        if (ex is AggregateException aggregate && aggregate.InnerExceptions.Count == 1)
            return Unwrap(aggregate.InnerExceptions[0]);
        if (ex is TargetInvocationException tie && tie.InnerException is not null)
            return Unwrap(tie.InnerException);
        return ex;
    }
}
