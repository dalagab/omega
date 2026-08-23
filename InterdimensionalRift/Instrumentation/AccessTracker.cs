using System.Collections.Concurrent;
using System.Diagnostics;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Instrumentation;

/// <summary>
/// Thread-safe sink for neutral runtime observations produced during a Rift run.
/// This class does not assign risk or severity. Interpretation belongs downstream.
/// </summary>
public sealed class AccessTracker
{
    private const int MaxObservations = 25_000;
    private const int MaxMessageChars = 16 * 1024;
    private const int MaxParameterChars = 2 * 1024;

    private readonly ConcurrentQueue<RuntimeObservation> observations = new();
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private readonly AsyncLocal<string?> phase = new();
    private readonly AsyncLocal<ActivityContext?> activity = new();
    private long sequence;
    private long activitySequence;
    private long acceptedObservations;
    private long droppedObservations;

    public AccessTracker()
    {
        phase.Value = "bootstrap";
    }

    public IReadOnlyCollection<RuntimeObservation> Snapshot()
    {
        var snapshot = observations.ToList();
        var dropped = Interlocked.Read(ref droppedObservations);
        if (dropped > 0)
        {
            snapshot.Add(new RuntimeObservation
            {
                Id = "observation-budget-truncation",
                Kind = RuntimeObservationKind.Boundary,
                TimestampOffsetMs = clock.ElapsedMilliseconds,
                Phase = "reporting",
                Component = "rift",
                Operation = "observation_budget",
                Outcome = "truncated",
                Message = "Rift observation collection reached its bounded in-process evidence budget.",
                Parameters = new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    ["max_observations"] = MaxObservations.ToString(),
                    ["observations_dropped"] = dropped.ToString(),
                },
            });
        }
        return snapshot;
    }

    public void Record(
        RuntimeObservationKind kind,
        string? component,
        string? operation,
        string? outcome = null,
        string? message = null,
        Exception? exception = null,
        string? context = null,
        Dictionary<string, string?>? parameters = null)
    {
        var accepted = Interlocked.Increment(ref acceptedObservations);
        if (accepted > MaxObservations)
        {
            Interlocked.Increment(ref droppedObservations);
            return;
        }

        var currentActivity = activity.Value;
        observations.Enqueue(new RuntimeObservation
        {
            Id = Interlocked.Increment(ref sequence).ToString("x16"),
            Kind = kind,
            TimestampOffsetMs = clock.ElapsedMilliseconds,
            Phase = phase.Value ?? "unknown",
            ActivityId = currentActivity?.Id,
            ParentActivityId = currentActivity?.ParentId,
            RegistrationId = currentActivity?.RegistrationId,
            Invocation = currentActivity?.Invocation,
            Component = component,
            Operation = operation,
            Outcome = outcome,
            Message = Truncate(message, MaxMessageChars),
            ExceptionType = exception?.GetType().FullName,
            ExceptionMessage = Truncate(exception?.Message, MaxMessageChars),
            ExceptionDetail = ExceptionDetail(exception),
            Context = Truncate(context, MaxMessageChars),
            Parameters = SanitizeParameters(parameters),
        });
    }

    public IDisposable PushPhase(string value)
    {
        var previous = phase.Value;
        phase.Value = value;
        return new Scope(() => phase.Value = previous);
    }

    public IDisposable PushActivity(string kind, string? registrationId = null, int? invocation = null)
    {
        var previous = activity.Value;
        var id = $"activity-{Interlocked.Increment(ref activitySequence):D6}";
        activity.Value = new ActivityContext
        {
            Id = id,
            ParentId = previous?.Id,
            RegistrationId = registrationId ?? previous?.RegistrationId,
            Invocation = invocation ?? previous?.Invocation,
            Kind = kind,
        };
        return new Scope(() => activity.Value = previous);
    }

    public void Registration(string kind, string component, string operation, string outcome, string? target = null, Dictionary<string, string?>? parameters = null)
    {
        parameters ??= new Dictionary<string, string?>(StringComparer.Ordinal);
        parameters["registration_kind"] = kind;
        if (target is not null) parameters["target"] = target;
        Record(RuntimeObservationKind.Registration, component, operation, outcome, parameters: parameters);
    }

    public void Exercise(string component, string operation, string outcome, string? target = null, Exception? exception = null, Dictionary<string, string?>? parameters = null)
    {
        parameters ??= new Dictionary<string, string?>(StringComparer.Ordinal);
        if (target is not null) parameters["target"] = target;
        Record(RuntimeObservationKind.Exercise, component, operation, outcome, exception: exception, parameters: parameters);
    }

    public void ServiceTouch(string serviceName, string method, Dictionary<string, string?>? parameters = null)
        => Record(RuntimeObservationKind.ServiceAccess, serviceName, method, outcome: "observed", parameters: parameters);

    public void ServiceInjection(string serviceName, string target, string mode)
        => Record(RuntimeObservationKind.ServiceInjection, serviceName, mode, outcome: "injected", message: target);

    public void Lifecycle(string phase, string outcome, string? subject = null, Exception? exception = null)
        => Record(RuntimeObservationKind.Lifecycle, "plugin", phase, outcome, exception: exception, context: subject);

    public void Boundary(string operation, string outcome, string? message = null, Dictionary<string, string?>? parameters = null)
        => Record(RuntimeObservationKind.Boundary, "rift", operation, outcome, message: message, parameters: parameters);

    public void Log(string level, string message)
        => Record(RuntimeObservationKind.Log, "IPluginLog", level, outcome: "emitted", message: message);

    public void AssemblyLoad(string assemblyName, string? path = null, bool resolved = false)
        => Record(
            RuntimeObservationKind.AssemblyLoad,
            "assembly_loader",
            resolved ? "load_resolved" : "load_attempted",
            resolved ? "resolved" : "attempted",
            message: assemblyName,
            context: path);

    public void NativeLibrary(string requestedName, string? resolvedPath, string outcome)
        => Record(
            RuntimeObservationKind.NativeLibrary,
            "native_loader",
            "load",
            outcome,
            message: requestedName,
            context: resolvedPath,
            parameters: new Dictionary<string, string?>
            {
                ["requested_library"] = requestedName,
                ["resolved_path"] = resolvedPath,
            });

    public void Signature(string operation, string signature, string outcome, long? syntheticAddress = null)
        => Record(
            RuntimeObservationKind.SignatureScan,
            "ISigScanner",
            operation,
            outcome,
            message: signature,
            parameters: new Dictionary<string, string?>
            {
                ["signature"] = signature,
                ["synthetic_address"] = syntheticAddress?.ToString("X"),
                ["real_game_memory"] = "false",
            });

    public void InitException(Exception exception)
        => Record(RuntimeObservationKind.Exception, "plugin", "Initialize", "threw", exception: exception, context: "plugin init threw");

    public void DisposeException(Exception exception)
        => Record(RuntimeObservationKind.Exception, "plugin", "Dispose", "threw", exception: exception, context: "plugin dispose threw");

    public void Timeout(string phase)
        => Record(RuntimeObservationKind.Timeout, "plugin", phase, "timeout", message: $"Timed out during {phase}");

    private static Dictionary<string, string?>? SanitizeParameters(Dictionary<string, string?>? parameters)
    {
        if (parameters is null)
            return null;
        return parameters.ToDictionary(
            kv => kv.Key,
            kv => Truncate(kv.Value, MaxParameterChars),
            StringComparer.Ordinal);
    }

    private static string? Truncate(string? value, int limit)
    {
        if (value is null || value.Length <= limit)
            return value;
        return value[..limit] + "...[truncated by Rift]";
    }

    private static string? ExceptionDetail(Exception? exception)
    {
        if (exception is null)
            return null;
        var text = exception.ToString();
        return text.Length <= MaxMessageChars ? text : text[..MaxMessageChars] + "\n...[truncated by Rift]";
    }

    public long ElapsedMs => clock.ElapsedMilliseconds;

    private sealed class ActivityContext
    {
        public string Id { get; init; } = string.Empty;
        public string? ParentId { get; init; }
        public string? RegistrationId { get; init; }
        public int? Invocation { get; init; }
        public string Kind { get; init; } = string.Empty;
    }

    private sealed class Scope : IDisposable
    {
        private Action? onDispose;
        public Scope(Action onDispose) => this.onDispose = onDispose;
        public void Dispose() => Interlocked.Exchange(ref onDispose, null)?.Invoke();
    }
}
