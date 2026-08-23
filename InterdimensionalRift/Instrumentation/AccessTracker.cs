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
    private readonly ConcurrentQueue<RuntimeObservation> observations = new();
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private long sequence;

    public IReadOnlyCollection<RuntimeObservation> Snapshot() => observations.ToArray();

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
        observations.Enqueue(new RuntimeObservation
        {
            Id = Interlocked.Increment(ref sequence).ToString("x16"),
            Kind = kind,
            TimestampOffsetMs = clock.ElapsedMilliseconds,
            Component = component,
            Operation = operation,
            Outcome = outcome,
            Message = message,
            ExceptionType = exception?.GetType().FullName,
            ExceptionMessage = exception?.Message,
            ExceptionDetail = ExceptionDetail(exception),
            Context = context,
            Parameters = parameters,
        });
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

    private static string? ExceptionDetail(Exception? exception)
    {
        if (exception is null)
            return null;
        var text = exception.ToString();
        return text.Length <= 16384 ? text : text[..16384] + "\n...[truncated by Rift]";
    }

    public long ElapsedMs => clock.ElapsedMilliseconds;
}
