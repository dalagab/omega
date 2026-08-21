using System.Collections.Concurrent;
using System.Diagnostics;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Instrumentation;

/// <summary>
/// Thread-safe sink for all findings produced during a sandbox run.
/// </summary>
public sealed class AccessTracker
{
    private readonly ConcurrentQueue<Finding> _findings = new();
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private long _sequence;

    public IReadOnlyCollection<Finding> Snapshot() => _findings.ToArray();

    public void Record(FindingKind kind, FindingSeverity severity, string? service, string? method,
        string? message = null, Exception? exception = null, string? context = null,
        Dictionary<string, string?>? parameters = null)
    {
        var finding = new Finding
        {
            Id = Interlocked.Increment(ref _sequence).ToString("x16"),
            Kind = kind,
            Severity = severity,
            TimestampOffsetMs = _clock.ElapsedMilliseconds,
            Service = service,
            Method = method,
            Message = message,
            ExceptionType = exception?.GetType().FullName,
            ExceptionMessage = exception?.Message,
            Context = context,
            Parameters = parameters,
        };
        _findings.Enqueue(finding);
    }

    public void ServiceTouch(string serviceName, string method, FindingSeverity severity = FindingSeverity.Info,
        Dictionary<string, string?>? parameters = null)
    {
        Record(FindingKind.ServiceAccess, severity, serviceName, method, parameters: parameters);
    }


    public void ServiceInjection(string serviceName, string target, string mode)
    {
        Record(FindingKind.ServiceInjection, FindingSeverity.Info,
            service: serviceName, method: mode, message: target);
    }

    public void Lifecycle(string phase, string outcome, string? subject = null, Exception? exception = null)
    {
        Record(FindingKind.Lifecycle, FindingSeverity.Info,
            service: null, method: phase, message: outcome, exception: exception, context: subject);
    }

    public void Log(string level, string message)
    {
        var severity = level switch
        {
            "Error" => FindingSeverity.Medium,
            "Warning" => FindingSeverity.Low,
            _ => FindingSeverity.Info,
        };
        Record(FindingKind.Log, severity, service: "IPluginLog", method: level, message: message);
    }

    public void ReflectiveLoad(string assemblyName, string? path = null, bool resolved = false)
    {
        Record(FindingKind.ReflectiveLoad, FindingSeverity.Medium,
            service: null, method: resolved ? "load_resolved" : "load_attempted",
            message: assemblyName, context: path);
    }

    public void AssemblyReference(string referencedName)
    {
        Record(FindingKind.AssemblyReference, FindingSeverity.Info,
            service: null, method: "metadata_reference", message: referencedName);
    }

    public void InitException(Exception exception)
    {
        Record(FindingKind.InitException, FindingSeverity.High,
            service: null, method: "Initialize", exception: exception, context: "plugin init threw");
    }

    public void DisposeException(Exception exception)
    {
        Record(FindingKind.InitException, FindingSeverity.Medium,
            service: null, method: "Dispose", exception: exception, context: "plugin dispose threw");
    }

    public void Timeout(string phase)
    {
        Record(FindingKind.Timeout, FindingSeverity.High,
            service: null, method: phase, message: $"Timed out during {phase}");
    }

    public long ElapsedMs => _clock.ElapsedMilliseconds;
}
