using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Stubs;

/// <summary>
/// Base for every stub. Provides helpers to emit findings and stash the
/// service / tracker pair for instrumented stubs.
/// </summary>
public abstract class InstrumentedStub
{
    protected AccessTracker Tracker { get; }
    protected string ServiceName { get; }

    protected InstrumentedStub(string serviceName, AccessTracker tracker)
    {
        ServiceName = serviceName;
        Tracker = tracker;
    }

    protected void Touch(string method, FindingSeverity severity = FindingSeverity.Info,
        Dictionary<string, string?>? parameters = null)
    {
        var context = StackSampler.SampleForPlugin();
        var finding = new Finding
        {
            Kind = FindingKind.ServiceAccess,
            Severity = severity,
            Service = ServiceName,
            Method = method,
            Context = context,
            Parameters = parameters,
            TimestampOffsetMs = Tracker.ElapsedMs,
        };
        Tracker.Record(finding.Kind, finding.Severity, finding.Service, finding.Method,
            message: null, exception: null, context: finding.Context, parameters: finding.Parameters);
    }
}
