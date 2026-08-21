using System.Text.Json;
using System.Text.Json.Serialization;

namespace InterdimensionalRift.Reporting;

public static class FindingReporter
{
    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    public static SandboxReport Finalize(IEnumerable<Finding> findings, PluginInfo plugin)
    {
        var ordered = findings.OrderBy(f => f.TimestampOffsetMs).ThenBy(f => f.Id).ToList();
        var report = new SandboxReport
        {
            Plugin = plugin,
            Findings = ordered,
            Summary = new ReportSummary
            {
                TotalFindings = ordered.Count,
                BySeverity = ordered
                    .GroupBy(f => f.Severity.ToString().ToLowerInvariant())
                    .ToDictionary(g => g.Key, g => g.Count()),
                ByKind = ordered
                    .GroupBy(f => f.Kind switch
                    {
                        FindingKind.ServiceAccess => "service_access",
                        FindingKind.Log => "log",
                        FindingKind.AssemblyReference => "assembly_reference",
                        FindingKind.ReflectiveLoad => "reflective_load",
                        FindingKind.InitException => "init_exception",
                        FindingKind.Timeout => "timeout",
                        FindingKind.Capability => "capability",
                        _ => "other",
                    })
                    .ToDictionary(g => g.Key, g => g.Count()),
            },
        };
        return report;
    }

    public static string Serialize(SandboxReport report) => JsonSerializer.Serialize(report, s_jsonOptions);
}
