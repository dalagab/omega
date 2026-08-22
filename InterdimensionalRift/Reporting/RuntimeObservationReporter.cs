using System.Text.Json;
using System.Text.Json.Serialization;

namespace InterdimensionalRift.Reporting;

public static class RuntimeObservationReporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    public static SandboxReport Finalize(IEnumerable<RuntimeObservation> observations, PluginInfo plugin)
    {
        var ordered = observations
            .OrderBy(o => o.TimestampOffsetMs)
            .ThenBy(o => o.Id, StringComparer.Ordinal)
            .ToList();

        return new SandboxReport
        {
            Plugin = plugin,
            Observations = ordered,
            Summary = new ReportSummary
            {
                TotalObservations = ordered.Count,
                ByKind = ordered
                    .GroupBy(o => JsonNamingPolicy.SnakeCaseLower.ConvertName(o.Kind.ToString()))
                    .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal),
            },
        };
    }

    public static string Serialize(SandboxReport report) => JsonSerializer.Serialize(report, JsonOptions);
}
