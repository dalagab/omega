using System.Text.Json.Serialization;

namespace InterdimensionalRift.Reporting;

public sealed class PluginInfo
{
    [JsonPropertyName("path")] public string Path { get; set; } = string.Empty;
    [JsonPropertyName("assembly_name")] public string AssemblyName { get; set; } = string.Empty;
    [JsonPropertyName("internal_name")] public string InternalName { get; set; } = string.Empty;
    [JsonPropertyName("load_outcome")] public string LoadOutcome { get; set; } = "ok";
    [JsonPropertyName("load_error")] public string? LoadError { get; set; }
    [JsonPropertyName("init_duration_ms")] public long InitDurationMs { get; set; }
    [JsonPropertyName("dispose_outcome")] public string DisposeOutcome { get; set; } = "ok";
    [JsonPropertyName("dispose_error")] public string? DisposeError { get; set; }
}

public sealed class ReportSummary
{
    [JsonPropertyName("total_findings")] public int TotalFindings { get; set; }
    [JsonPropertyName("by_severity")] public Dictionary<string, int> BySeverity { get; set; } = new();
    [JsonPropertyName("by_kind")] public Dictionary<string, int> ByKind { get; set; } = new();
}

public sealed class SandboxReport
{
    [JsonPropertyName("schema_version")] public string SchemaVersion { get; set; } = "1";
    [JsonPropertyName("scanner_version")] public string ScannerVersion { get; set; } = "0.1.0";
    [JsonPropertyName("ran_at")] public string RanAt { get; set; } = DateTime.UtcNow.ToString("O");
    [JsonPropertyName("plugin")] public PluginInfo Plugin { get; set; } = new();
    [JsonPropertyName("findings")] public List<Finding> Findings { get; set; } = new();
    [JsonPropertyName("summary")] public ReportSummary Summary { get; set; } = new();
}
