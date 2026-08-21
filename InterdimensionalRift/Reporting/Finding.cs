using System.Text.Json.Serialization;

namespace InterdimensionalRift.Reporting;

public enum FindingKind
{
    ServiceAccess,
    ServiceInjection,
    Lifecycle,
    Log,
    AssemblyReference,
    ReflectiveLoad,
    InitException,
    Timeout,
    Capability,
}

public enum FindingSeverity
{
    Info,
    Low,
    Medium,
    High,
}

public sealed class Finding
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("kind")]
    public FindingKind Kind { get; set; }

    [JsonPropertyName("severity")]
    public FindingSeverity Severity { get; set; } = FindingSeverity.Info;

    [JsonPropertyName("ts_offset_ms")]
    public long TimestampOffsetMs { get; set; }

    [JsonPropertyName("service")]
    public string? Service { get; set; }

    [JsonPropertyName("method")]
    public string? Method { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    [JsonPropertyName("exception_type")]
    public string? ExceptionType { get; set; }

    [JsonPropertyName("exception_message")]
    public string? ExceptionMessage { get; set; }

    [JsonPropertyName("context")]
    public string? Context { get; set; }

    [JsonPropertyName("parameters")]
    public Dictionary<string, string?>? Parameters { get; set; }
}
