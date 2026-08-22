using System.Text.Json.Serialization;

namespace InterdimensionalRift.Reporting;

/// <summary>
/// Neutral runtime evidence emitted by Rift. Kinds describe what Rift observed;
/// they intentionally do not encode security severity or a malware verdict.
/// </summary>
public enum RuntimeObservationKind
{
    ServiceAccess,
    ServiceInjection,
    Lifecycle,
    Log,
    AssemblyLoad,
    Exception,
    Timeout,
    Boundary,
}

public sealed class RuntimeObservation
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("kind")]
    public RuntimeObservationKind Kind { get; set; }

    [JsonPropertyName("ts_offset_ms")]
    public long TimestampOffsetMs { get; set; }

    [JsonPropertyName("component")]
    public string? Component { get; set; }

    [JsonPropertyName("operation")]
    public string? Operation { get; set; }

    [JsonPropertyName("outcome")]
    public string? Outcome { get; set; }

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
