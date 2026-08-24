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
    NativeLibrary,
    NativeGameState,
    Registration,
    Exercise,
    SignatureScan,
    Hook,
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

    [JsonPropertyName("phase")]
    public string? Phase { get; set; }

    [JsonPropertyName("activity_id")]
    public string? ActivityId { get; set; }

    [JsonPropertyName("parent_activity_id")]
    public string? ParentActivityId { get; set; }

    [JsonPropertyName("registration_id")]
    public string? RegistrationId { get; set; }

    [JsonPropertyName("invocation")]
    public int? Invocation { get; set; }

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

    [JsonPropertyName("exception_detail")]
    public string? ExceptionDetail { get; set; }

    [JsonPropertyName("context")]
    public string? Context { get; set; }

    [JsonPropertyName("origin_assembly")]
    public string? OriginAssembly { get; set; }

    [JsonPropertyName("origin_artifact_path")]
    public string? OriginArtifactPath { get; set; }

    [JsonPropertyName("origin_artifact_sha256")]
    public string? OriginArtifactSha256 { get; set; }

    [JsonPropertyName("parameters")]
    public Dictionary<string, string?>? Parameters { get; set; }
}
