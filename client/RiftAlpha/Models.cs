using System.Text.Json.Serialization;

namespace Omega.RiftAlpha;

internal sealed class AlphaManifest
{
    public string Schema { get; set; } = "";
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public string Status { get; set; } = "";
    public string Project { get; set; } = "";
    public string AssemblyName { get; set; } = "";
    public string EntryAssembly { get; set; } = "";
    public string Mode { get; set; } = "";
    public string SafetyClass { get; set; } = "";
    public string[] Engines { get; set; } = [];
    public string[] Tags { get; set; } = [];
    public Dictionary<string, object?> Expected { get; set; } = new();

    [JsonIgnore]
    public string ManifestPath { get; set; } = "";

    [JsonIgnore]
    public string FolderPath => Path.GetDirectoryName(ManifestPath)!;

    [JsonIgnore]
    public string ProjectPath => Path.Combine(FolderPath, Project);
}

internal sealed record AlphaReportedEvent(
    string Id,
    string Kind,
    string? Detail,
    DateTimeOffset Timestamp);

internal sealed class AlphaRuntimeReport
{
    public string Schema { get; set; } = "omega.alpha.runtime-report.v1";
    public string Lane { get; set; } = "alpha";
    public string Authority { get; set; } = "local-alpha-scenario";
    public string RunId { get; set; } = "";
    public string AlphaId { get; set; } = "";
    public string Outcome { get; set; } = "pending";
    public string? Error { get; set; }
    public List<AlphaReportedEvent> Events { get; set; } = [];
}

internal sealed class RiftAlphaExecutionRequest
{
    public string Schema { get; set; } = "omega.rift.alpha-execution-request.v1";
    public string Lane { get; set; } = "alpha";
    public bool Synthetic { get; set; } = true;
    public string Authority { get; set; } = "local-alpha";
    public string RunId { get; set; } = "";
    public string AlphaId { get; set; } = "";
    public string ScenarioSha256 { get; set; } = "";
    public string EntryAssembly { get; set; } = "";
    public string SdkContract { get; set; } = "Omega.Alpha.Sdk/IAlphaScenario/v1";
}

internal sealed class RiftAlphaRunEvidence
{
    public string Schema { get; set; } = "omega.rift.alpha-run.v1";
    public string Lane { get; set; } = "alpha";
    public bool Synthetic { get; set; } = true;
    public string Authority { get; set; } = "local-alpha";
    public bool Published { get; set; }
    public string RunId { get; set; } = "";
    public string AlphaId { get; set; } = "";
    public string Backend { get; set; } = "";
    public string ScenarioSha256 { get; set; } = "";
    public string RequestSha256 { get; set; } = "";
    public string Outcome { get; set; } = "pending";
    public int ExitCode { get; set; }
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset CompletedAt { get; set; }
    public AlphaRuntimeReport? Offensive { get; set; }
    public RiftAlphaBoundaryEvidence Rift { get; set; } = new();
    public RiftAlphaDefensiveEvidence Defensive { get; set; } = new();
}

internal sealed class RiftAlphaBoundaryEvidence
{
    public string Profile { get; set; } = "rift-alpha-local-bwrap-v1";
    public bool NetworkNamespaceIsolated { get; set; } = true;
    public bool UserNamespaceIsolated { get; set; } = true;
    public bool ProcessNamespaceIsolated { get; set; } = true;
    public bool CgroupBound { get; set; } = true;
    public bool SeccompApplied { get; set; } = true;
    public string? StandardError { get; set; }
}

internal sealed class RiftAlphaDefensiveEvidence
{
    public string Status { get; set; } = "not-run";
    public List<string> Findings { get; set; } = [];
}
