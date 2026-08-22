using System.Runtime.InteropServices;
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
    [JsonPropertyName("total_observations")] public int TotalObservations { get; set; }
    [JsonPropertyName("by_kind")] public Dictionary<string, int> ByKind { get; set; } = new(StringComparer.Ordinal);
}


public sealed class ExecutionProvenance
{
    [JsonPropertyName("executor")] public string? Executor { get; set; }
    [JsonPropertyName("artifact_tree_sha256")] public string? ArtifactTreeSha256 { get; set; }
    [JsonPropertyName("entry_sha256")] public string? EntrySha256 { get; set; }
    [JsonPropertyName("network")] public string? Network { get; set; }
    [JsonPropertyName("seccomp")] public string? Seccomp { get; set; }
    [JsonPropertyName("memory_max")] public string? MemoryMax { get; set; }
    [JsonPropertyName("tasks_max")] public string? TasksMax { get; set; }
    [JsonPropertyName("cpu_quota")] public string? CpuQuota { get; set; }
    [JsonPropertyName("memory_swap_max")] public string? MemorySwapMax { get; set; }
    [JsonPropertyName("wall_timeout_seconds")] public string? WallTimeoutSeconds { get; set; }
    [JsonPropertyName("tmpfs_tmp_bytes")] public string? TmpfsTmpBytes { get; set; }
    [JsonPropertyName("tmpfs_home_bytes")] public string? TmpfsHomeBytes { get; set; }
    [JsonPropertyName("tmpfs_work_bytes")] public string? TmpfsWorkBytes { get; set; }
    [JsonPropertyName("boundary_profile")] public string? BoundaryProfile { get; set; }
    [JsonPropertyName("contract_mode")] public string? ContractMode { get; set; }
    [JsonPropertyName("host_os")] public string? HostOs { get; set; }
    [JsonPropertyName("host_arch")] public string? HostArch { get; set; }
    [JsonPropertyName("runtime_identifier")] public string? RuntimeIdentifier { get; set; }

    public static ExecutionProvenance Capture() => new()
    {
        Executor = Environment.GetEnvironmentVariable("RIFT_EXECUTOR"),
        ArtifactTreeSha256 = Environment.GetEnvironmentVariable("RIFT_ARTIFACT_TREE_SHA256"),
        EntrySha256 = Environment.GetEnvironmentVariable("RIFT_ENTRY_SHA256"),
        Network = Environment.GetEnvironmentVariable("RIFT_NETWORK_MODE"),
        Seccomp = Environment.GetEnvironmentVariable("RIFT_SECCOMP_MODE"),
        MemoryMax = Environment.GetEnvironmentVariable("RIFT_MEMORY_MAX"),
        TasksMax = Environment.GetEnvironmentVariable("RIFT_TASKS_MAX"),
        CpuQuota = Environment.GetEnvironmentVariable("RIFT_CPU_QUOTA"),
        MemorySwapMax = Environment.GetEnvironmentVariable("RIFT_MEMORY_SWAP_MAX"),
        WallTimeoutSeconds = Environment.GetEnvironmentVariable("RIFT_WALL_TIMEOUT_SECONDS"),
        TmpfsTmpBytes = Environment.GetEnvironmentVariable("RIFT_TMPFS_TMP_BYTES"),
        TmpfsHomeBytes = Environment.GetEnvironmentVariable("RIFT_TMPFS_HOME_BYTES"),
        TmpfsWorkBytes = Environment.GetEnvironmentVariable("RIFT_TMPFS_WORK_BYTES"),
        BoundaryProfile = Environment.GetEnvironmentVariable("RIFT_BOUNDARY_PROFILE"),
        ContractMode = Environment.GetEnvironmentVariable("RIFT_CONTRACT_MODE"),
        HostOs = OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsLinux() ? "linux" : OperatingSystem.IsMacOS() ? "macos" : "unknown",
        HostArch = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
        RuntimeIdentifier = RuntimeInformation.RuntimeIdentifier,
    };
}

public sealed class SandboxReport
{
    [JsonPropertyName("schema_version")]
    public string SchemaVersion { get; set; } = "rift.runtime-observation.v1";

    [JsonPropertyName("producer")]
    public string Producer { get; set; } = "interdimensional-rift";

    [JsonPropertyName("producer_version")]
    public string ProducerVersion { get; set; } = "0.3.1";

    [JsonPropertyName("ran_at")]
    public string RanAt { get; set; } = DateTime.UtcNow.ToString("O");

    [JsonPropertyName("execution")]
    public ExecutionProvenance Execution { get; set; } = ExecutionProvenance.Capture();

    [JsonPropertyName("plugin")]
    public PluginInfo Plugin { get; set; } = new();

    [JsonPropertyName("observations")]
    public List<RuntimeObservation> Observations { get; set; } = new();

    [JsonPropertyName("summary")]
    public ReportSummary Summary { get; set; } = new();
}
