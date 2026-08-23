using System.Text.Json;
using InterdimensionalRift.Host;
using InterdimensionalRift.Reporting;
using Xunit;

namespace InterdimensionalRift.Tests;

public sealed class RuntimeObservationSchemaTest
{
    [Fact]
    public void Report_IsNeutralRuntimeObservationSchema()
    {
        var sample = LocateFixture("SamplePlugin");
        var report = new SandboxHost().Run(sample, TimeSpan.FromSeconds(10), frameworkTicks: 0, exerciseProfile: "none");
        var json = RuntimeObservationReporter.Serialize(report);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        Assert.Equal("rift.runtime-observation.v2", root.GetProperty("schema_version").GetString());
        Assert.True(root.TryGetProperty("execution", out var execution));
        Assert.Equal(JsonValueKind.Object, execution.ValueKind);
        Assert.True(execution.TryGetProperty("host_os", out _));
        Assert.True(execution.TryGetProperty("host_arch", out _));
        Assert.True(execution.TryGetProperty("runtime_identifier", out _));
        Assert.True(root.TryGetProperty("exercise", out var exercise));
        Assert.Equal(JsonValueKind.Object, exercise.ValueKind);
        Assert.Equal("rift.exercise.v1", exercise.GetProperty("schema_version").GetString());
        Assert.True(root.TryGetProperty("observations", out var observations));
        Assert.Equal(JsonValueKind.Array, observations.ValueKind);
        Assert.True(observations.EnumerateArray().All(o => o.TryGetProperty("phase", out var p) && p.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(p.GetString())));
        Assert.False(root.TryGetProperty("findings", out _));
        Assert.False(root.GetProperty("summary").TryGetProperty("by_severity", out _));
        Assert.DoesNotContain("severity", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("capability", json, StringComparison.OrdinalIgnoreCase);
    }

    private static string LocateFixture(string assemblyName)
    {
        var testBin = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.Combine(testBin, assemblyName + ".dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "..", "samples", assemblyName, "bin", "Debug", "net10.0", assemblyName + ".dll"),
            Path.Combine(testBin, "..", "..", "..", "..", "..", "samples", assemblyName, "bin", "Release", "net10.0", assemblyName + ".dll"),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists) ?? Path.GetFullPath(candidates[0]);
    }
}
