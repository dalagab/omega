using System.Diagnostics;
using System.Reflection;

namespace InterdimensionalRift.Artifacts;

public sealed class RuntimeCallerAttribution
{
    public string AssemblyName { get; init; } = string.Empty;
    public string ArtifactPath { get; init; } = string.Empty;
    public string ArtifactSha256 { get; init; } = string.Empty;
}

public static class RuntimeCallerAttributionCapture
{
    public static RuntimeCallerAttribution? Capture(ArtifactInventory? inventory)
    {
        if (inventory is null) return null;
        try
        {
            foreach (var frame in new StackTrace(skipFrames: 2, fNeedFileInfo: false).GetFrames() ?? Array.Empty<StackFrame>())
            {
                var method = frame.GetMethod();
                var assembly = method?.DeclaringType?.Assembly;
                if (assembly is null || string.IsNullOrWhiteSpace(assembly.Location)) continue;
                if (!inventory.TryGet(assembly.Location, out var artifact) || artifact is null) continue;
                return new RuntimeCallerAttribution
                {
                    AssemblyName = assembly.GetName().Name ?? assembly.FullName ?? "unknown",
                    ArtifactPath = artifact.Path,
                    ArtifactSha256 = artifact.Sha256,
                };
            }
        }
        catch { }
        return null;
    }
}
