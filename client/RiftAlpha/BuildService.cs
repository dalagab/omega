using System.Security.Cryptography;

namespace Omega.RiftAlpha;

internal sealed record AlphaBuild(string BuildDirectory, string EntryAssemblyPath, string Sha256);

internal static class AlphaBuilder
{
    public static AlphaBuild Build(AlphaManifest manifest, string runDirectory)
    {
        if (!ProcessUtil.Exists("dotnet"))
            throw new InvalidOperationException(".NET 10 SDK is required to build Alpha scenarios.");

        var outDir = Path.Combine(runDirectory, "build");
        Directory.CreateDirectory(outDir);
        var result = ProcessUtil.Run("dotnet", ["build", manifest.ProjectPath, "--configuration", "Release", "--output", outDir, "--nologo"], manifest.FolderPath, timeoutSeconds: 180);
        if (result.ExitCode != 0)
            throw new InvalidOperationException("Alpha build failed:\n" + result.Stdout + "\n" + result.Stderr);

        var assembly = Path.Combine(outDir, manifest.EntryAssembly);
        if (!File.Exists(assembly))
            throw new InvalidOperationException($"Build succeeded but entry assembly was not produced: {assembly}");
        var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assembly))).ToLowerInvariant();
        return new AlphaBuild(outDir, assembly, hash);
    }
}
