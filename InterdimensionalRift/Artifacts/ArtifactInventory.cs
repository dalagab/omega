using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace InterdimensionalRift.Artifacts;

public sealed class ArtifactFile
{
    [JsonPropertyName("path")] public string Path { get; init; } = string.Empty;
    [JsonPropertyName("sha256")] public string Sha256 { get; init; } = string.Empty;
    [JsonPropertyName("bytes")] public long Bytes { get; init; }
    [JsonPropertyName("kind")] public string Kind { get; init; } = "other";
}

public sealed class ArtifactInventory
{
    private readonly Dictionary<string, ArtifactFile> byFullPath;

    [JsonPropertyName("schema_version")] public string SchemaVersion { get; init; } = "rift.artifact-inventory.v1";
    [JsonPropertyName("root_name")] public string RootName { get; init; } = string.Empty;
    [JsonPropertyName("files")] public List<ArtifactFile> Files { get; init; } = new();

    private ArtifactInventory(string root, List<ArtifactFile> files, Dictionary<string, ArtifactFile> paths)
    {
        RootName = Path.GetFileName(root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        Files = files;
        byFullPath = paths;
    }

    public static ArtifactInventory Build(string artifactDirectory)
    {
        var root = Path.GetFullPath(artifactDirectory);
        var trustedHeadlessShimPath = Environment.GetEnvironmentVariable("RIFT_HEADLESS_UI_SHIM_PATH");
        var trustedHeadlessShimSha = Environment.GetEnvironmentVariable("RIFT_HEADLESS_UI_SHIM_SHA256");
        var files = new List<ArtifactFile>();
        var paths = new Dictionary<string, ArtifactFile>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).OrderBy(path => path, StringComparer.Ordinal))
        {
            var relativePath = Path.GetRelativePath(root, path).Replace('\\', '/');
            var sha256 = Hash(path);
            if (IsTrustedHeadlessShim(relativePath, sha256, trustedHeadlessShimPath, trustedHeadlessShimSha))
                continue;

            var entry = new ArtifactFile
            {
                Path = relativePath,
                Sha256 = sha256,
                Bytes = new FileInfo(path).Length,
                Kind = Classify(path),
            };
            files.Add(entry);
            paths[Path.GetFullPath(path)] = entry;
        }
        return new ArtifactInventory(root, files, paths);
    }

    private static bool IsTrustedHeadlessShim(string relativePath, string sha256, string? configuredPath, string? configuredSha)
    {
        return !string.IsNullOrWhiteSpace(configuredPath)
            && !string.IsNullOrWhiteSpace(configuredSha)
            && string.Equals(relativePath, configuredPath.Replace('\\', '/'), StringComparison.Ordinal)
            && string.Equals(sha256, configuredSha, StringComparison.OrdinalIgnoreCase);
    }

    public bool TryGet(string? path, out ArtifactFile? file)
    {
        file = null;
        if (string.IsNullOrWhiteSpace(path)) return false;
        try { return byFullPath.TryGetValue(Path.GetFullPath(path), out file); }
        catch { return false; }
    }

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static string Classify(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        if (extension == ".dll")
        {
            try { _ = AssemblyName.GetAssemblyName(path); return "managed-dll"; }
            catch { return "native-dll"; }
        }
        return extension switch
        {
            ".exe" => "executable",
            ".so" or ".dylib" => "native-library",
            ".pdb" => "debug-symbols",
            ".json" or ".config" or ".xml" => "metadata",
            ".png" or ".jpg" or ".jpeg" or ".gif" or ".webp" or ".ico" => "image",
            ".bin" => "binary-data",
            _ => "other",
        };
    }
}
