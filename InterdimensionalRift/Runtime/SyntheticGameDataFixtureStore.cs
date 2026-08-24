using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Runtime;

/// <summary>
/// Serves only explicitly staged, non-game fixture files through IDataManager.
/// The store is opt-in and never discovers or reads a player's game install.
/// </summary>
public sealed class SyntheticGameDataFixtureStore
{
    private const long MaximumFixtureFileBytes = 16 * 1024 * 1024;
    private readonly string? root;
    private readonly AccessTracker tracker;

    public SyntheticGameDataFixtureStore(AccessTracker tracker)
    {
        this.tracker = tracker;
        var configuredRoot = Environment.GetEnvironmentVariable("RIFT_GAME_DATA_FIXTURE_DIR");
        if (string.IsNullOrWhiteSpace(configuredRoot))
            return;

        var directory = new DirectoryInfo(Path.GetFullPath(configuredRoot));
        if (!directory.Exists || directory.LinkTarget is not null)
            throw new InvalidOperationException("Rift game-data fixture directory is unavailable or resolves through a link.");

        root = directory.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    public bool Contains(string? gamePath) => TryResolve(gamePath, out _);

    public bool TryCreateFileResource(string? gamePath, out object? fileResource)
    {
        fileResource = null;
        if (!TryResolve(gamePath, out var fixturePath))
            return false;

        var data = File.ReadAllBytes(fixturePath);
        var resourceType = DalamudContract.TryResolveTrusted(new AssemblyName("Lumina"))?
            .GetType("Lumina.Data.FileResource", throwOnError: true)
            ?? throw new InvalidOperationException("Frozen Lumina FileResource type was not available.");
        var resource = RuntimeHelpers.GetUninitializedObject(resourceType);
        resourceType.GetProperty("Data", BindingFlags.Instance | BindingFlags.Public)!
            .GetSetMethod(nonPublic: true)!
            .Invoke(resource, new object?[] { data });

        var sha256 = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
        tracker.Record(RuntimeObservationKind.ServiceAccess, "IDataManager", "GetFile", "synthetic_fixture",
            message: gamePath,
            parameters: new Dictionary<string, string?>
            {
                ["game_path"] = gamePath,
                ["fixture_sha256"] = sha256,
                ["bytes"] = data.Length.ToString(),
                ["real_game_data"] = "false",
                ["fixture_tree_sha256"] = Environment.GetEnvironmentVariable("RIFT_GAME_DATA_FIXTURE_TREE_SHA256"),
            });
        fileResource = resource;
        return true;
    }

    private bool TryResolve(string? gamePath, out string fixturePath)
    {
        fixturePath = string.Empty;
        if (root is null || string.IsNullOrWhiteSpace(gamePath))
            return false;

        var normalized = gamePath.Replace('\\', '/').TrimStart('/');
        if (normalized.Length == 0 || Path.IsPathRooted(gamePath) ||
            normalized.Split('/', StringSplitOptions.None).Any(segment => segment is "" or "." or ".."))
            return false;

        var candidate = Path.GetFullPath(Path.Combine(root, normalized.Replace('/', Path.DirectorySeparatorChar)));
        if (!candidate.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
            !File.Exists(candidate))
            return false;

        var file = new FileInfo(candidate);
        if (file.LinkTarget is not null || file.Length > MaximumFixtureFileBytes)
            return false;

        fixturePath = candidate;
        return true;
    }
}
