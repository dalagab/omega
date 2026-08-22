using System.Runtime.InteropServices;

namespace InterdimensionalRift.Host;

/// <summary>
/// Resolves unmanaged libraries only from the staged plugin artifact tree.
/// In particular, Dalamud packages commonly carry RID-specific assets below
/// runtimes/&lt;rid&gt;/native rather than next to the entry assembly.
/// </summary>
internal static class ArtifactNativeLibraryResolver
{
    public static string? Find(string artifactDirectory, string unmanagedDllName)
    {
        if (string.IsNullOrWhiteSpace(artifactDirectory) || string.IsNullOrWhiteSpace(unmanagedDllName))
            return null;

        var root = Path.GetFullPath(artifactDirectory);
        var requested = Path.GetFileName(unmanagedDllName);
        if (string.IsNullOrWhiteSpace(requested))
            return null;

        var names = CandidateNames(requested).Distinct(StringComparer.Ordinal).ToArray();
        var directories = CandidateDirectories(root).Distinct(StringComparer.Ordinal).ToArray();

        foreach (var directory in directories)
        {
            foreach (var name in names)
            {
                var candidate = Path.GetFullPath(Path.Combine(directory, name));
                if (!IsWithinRoot(root, candidate))
                    continue;
                if (File.Exists(candidate))
                    return candidate;
            }
        }

        return null;
    }

    private static IEnumerable<string> CandidateDirectories(string root)
    {
        // A native binary explicitly placed next to the plugin remains valid.
        yield return root;

        foreach (var rid in CandidateRuntimeIdentifiers())
            yield return Path.Combine(root, "runtimes", rid, "native");
    }

    private static IEnumerable<string> CandidateRuntimeIdentifiers()
    {
        if (!string.IsNullOrWhiteSpace(RuntimeInformation.RuntimeIdentifier))
            yield return RuntimeInformation.RuntimeIdentifier;

        var arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.X86 => "x86",
            Architecture.Arm64 => "arm64",
            Architecture.Arm => "arm",
            _ => RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
        };

        if (OperatingSystem.IsLinux()) yield return $"linux-{arch}";
        else if (OperatingSystem.IsWindows()) yield return $"win-{arch}";
        else if (OperatingSystem.IsMacOS()) yield return $"osx-{arch}";
    }

    private static IEnumerable<string> CandidateNames(string requested)
    {
        if (OperatingSystem.IsLinux())
        {
            var stem = requested.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? Path.GetFileNameWithoutExtension(requested)
                : requested;

            if (stem.EndsWith(".so", StringComparison.Ordinal))
            {
                yield return stem;
                yield break;
            }

            if (!stem.StartsWith("lib", StringComparison.Ordinal))
                yield return $"lib{stem}.so";
            yield return $"{stem}.so";
            yield return stem;
            yield break;
        }

        if (OperatingSystem.IsMacOS())
        {
            var stem = requested.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? Path.GetFileNameWithoutExtension(requested)
                : requested;
            if (stem.EndsWith(".dylib", StringComparison.OrdinalIgnoreCase))
            {
                yield return stem;
                yield break;
            }
            if (!stem.StartsWith("lib", StringComparison.Ordinal))
                yield return $"lib{stem}.dylib";
            yield return $"{stem}.dylib";
            yield return stem;
            yield break;
        }

        if (OperatingSystem.IsWindows())
        {
            yield return requested;
            if (!requested.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                yield return requested + ".dll";
            yield break;
        }

        yield return requested;
    }

    private static bool IsWithinRoot(string root, string candidate)
    {
        var normalizedRoot = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        return candidate.StartsWith(normalizedRoot, StringComparison.Ordinal);
    }
}
