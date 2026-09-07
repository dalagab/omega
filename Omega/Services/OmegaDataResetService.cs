namespace Dalagab.Omega;

/// <summary>
/// Implements a true local first-install reset without trying to delete SQLite/config files while
/// the running Omega instance may still have them open. Settings writes a tiny marker; the next
/// plugin construction removes Omega-owned local state before configuration/catalog services open.
/// Dalamud repository registrations and third-party plugin configuration are deliberately outside
/// this boundary and are never removed here.
/// </summary>
internal static class OmegaDataResetService
{
    private const string ResetMarkerFileName = ".omega-reset-requested";

    public static bool IsRequested(string configurationDirectory)
        => File.Exists(Path.Combine(configurationDirectory, ResetMarkerFileName));

    public static void Request(string configurationDirectory)
    {
        Directory.CreateDirectory(configurationDirectory);
        File.WriteAllText(
            Path.Combine(configurationDirectory, ResetMarkerFileName),
            DateTimeOffset.UtcNow.ToString("O"));
    }

    public static void ApplyPendingReset(string configurationDirectory, string configurationFilePath)
    {
        var markerPath = Path.Combine(configurationDirectory, ResetMarkerFileName);
        if (!File.Exists(markerPath))
            return;

        var failures = new List<string>();
        try
        {
            if (Directory.Exists(configurationDirectory))
            {
                foreach (var file in Directory.EnumerateFiles(configurationDirectory, "*", SearchOption.TopDirectoryOnly))
                {
                    if (Path.GetFullPath(file).Equals(Path.GetFullPath(markerPath), StringComparison.OrdinalIgnoreCase))
                        continue;
                    TryDeleteFile(file, failures);
                }

                foreach (var directory in Directory.EnumerateDirectories(configurationDirectory, "*", SearchOption.TopDirectoryOnly))
                    TryDeleteDirectory(directory, failures);
            }

            if (!string.IsNullOrWhiteSpace(configurationFilePath) &&
                File.Exists(configurationFilePath) &&
                !IsWithinDirectory(configurationFilePath, configurationDirectory))
            {
                TryDeleteFile(configurationFilePath, failures);
            }

            var tempRoot = Path.Combine(Path.GetTempPath(), "Dalagab", "Omega");
            if (Directory.Exists(tempRoot))
                TryDeleteDirectory(tempRoot, failures);

            if (failures.Count == 0)
            {
                File.Delete(markerPath);
                return;
            }
        }
        catch (Exception ex)
        {
            failures.Add(ex.GetBaseException().Message);
        }

        Plugin.Log.Warning(
            "Omega local-data reset could not remove every item and will retry on the next reload: {Failures}",
            string.Join(" | ", failures.Take(8)));
    }

    private static bool IsWithinDirectory(string path, string directory)
    {
        var fullPath = Path.GetFullPath(path);
        var fullDirectory = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                            + Path.DirectorySeparatorChar;
        return fullPath.StartsWith(fullDirectory, StringComparison.OrdinalIgnoreCase);
    }

    private static void TryDeleteFile(string path, List<string> failures)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex)
        {
            failures.Add($"{Path.GetFileName(path)}: {ex.GetBaseException().Message}");
        }
    }

    private static void TryDeleteDirectory(string path, List<string> failures)
    {
        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (Exception ex)
        {
            failures.Add($"{Path.GetFileName(path)}: {ex.GetBaseException().Message}");
        }
    }
}
