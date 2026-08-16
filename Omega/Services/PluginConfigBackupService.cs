using System.IO.Compression;

namespace Dalagab.Omega;

internal sealed record PluginConfigBackupResult(
    bool Success,
    string Message,
    string? BackupPath = null,
    string? BackupDirectory = null);

/// <summary>
/// Creates user-requested ZIP backups of a plugin's Dalamud-managed JSON configuration and
/// auxiliary configuration directory without interpreting or modifying plugin data. Backups are
/// intentionally temporary and are written below the operating-system temp directory.
/// </summary>
internal sealed class PluginConfigBackupService
{
    private readonly string pluginConfigRoot;
    private readonly string backupRoot;

    public PluginConfigBackupService(string omegaConfigFilePath)
    {
        pluginConfigRoot = Path.GetDirectoryName(omegaConfigFilePath)
            ?? throw new InvalidOperationException("Dalamud plugin configuration root is unavailable.");
        backupRoot = Path.Combine(Path.GetTempPath(), "Dalagab", "Omega", "config-backups");
    }

    public string BackupRoot => backupRoot;

    public PluginConfigBackupResult Backup(string internalName, string displayName, DateTimeOffset? timestampUtc = null)
    {
        if (string.IsNullOrWhiteSpace(internalName))
            return new PluginConfigBackupResult(false, "Plugin identity is unavailable.");

        try
        {
            var configFile = Path.Combine(pluginConfigRoot, $"{internalName}.json");
            var configDirectory = Path.Combine(pluginConfigRoot, internalName);
            if (!File.Exists(configFile) && !Directory.Exists(configDirectory))
                return new PluginConfigBackupResult(false, $"{displayName} does not currently have configuration files to back up.");

            Directory.CreateDirectory(backupRoot);
            var stamp = (timestampUtc ?? DateTimeOffset.UtcNow).ToString("yyyyMMdd-HHmmss");
            var safeName = SanitizeFileName(internalName);
            var destination = UniqueDestination(Path.Combine(backupRoot, $"{safeName}-{stamp}.zip"));
            var temp = destination + ".tmp";

            var fileCount = 0;
            using (var archive = ZipFile.Open(temp, ZipArchiveMode.Create))
            {
                if (File.Exists(configFile))
                {
                    archive.CreateEntryFromFile(configFile, $"config/{Path.GetFileName(configFile)}", CompressionLevel.Optimal);
                    fileCount++;
                }

                if (Directory.Exists(configDirectory))
                {
                    foreach (var file in Directory.EnumerateFiles(configDirectory, "*", SearchOption.AllDirectories))
                    {
                        var relative = Path.GetRelativePath(configDirectory, file);
                        archive.CreateEntryFromFile(file, $"config-directory/{relative.Replace('\\', '/')}", CompressionLevel.Optimal);
                        fileCount++;
                    }
                }
            }

            File.Move(temp, destination, overwrite: false);
            return new PluginConfigBackupResult(
                true,
                $"Backed up {displayName} configuration ({fileCount} file{(fileCount == 1 ? string.Empty : "s")}).",
                destination,
                backupRoot);
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not back up configuration for {Plugin}", internalName);
            return new PluginConfigBackupResult(false, $"Could not back up {displayName}: {ex.GetBaseException().Message}");
        }
    }

    private static string UniqueDestination(string path)
    {
        if (!File.Exists(path))
            return path;

        var directory = Path.GetDirectoryName(path) ?? ".";
        var stem = Path.GetFileNameWithoutExtension(path);
        for (var suffix = 2; suffix < 1000; suffix++)
        {
            var candidate = Path.Combine(directory, $"{stem}-{suffix}.zip");
            if (!File.Exists(candidate))
                return candidate;
        }

        throw new IOException("Could not allocate a unique backup file name.");
    }

    private static string SanitizeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars().ToHashSet();
        var cleaned = new string(value.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray()).Trim();
        return string.IsNullOrWhiteSpace(cleaned) ? "plugin" : cleaned;
    }
}
