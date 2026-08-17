using System.IO.Compression;
using System.Text.Json;

namespace Dalagab.Omega;

internal sealed record PluginConfigBackupResult(
    bool Success,
    string Message,
    string? BackupPath = null,
    string? BackupDirectory = null);

internal sealed record PluginConfigBackupInspection(
    bool Success,
    string Message,
    string InternalName = "",
    string DisplayName = "",
    int FileCount = 0,
    long UncompressedBytes = 0);

internal sealed record PluginConfigImportResult(
    bool Success,
    string Message,
    string InternalName = "",
    string? SafetyBackupPath = null);

internal sealed record PluginConfigBackupManifest(
    string Schema,
    string InternalName,
    string DisplayName,
    string CreatedAtUtc);

/// <summary>
/// Creates and restores user-requested ZIP backups of a plugin's Dalamud-managed JSON
/// configuration and auxiliary configuration directory without interpreting plugin data.
/// Backups are intentionally temporary and are written below the operating-system temp directory.
/// </summary>
internal sealed class PluginConfigBackupService
{
    private const string BackupSchema = "omega.plugin-config-backup.v1";
    private const int MaximumEntries = 4096;
    private const long MaximumUncompressedBytes = 128L * 1024L * 1024L;

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
        if (!IsSafeInternalName(internalName))
            return new PluginConfigBackupResult(false, "Plugin identity is unavailable.");

        try
        {
            var configFile = Path.Combine(pluginConfigRoot, $"{internalName}.json");
            var configDirectory = Path.Combine(pluginConfigRoot, internalName);
            if (!File.Exists(configFile) && !Directory.Exists(configDirectory))
                return new PluginConfigBackupResult(false, $"{displayName} does not currently have configuration files to back up.");

            Directory.CreateDirectory(backupRoot);
            var createdAt = timestampUtc ?? DateTimeOffset.UtcNow;
            var stamp = createdAt.ToString("yyyyMMdd-HHmmss");
            var safeName = SanitizeFileName(internalName);
            var destination = UniqueDestination(Path.Combine(backupRoot, $"{safeName}-{stamp}.zip"));
            var temp = destination + ".tmp";

            var fileCount = 0;
            using (var archive = ZipFile.Open(temp, ZipArchiveMode.Create))
            {
                var manifest = new PluginConfigBackupManifest(
                    BackupSchema,
                    internalName,
                    string.IsNullOrWhiteSpace(displayName) ? internalName : displayName,
                    createdAt.ToString("O"));
                var manifestEntry = archive.CreateEntry("omega-backup.json", CompressionLevel.Optimal);
                using (var writer = new StreamWriter(manifestEntry.Open()))
                    writer.Write(JsonSerializer.Serialize(manifest));

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

    public PluginConfigBackupInspection Inspect(string archivePath, IReadOnlyCollection<string> installedInternalNames)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(archivePath) || !File.Exists(archivePath))
                return new(false, "The selected backup file no longer exists.");
            if (!Path.GetExtension(archivePath).Equals(".zip", StringComparison.OrdinalIgnoreCase))
                return new(false, "Omega configuration backups must be ZIP files.");

            using var archive = ZipFile.OpenRead(archivePath);
            var validation = ValidateArchive(archive);
            if (!validation.Success)
                return validation;

            var internalName = ReadManifestIdentity(archive, out var displayName);
            if (string.IsNullOrWhiteSpace(internalName))
                internalName = InferLegacyIdentity(archive);
            if (!IsSafeInternalName(internalName))
                return new(false, "This ZIP does not contain an identifiable Omega plugin configuration backup.");
            if (!installedInternalNames.Contains(internalName, StringComparer.OrdinalIgnoreCase))
                return new(false, $"{displayNameOrInternal(displayName, internalName)} is not currently installed. Omega only restores configuration for installed plugins.", internalName, displayName);

            var dataEntries = archive.Entries.Count(IsConfigDataEntry);
            return new(
                true,
                $"Ready to restore {displayNameOrInternal(displayName, internalName)} configuration from {dataEntries} file{(dataEntries == 1 ? string.Empty : "s")}. Current configuration will be safety-backed up first.",
                internalName,
                displayNameOrInternal(displayName, internalName),
                dataEntries,
                archive.Entries.Where(IsConfigDataEntry).Sum(x => x.Length));
        }
        catch (InvalidDataException ex)
        {
            return new(false, $"The selected ZIP is not a valid Omega configuration backup: {ex.Message}");
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not inspect configuration backup {Backup}", archivePath);
            return new(false, $"Could not inspect this configuration backup: {ex.GetBaseException().Message}");
        }
    }

    public PluginConfigImportResult Restore(string archivePath, PluginConfigBackupInspection inspection)
    {
        if (!inspection.Success || !IsSafeInternalName(inspection.InternalName))
            return new(false, "The selected backup has not passed Omega validation.");

        var internalName = inspection.InternalName;
        var displayName = displayNameOrInternal(inspection.DisplayName, internalName);
        try
        {
            using var archive = ZipFile.OpenRead(archivePath);
            var revalidation = ValidateArchive(archive);
            if (!revalidation.Success)
                return new(false, revalidation.Message, internalName);
            var archiveIdentity = ReadManifestIdentity(archive, out _);
            if (string.IsNullOrWhiteSpace(archiveIdentity))
                archiveIdentity = InferLegacyIdentity(archive);
            if (!internalName.Equals(archiveIdentity, StringComparison.OrdinalIgnoreCase))
                return new(false, "The backup identity changed after it was selected. Import was canceled.", internalName);

            // A restore is destructive. Preserve the current state first whenever it exists and
            // fail closed if that safety copy cannot be created.
            var currentConfigFile = Path.Combine(pluginConfigRoot, $"{internalName}.json");
            var currentConfigDirectory = Path.Combine(pluginConfigRoot, internalName);
            var hasCurrentConfig = File.Exists(currentConfigFile) || Directory.Exists(currentConfigDirectory);
            var safety = Backup(internalName, displayName);
            if (hasCurrentConfig && !safety.Success)
                return new(false, $"Could not safety-back up the current {displayName} configuration, so import was canceled: {safety.Message}", internalName);

            var staging = Path.Combine(backupRoot, "import-staging", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(staging);
            try
            {
                ExtractConfigData(archive, staging, internalName);
                ApplyStagedConfig(staging, internalName);
            }
            finally
            {
                try { Directory.Delete(staging, recursive: true); } catch { }
            }

            var safetyNote = safety.Success && !string.IsNullOrWhiteSpace(safety.BackupPath)
                ? " Previous configuration was safety-backed up in Omega's temporary backup folder."
                : string.Empty;
            return new(
                true,
                $"Imported {displayName} configuration. Reload the plugin or restart the game if it does not reread configuration automatically.{safetyNote}",
                internalName,
                safety.Success ? safety.BackupPath : null);
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not restore configuration backup for {Plugin}", internalName);
            return new(false, $"Could not import {displayName} configuration: {ex.GetBaseException().Message}", internalName);
        }
    }

    private static PluginConfigBackupInspection ValidateArchive(ZipArchive archive)
    {
        if (archive.Entries.Count > MaximumEntries)
            return new(false, $"Backup contains too many entries ({archive.Entries.Count:N0}).");

        long total = 0;
        foreach (var entry in archive.Entries)
        {
            if (entry.FullName.EndsWith('/'))
                continue;
            if (!IsAllowedEntry(entry.FullName))
                return new(false, $"Backup contains an unexpected entry: {entry.FullName}");
            total += entry.Length;
            if (total > MaximumUncompressedBytes)
                return new(false, "Backup expands beyond Omega's 128 MiB configuration safety limit.");
        }

        if (!archive.Entries.Any(IsConfigDataEntry))
            return new(false, "Backup does not contain plugin configuration data.");
        return new(true, "Backup structure is valid.", UncompressedBytes: total);
    }

    private static bool IsAllowedEntry(string name)
    {
        var normalized = name.Replace('\\', '/');
        if (string.IsNullOrWhiteSpace(normalized) || normalized.StartsWith('/') || normalized.Contains(":", StringComparison.Ordinal) || normalized.Contains('\0'))
            return false;
        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Any(segment => segment is "." or ".."))
            return false;
        return normalized.Equals("omega-backup.json", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("config/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("config-directory/", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsConfigDataEntry(ZipArchiveEntry entry)
    {
        if (entry.FullName.EndsWith('/'))
            return false;
        var normalized = entry.FullName.Replace('\\', '/');
        return normalized.StartsWith("config/", StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith("config-directory/", StringComparison.OrdinalIgnoreCase);
    }

    private static string ReadManifestIdentity(ZipArchive archive, out string displayName)
    {
        displayName = string.Empty;
        var entry = archive.Entries.FirstOrDefault(x => x.FullName.Equals("omega-backup.json", StringComparison.OrdinalIgnoreCase));
        if (entry is null)
            return string.Empty;
        using var reader = new StreamReader(entry.Open());
        var manifest = JsonSerializer.Deserialize<PluginConfigBackupManifest>(reader.ReadToEnd());
        if (manifest is null || !BackupSchema.Equals(manifest.Schema, StringComparison.Ordinal))
            return string.Empty;
        displayName = manifest.DisplayName ?? string.Empty;
        return manifest.InternalName ?? string.Empty;
    }

    private static string InferLegacyIdentity(ZipArchive archive)
    {
        var candidates = archive.Entries
            .Where(entry => !entry.FullName.EndsWith('/'))
            .Select(entry => entry.FullName.Replace('\\', '/'))
            .Where(name => name.StartsWith("config/", StringComparison.OrdinalIgnoreCase))
            .Select(name => name["config/".Length..])
            .Where(name => !name.Contains('/') && name.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            .Select(Path.GetFileNameWithoutExtension)
            .OfType<string>()
            .Where(IsSafeInternalName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return candidates.Length == 1 ? candidates[0] : string.Empty;
    }

    private static void ExtractConfigData(ZipArchive archive, string staging, string internalName)
    {
        foreach (var entry in archive.Entries.Where(IsConfigDataEntry))
        {
            var normalized = entry.FullName.Replace('\\', '/');
            string relative;
            if (normalized.StartsWith("config/", StringComparison.OrdinalIgnoreCase))
            {
                relative = normalized["config/".Length..];
                if (!relative.Equals($"{internalName}.json", StringComparison.OrdinalIgnoreCase) || relative.Contains('/'))
                    throw new InvalidDataException("The backup config filename does not match the plugin identity.");
                relative = Path.Combine("config", $"{internalName}.json");
            }
            else
            {
                relative = normalized["config-directory/".Length..];
                if (string.IsNullOrWhiteSpace(relative))
                    continue;
                relative = Path.Combine("config-directory", relative.Replace('/', Path.DirectorySeparatorChar));
            }

            var target = Path.GetFullPath(Path.Combine(staging, relative));
            var stagingRoot = Path.GetFullPath(staging) + Path.DirectorySeparatorChar;
            if (!target.StartsWith(stagingRoot, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Backup entry escapes the staging directory.");
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            using var source = entry.Open();
            using var destination = File.Create(target);
            source.CopyTo(destination);
        }
    }

    private void ApplyStagedConfig(string staging, string internalName)
    {
        var stagedFile = Path.Combine(staging, "config", $"{internalName}.json");
        var stagedDirectory = Path.Combine(staging, "config-directory");
        var targetFile = Path.Combine(pluginConfigRoot, $"{internalName}.json");
        var targetDirectory = Path.Combine(pluginConfigRoot, internalName);

        if (File.Exists(stagedFile))
        {
            var temporaryTarget = targetFile + $".omega-import-{Guid.NewGuid():N}";
            File.Copy(stagedFile, temporaryTarget, overwrite: true);
            File.Move(temporaryTarget, targetFile, overwrite: true);
        }

        if (Directory.Exists(stagedDirectory))
        {
            if (Directory.Exists(targetDirectory))
                Directory.Delete(targetDirectory, recursive: true);
            CopyDirectory(stagedDirectory, targetDirectory);
        }
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(Path.Combine(destination, Path.GetRelativePath(source, directory)));
        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            var target = Path.Combine(destination, Path.GetRelativePath(source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }
    }

    private static bool IsSafeInternalName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 160)
            return false;
        if (value is "." or ".." || value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            return false;
        return !value.Contains(Path.DirectorySeparatorChar) && !value.Contains(Path.AltDirectorySeparatorChar);
    }

    private static string displayNameOrInternal(string? displayName, string internalName)
        => string.IsNullOrWhiteSpace(displayName) ? internalName : displayName;

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
