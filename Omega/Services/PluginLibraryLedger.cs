using System.Text.Json;

namespace Dalagab.Omega;

internal sealed record PluginInstallStamp(DateTimeOffset TimestampUtc, bool ExactInstallTime);

/// <summary>
/// Persists user-local Library metadata that Dalamud does not expose, primarily installation timing.
/// Existing plugins are recorded as first-seen until Omega observes a later install transition.
/// </summary>
internal sealed class PluginLibraryLedger
{
    private sealed class LedgerEntry
    {
        public DateTimeOffset FirstSeenUtc { get; set; }
        public DateTimeOffset? InstalledAtUtc { get; set; }
    }

    private sealed class LedgerDocument
    {
        public int SchemaVersion { get; set; } = 1;
        public Dictionary<string, LedgerEntry> Plugins { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private readonly string path;
    private readonly object sync = new();
    private readonly Dictionary<string, LedgerEntry> entries;
    private HashSet<string> previousInstalled = new(StringComparer.OrdinalIgnoreCase);
    private bool hasBaseline;

    public PluginLibraryLedger(string configurationDirectory)
    {
        path = Path.Combine(configurationDirectory, "library-metadata.json");
        entries = Load(path);
    }

    public void ObserveInstalled(IEnumerable<string> internalNames, DateTimeOffset? observedAtUtc = null)
    {
        var now = observedAtUtc ?? DateTimeOffset.UtcNow;
        var snapshot = internalNames
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        lock (sync)
        {
            var changed = false;
            foreach (var internalName in snapshot)
            {
                if (!entries.TryGetValue(internalName, out var entry))
                {
                    entries[internalName] = new LedgerEntry { FirstSeenUtc = now };
                    changed = true;
                    continue;
                }

                if (hasBaseline && !previousInstalled.Contains(internalName))
                {
                    entry.InstalledAtUtc = now;
                    changed = true;
                }
            }

            previousInstalled = snapshot;
            hasBaseline = true;
            if (changed)
                Save();
        }
    }

    public void MarkInstalled(string internalName, DateTimeOffset? installedAtUtc = null)
    {
        if (string.IsNullOrWhiteSpace(internalName))
            return;

        var now = installedAtUtc ?? DateTimeOffset.UtcNow;
        lock (sync)
        {
            if (!entries.TryGetValue(internalName, out var entry))
            {
                entry = new LedgerEntry { FirstSeenUtc = now };
                entries[internalName] = entry;
            }

            entry.InstalledAtUtc = now;
            previousInstalled.Add(internalName);
            Save();
        }
    }

    public PluginInstallStamp? GetInstallStamp(string internalName)
    {
        lock (sync)
        {
            if (!entries.TryGetValue(internalName, out var entry))
                return null;

            return entry.InstalledAtUtc is { } installed
                ? new PluginInstallStamp(installed, true)
                : new PluginInstallStamp(entry.FirstSeenUtc, false);
        }
    }

    private static Dictionary<string, LedgerEntry> Load(string path)
    {
        try
        {
            if (!File.Exists(path))
                return new Dictionary<string, LedgerEntry>(StringComparer.OrdinalIgnoreCase);

            var document = JsonSerializer.Deserialize<LedgerDocument>(File.ReadAllText(path));
            if (document?.SchemaVersion != 1 || document.Plugins is null)
                return new Dictionary<string, LedgerEntry>(StringComparer.OrdinalIgnoreCase);

            return new Dictionary<string, LedgerEntry>(document.Plugins, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not read its Library metadata ledger.");
            return new Dictionary<string, LedgerEntry>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private void Save()
    {
        try
        {
            var directory = Path.GetDirectoryName(path) ?? ".";
            Directory.CreateDirectory(directory);
            var temp = path + ".tmp";
            var json = JsonSerializer.Serialize(new LedgerDocument
            {
                Plugins = new Dictionary<string, LedgerEntry>(entries, StringComparer.OrdinalIgnoreCase),
            });
            File.WriteAllText(temp, json);
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex)
        {
            Plugin.Log.Warning(ex, "Omega could not save its Library metadata ledger.");
        }
    }
}
