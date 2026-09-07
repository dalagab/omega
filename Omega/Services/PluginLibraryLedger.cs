using System.Text.Json;

namespace Dalagab.Omega;

internal sealed record PluginInstallStamp(DateTimeOffset TimestampUtc, bool ExactInstallTime);

internal enum PluginInstallOwnershipKind
{
    Manual,
    Dependency,
}

internal sealed record PluginInstallOwnership(
    PluginInstallOwnershipKind Kind,
    IReadOnlySet<string> RequestedBy)
{
    public bool IsDependencyOwned => Kind == PluginInstallOwnershipKind.Dependency;
    public bool IsOrphan => IsDependencyOwned && RequestedBy.Count == 0;
}

/// <summary>
/// Persists user-local Library metadata that Dalamud does not expose: installation timing and
/// package-manager ownership. Existing/externally installed plugins always default to Manual so
/// Omega can never autoremove a plugin it did not itself introduce as a dependency.
/// </summary>
internal sealed class PluginLibraryLedger
{
    private sealed class LedgerEntry
    {
        public DateTimeOffset FirstSeenUtc { get; set; }
        public DateTimeOffset? InstalledAtUtc { get; set; }
        public string InstallReason { get; set; } = "manual";
        public HashSet<string> RequestedBy { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class LedgerDocument
    {
        public int SchemaVersion { get; set; } = 2;
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
                    // Unknown pre-existing or externally installed plugins are manual by default.
                    entries[internalName] = NewManualEntry(now);
                    changed = true;
                    continue;
                }

                if (hasBaseline && !previousInstalled.Contains(internalName) && entry.InstalledAtUtc is null)
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

    /// <summary>Marks a direct user install/claim. Manual ownership is sticky and is never demoted.</summary>
    public void MarkManualInstalled(string internalName, DateTimeOffset? installedAtUtc = null)
    {
        if (string.IsNullOrWhiteSpace(internalName))
            return;
        var now = installedAtUtc ?? DateTimeOffset.UtcNow;
        lock (sync)
        {
            var entry = GetOrCreate(internalName, now);
            entry.InstalledAtUtc = now;
            entry.InstallReason = "manual";
            entry.RequestedBy.Clear();
            previousInstalled.Add(internalName);
            Save();
        }
    }

    /// <summary>
    /// Records a dependency introduced by an Omega transaction. A plugin that is already manual
    /// remains manual; dependency roots are only attached to dependency-owned entries.
    /// </summary>
    public void MarkDependencyInstalled(
        string internalName,
        string requestedByRoot,
        DateTimeOffset? installedAtUtc = null)
    {
        if (string.IsNullOrWhiteSpace(internalName))
            return;
        var now = installedAtUtc ?? DateTimeOffset.UtcNow;
        lock (sync)
        {
            var existed = entries.TryGetValue(internalName, out var entry);
            entry ??= GetOrCreate(internalName, now);
            entry.InstalledAtUtc ??= now;

            // If Omega already knew this plugin before the transaction, treat it conservatively as
            // user-owned unless it was explicitly dependency-owned by an earlier transaction.
            if (!existed)
                entry.InstallReason = "dependency";
            if (entry.InstallReason.Equals("dependency", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(requestedByRoot))
            {
                entry.RequestedBy.Add(requestedByRoot);
            }
            previousInstalled.Add(internalName);
            Save();
        }
    }

    /// <summary>Add another root owner to an already dependency-owned provider without demoting manual installs.</summary>
    public void AddDependencyRequester(string internalName, string requestedByRoot)
    {
        if (string.IsNullOrWhiteSpace(internalName) || string.IsNullOrWhiteSpace(requestedByRoot))
            return;
        lock (sync)
        {
            if (!entries.TryGetValue(internalName, out var entry) ||
                !entry.InstallReason.Equals("dependency", StringComparison.OrdinalIgnoreCase))
                return;
            if (entry.RequestedBy.Add(requestedByRoot))
                Save();
        }
    }

    /// <summary>Explicitly promotes an auto dependency to a direct/manual install.</summary>
    public bool PromoteToManual(string internalName)
    {
        if (string.IsNullOrWhiteSpace(internalName))
            return false;
        lock (sync)
        {
            if (!entries.TryGetValue(internalName, out var entry) ||
                entry.InstallReason.Equals("manual", StringComparison.OrdinalIgnoreCase))
                return false;
            entry.InstallReason = "manual";
            entry.RequestedBy.Clear();
            Save();
            return true;
        }
    }

    /// <summary>Removes a root ownership edge after that direct/root plugin is removed.</summary>
    public void MarkRootRemoved(string rootInternalName)
    {
        if (string.IsNullOrWhiteSpace(rootInternalName))
            return;
        lock (sync)
        {
            var changed = false;
            foreach (var entry in entries.Values)
            {
                if (entry.InstallReason.Equals("dependency", StringComparison.OrdinalIgnoreCase))
                    changed |= entry.RequestedBy.Remove(rootInternalName);
            }
            if (changed)
                Save();
        }
    }

    /// <summary>
    /// Reconciles one successfully installed/updated root against its newly resolved dependency
    /// closure. This both adds current ownership edges and releases dependencies the new root no
    /// longer requires, without ever changing manual ownership.
    /// </summary>
    public void ReconcileRootDependencies(string rootInternalName, IEnumerable<string> dependencyInternalNames)
    {
        if (string.IsNullOrWhiteSpace(rootInternalName))
            return;
        var desired = dependencyInternalNames
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        lock (sync)
        {
            var changed = false;
            foreach (var pair in entries)
            {
                var entry = pair.Value;
                if (!entry.InstallReason.Equals("dependency", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (desired.Contains(pair.Key))
                    changed |= entry.RequestedBy.Add(rootInternalName);
                else
                    changed |= entry.RequestedBy.Remove(rootInternalName);
            }
            if (changed)
                Save();
        }
    }

    public void ForgetRemoved(string internalName)
    {
        if (string.IsNullOrWhiteSpace(internalName))
            return;
        lock (sync)
        {
            previousInstalled.Remove(internalName);
            // Keep timing/manual history for ordinary manual installs. Dependency ownership is
            // specific to the removed installation; a future external reinstall must default to
            // manual unless a new Omega dependency transaction reserves it again.
            if (entries.TryGetValue(internalName, out var entry) &&
                entry.InstallReason.Equals("dependency", StringComparison.OrdinalIgnoreCase))
            {
                entries.Remove(internalName);
                Save();
            }
        }
    }

    public void ForgetAutoDependency(string internalName)
    {
        if (string.IsNullOrWhiteSpace(internalName))
            return;
        lock (sync)
        {
            previousInstalled.Remove(internalName);
            if (entries.TryGetValue(internalName, out var entry) &&
                entry.InstallReason.Equals("dependency", StringComparison.OrdinalIgnoreCase))
            {
                entries.Remove(internalName);
                Save();
            }
        }
    }

    public PluginInstallOwnership GetOwnership(string internalName)
    {
        lock (sync)
        {
            if (!entries.TryGetValue(internalName, out var entry))
                return new PluginInstallOwnership(PluginInstallOwnershipKind.Manual, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            return new PluginInstallOwnership(
                entry.InstallReason.Equals("dependency", StringComparison.OrdinalIgnoreCase)
                    ? PluginInstallOwnershipKind.Dependency
                    : PluginInstallOwnershipKind.Manual,
                entry.RequestedBy.ToHashSet(StringComparer.OrdinalIgnoreCase));
        }
    }

    public IReadOnlyList<string> GetDependencyOwnedOrphans(IEnumerable<string> installedInternalNames)
    {
        var installed = installedInternalNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        lock (sync)
        {
            return entries
                .Where(pair => installed.Contains(pair.Key) &&
                               pair.Value.InstallReason.Equals("dependency", StringComparison.OrdinalIgnoreCase) &&
                               pair.Value.RequestedBy.Count == 0)
                .Select(pair => pair.Key)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
    }

    // Backward-compatible alias retained for existing UI/regression contracts.
    public void MarkInstalled(string internalName, DateTimeOffset? installedAtUtc = null)
        => MarkManualInstalled(internalName, installedAtUtc);

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

    private LedgerEntry GetOrCreate(string internalName, DateTimeOffset now)
    {
        if (entries.TryGetValue(internalName, out var entry))
            return entry;
        entry = NewManualEntry(now);
        entries[internalName] = entry;
        return entry;
    }

    private static LedgerEntry NewManualEntry(DateTimeOffset now)
        => new()
        {
            FirstSeenUtc = now,
            InstallReason = "manual",
            RequestedBy = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        };

    private static Dictionary<string, LedgerEntry> Load(string path)
    {
        try
        {
            if (!File.Exists(path))
                return new Dictionary<string, LedgerEntry>(StringComparer.OrdinalIgnoreCase);

            using var documentJson = JsonDocument.Parse(File.ReadAllText(path));
            var root = documentJson.RootElement;
            var schema = root.TryGetProperty("SchemaVersion", out var schemaNode) && schemaNode.TryGetInt32(out var parsedSchema)
                ? parsedSchema
                : 1;

            var document = JsonSerializer.Deserialize<LedgerDocument>(root.GetRawText());
            if (document?.Plugins is null)
                return new Dictionary<string, LedgerEntry>(StringComparer.OrdinalIgnoreCase);

            var result = new Dictionary<string, LedgerEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var pair in document.Plugins)
            {
                pair.Value.RequestedBy = pair.Value.RequestedBy is null
                    ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    : pair.Value.RequestedBy.ToHashSet(StringComparer.OrdinalIgnoreCase);
                if (schema < 2 || string.IsNullOrWhiteSpace(pair.Value.InstallReason))
                {
                    // Schema 1 had no ownership concept. Existing entries must be manual so an
                    // upgrade can never turn historical user installs into autoremove candidates.
                    pair.Value.InstallReason = "manual";
                    pair.Value.RequestedBy.Clear();
                }
                result[pair.Key] = pair.Value;
            }
            return result;
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
