using System.Text.Json;

namespace Dalagab.Omega;

/// <summary>
/// Tracks when Omega first observed each plugin so Spotlight can distinguish newly added plugins
/// from merely updated ones. The initial baseline uses the manifest LastUpdate timestamp when
/// available because standard Dalamud manifests do not expose a creation timestamp.
/// </summary>
internal sealed class PluginRecencyLedger
{
    private sealed class LedgerDocument
    {
        public int SchemaVersion { get; set; } = 1;
        public Dictionary<string, long> FirstSeenUnix { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private readonly string path;
    private readonly object sync = new();
    private readonly Dictionary<string, long> firstSeenUnix;

    public PluginRecencyLedger(string configurationDirectory)
    {
        path = Path.Combine(configurationDirectory, "plugin-recency.json");
        firstSeenUnix = Load(path);
    }

    public void Observe(IEnumerable<MarketplacePlugin> plugins)
    {
        lock (sync)
        {
            var snapshot = plugins
                .Where(x => !string.IsNullOrWhiteSpace(x.InternalName))
                .GroupBy(x => x.InternalName, StringComparer.OrdinalIgnoreCase)
                .Select(x => x.OrderByDescending(p => NormalizeUnix(p.LastUpdate)).First())
                .ToArray();
            if (snapshot.Length == 0)
                return;

            var baseline = firstSeenUnix.Count == 0;
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var changed = false;
            foreach (var plugin in snapshot)
            {
                if (firstSeenUnix.ContainsKey(plugin.InternalName))
                    continue;

                var manifestDate = NormalizeUnix(plugin.LastUpdate);
                firstSeenUnix[plugin.InternalName] = baseline && manifestDate > 0 ? manifestDate : now;
                changed = true;
            }

            if (changed)
                Save();
        }
    }

    public long GetFirstSeenUnix(string internalName)
    {
        lock (sync)
            return firstSeenUnix.TryGetValue(internalName, out var value) ? value : 0;
    }

    public static long NormalizeUnix(long value)
    {
        if (value <= 0)
            return 0;
        return value > 100_000_000_000L ? value / 1000L : value;
    }

    private static Dictionary<string, long> Load(string path)
    {
        try
        {
            if (!File.Exists(path))
                return new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);

            var document = JsonSerializer.Deserialize<LedgerDocument>(File.ReadAllText(path));
            if (document?.SchemaVersion != 1 || document.FirstSeenUnix is null)
                return new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);

            return new Dictionary<string, long>(document.FirstSeenUnix, StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private void Save()
    {
        var directory = Path.GetDirectoryName(path) ?? ".";
        Directory.CreateDirectory(directory);
        var temp = path + ".tmp";
        var json = JsonSerializer.Serialize(new LedgerDocument
        {
            FirstSeenUnix = new Dictionary<string, long>(firstSeenUnix, StringComparer.OrdinalIgnoreCase),
        });
        File.WriteAllText(temp, json);
        File.Move(temp, path, overwrite: true);
    }
}
