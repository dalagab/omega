using Dalamud.Configuration;

namespace Dalagab.Omega;

[Serializable]
public sealed class Configuration : IPluginConfiguration
{
    public int Version { get; set; } = 7;

    // Persisted source state. Curated identity/name/url are refreshed from the
    // bundled curated-sources.json whenever Omega loads; user-added sources remain editable.
    public List<RepositorySource> Repositories { get; set; } = [];

    public bool PreferTestingBuilds { get; set; }

    // Last completed automatic full-source conditional check. Used by the daily update job.
    public DateTimeOffset? LastDailyUpdateCheckUtc { get; set; }

    public void Save() => Plugin.PluginInterface.SavePluginConfig(this);
}
