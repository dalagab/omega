using Dalamud.Configuration;

namespace Dalagab.Omega;

[Serializable]
public sealed class Configuration : IPluginConfiguration
{
    public int Version { get; set; } = 9;

    // Persisted source state. Curated identity/name/url are refreshed from the
    // bundled curated-sources.json whenever Omega loads; user-added sources remain editable.
    public List<RepositorySource> Repositories { get; set; } = [];

    public bool PreferTestingBuilds { get; set; }

    // Last completed automatic central-catalog check. Used by the daily update job.
    public DateTimeOffset? LastDailyUpdateCheckUtc { get; set; }

    // Periodic Omega application update state. This is intentionally separate from Definitions updates.
    public DateTimeOffset? LastApplicationUpdateCheckUtc { get; set; }
    public string AvailableApplicationVersion { get; set; } = string.Empty;

    // Repository-risk acknowledgements are keyed to the exact current set of risky source URLs/reasons.
    // A changed risk set produces a fresh warning instead of silently inheriting an old acknowledgement.
    public string AcknowledgedRepositoryRiskFingerprint { get; set; } = string.Empty;

    // First-use EULA acceptance is intentionally independent of the Omega build/version.
    public bool EulaAccepted { get; set; }

    public DateTimeOffset? EulaAcceptedAtUtc { get; set; }

    // One-time migration marker for window geometry written by the retired forced-full-screen build.
    public int WindowGeometryRevision { get; set; }

    public void Save() => Plugin.PluginInterface.SavePluginConfig(this);
}
