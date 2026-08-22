using Dalamud.Configuration;

namespace Dalagab.Omega;

public enum DiscoverLayoutMode
{
    Dynamic,
    CompactCards,
    List,
}

[Serializable]
public sealed class Configuration : IPluginConfiguration
{
    public int Version { get; set; } = 18;

    // Persisted source state. Curated identity/name/url are refreshed from the
    // bundled/online Definitions whenever Omega loads. Non-curated rows are temporary mirrors of
    // user-managed Dalamud repositories and are pruned when those Dalamud entries disappear.
    public List<RepositorySource> Repositories { get; set; } = [];

    public bool PreferTestingBuilds { get; set; }

    // User-facing Omega shell behavior. Positive Show* flags default to the historical behavior,
    // so existing configurations keep both Dalamud menu entry points until explicitly disabled.
    public bool MinimizeAsBar { get; set; }
    public bool ShowInSystemMenu { get; set; } = true;
    public bool ShowInTitleScreenMenu { get; set; } = true;

    // Marketplace presentation preferences. Search stays global by default; security starts compact.
    // Dynamic keeps the existing screenshot-first storefront, while CompactCards and List let users
    // choose a denser catalogue without changing filtering, indicators, or product-page behavior.
    public bool SearchEverywhere { get; set; } = true;
    public DiscoverLayoutMode DiscoverLayout { get; set; } = DiscoverLayoutMode.Dynamic;
    public bool ShowAdvancedSecurityInformation { get; set; } = false;

    // Source trust only skips Omega's generic acknowledgement for repositories whose identity is
    // outside the recognized-provider list. It never suppresses Sigmascope, package-divergence,
    // permission, compatibility, or unsupported-plugin reporting/gates.
    public bool TrustUnrecognizedSources { get; set; }

    // First-use guidance. The tutorial is intentionally independent from the EULA so users can replay
    // it without touching acceptance state. Schema 15 shows it once to existing development clients.
    public bool TutorialCompleted { get; set; }

    // Install-time permission preferences. These do not sandbox Dalamud plugins; they tell Omega which
    // known capabilities should stop the install flow and ask the user before continuing.
    public bool WarnOnBotLikeAutomation { get; set; } = true;
    public bool WarnOnCameraControl { get; set; }
    public bool WarnOnChatControl { get; set; }
    public bool WarnOnMenuControl { get; set; }

    // Last completed automatic central-catalog check. LastDailyUpdateCheckUtc is retained as a
    // compatibility fallback for configurations written before hourly Definitions polling.
    public DateTimeOffset? LastDailyUpdateCheckUtc { get; set; }
    public DateTimeOffset? LastDefinitionsUpdateCheckUtc { get; set; }
    public string LastNotifiedDefinitionsRevision { get; set; } = string.Empty;

    // Periodic Omega application update state. This is intentionally separate from Definitions updates.
    public DateTimeOffset? LastApplicationUpdateCheckUtc { get; set; }
    public string AvailableApplicationVersion { get; set; } = string.Empty;

    // Repository-risk acknowledgements are keyed to the exact current set of risky source URLs/reasons.
    // A changed risk set produces a fresh warning instead of silently inheriting an old acknowledgement.
    public string AcknowledgedRepositoryRiskFingerprint { get; set; } = string.Empty;

    // Source-specific acknowledgement keeps Review Sources useful when several Dalamud repositories
    // are configured at once. The value is a fingerprint of the current divergence evidence for that
    // normalized repository URL, so changed package evidence automatically requires fresh review.
    public Dictionary<string, string> AcknowledgedRepositoryRiskByUrl { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    // Installing from an unrecognized community source requires explicit source-specific consent.
    // The value is a trust-model fingerprint so a future change in Omega's provider classification
    // can invalidate old consent without conflating it with Sigmascope divergence evidence.
    public Dictionary<string, string> AcknowledgedUntrustedRepositoryByUrl { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    // Risky-repository remediation is staged. After all installed plugins leave a source, Omega
    // disables it and records the row here. On a later clean launch Omega removes only rows that
    // Omega originally created; user-owned repository rows remain disabled until the user removes them.
    public List<RepositoryRemediationState> RepositoryRemediationCleanup { get; set; } = [];

    // Failed plugin updates stay visible across Omega restarts until a retry succeeds, the update
    // is no longer applicable, or the user explicitly dismisses the diagnostic.
    public Dictionary<string, PersistedUpdateFailure> UpdateFailures { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    // First-use EULA acceptance is intentionally independent of the Omega build/version.
    public bool EulaAccepted { get; set; }

    public DateTimeOffset? EulaAcceptedAtUtc { get; set; }

    // One-time migration marker for window geometry written by the retired forced-full-screen build.
    public int WindowGeometryRevision { get; set; }

    public void Save() => Plugin.PluginInterface.SavePluginConfig(this);
}
