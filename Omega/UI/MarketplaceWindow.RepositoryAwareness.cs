using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private const string RepositoryRiskPopupId = "Repository warning###DalagabOmegaRepositoryRisk";
    private bool repositoryRiskPopupOpen;
    private bool requestRepositoryRiskPopup;
    private string repositoryRiskFingerprint = string.Empty;
    private string repositoryRiskDismissedFingerprint = string.Empty;
    private RepositoryRiskNotice[] repositoryRiskNotices = [];
    private RepositoryRiskNotice[] repositoryRiskAllNotices = [];

    private sealed record RepositoryRiskNotice(
        string Name,
        string Url,
        bool EnabledInDalamud,
        bool UsedByInstalledPlugin,
        int DivergentArtifactCount,
        string ExamplePlugin,
        string NoticeFingerprint);

    private void RefreshDalamudRepositoryAwareness()
    {
        try
        {
            if (!DalamudRepositoryAwareness.MergeExisting(
                    configuration,
                    repositoryBridge,
                    catalog,
                    Plugin.PluginInterface.Manifest.DalamudApiLevel))
                return;
            configuration.Save();
            InvalidateSourceCaches();
            catalog.LoadCached(configuration.Repositories);
            sourceStateRevision++;
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega could not refresh Dalamud repository awareness.");
        }
    }

    private void EvaluateRepositoryRiskWarnings(
        IReadOnlyDictionary<string, Dalamud.Plugin.IExposedPlugin> installed,
        int currentApi)
    {
        if (!catalog.HasLoaded || repositoryRiskPopupOpen || requestRepositoryRiskPopup)
            return;

        repositoryRiskAllNotices = BuildRepositoryRiskNotices(installed.Values);
        var risky = repositoryRiskAllNotices
            .Where(x => x.EnabledInDalamud || x.UsedByInstalledPlugin)
            .ToArray();
        if (risky.Length == 0)
            return;

        var fingerprintMaterial = string.Join("\n", risky.Select(x => x.NoticeFingerprint));
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintMaterial))).ToLowerInvariant();
        if (fingerprint.Equals(configuration.AcknowledgedRepositoryRiskFingerprint, StringComparison.OrdinalIgnoreCase) ||
            fingerprint.Equals(repositoryRiskDismissedFingerprint, StringComparison.OrdinalIgnoreCase))
            return;

        var unacknowledged = risky.Where(notice => !IsRepositoryRiskAcknowledged(notice)).ToArray();
        if (unacknowledged.Length == 0)
            return;

        repositoryRiskNotices = unacknowledged;
        repositoryRiskFingerprint = fingerprint;
        repositoryRiskPopupOpen = true;
        requestRepositoryRiskPopup = true;
    }

    private RepositoryRiskNotice[] BuildRepositoryRiskNotices(IEnumerable<Dalamud.Plugin.IExposedPlugin> installedPlugins)
    {
        var registrations = repositoryBridge.GetConfiguredRepositories();
        var enabledUrls = registrations
            .Where(x => x.Enabled)
            .Select(x => NormalizeUrl(x.Url))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var installedUrls = installedPlugins
            .Select(x => NormalizeUrl(x.Manifest.InstalledFromUrl))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return catalog.Variants
            .Where(variant => variant.SecurityFindings.Any(finding =>
                finding.RuleId.Equals("artifact.cross-source-hash-mismatch", StringComparison.OrdinalIgnoreCase)))
            .GroupBy(variant => NormalizeUrl(variant.SourceUrl), StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var first = group.First();
                var example = group.FirstOrDefault(x => x.SecurityFindings.Any(f =>
                    f.RuleId.Equals("artifact.cross-source-hash-mismatch", StringComparison.OrdinalIgnoreCase))) ?? first;
                var enabled = enabledUrls.Contains(group.Key);
                var installed = installedUrls.Contains(group.Key);
                var pluginNames = group.Select(x => x.InternalName)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var noticeMaterial = $"{group.Key}|{enabled}|{installed}|{string.Join(",", pluginNames)}";
                var noticeFingerprint = Convert.ToHexString(
                    SHA256.HashData(Encoding.UTF8.GetBytes(noticeMaterial))).ToLowerInvariant();
                return new RepositoryRiskNotice(
                    SourceLabel(first),
                    group.Key,
                    enabled,
                    installed,
                    pluginNames.Length,
                    example.Name,
                    noticeFingerprint);
            })
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private RepositoryRiskNotice? FindRepositoryRiskNotice(string sourceUrl)
    {
        var normalized = NormalizeUrl(sourceUrl);
        var notice = repositoryRiskAllNotices.FirstOrDefault(x =>
            NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase));
        if (notice is not null)
            return notice;

        repositoryRiskAllNotices = BuildRepositoryRiskNotices(Plugin.PluginInterface.InstalledPlugins);
        return repositoryRiskAllNotices.FirstOrDefault(x =>
            NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsRepositoryRiskAcknowledged(RepositoryRiskNotice notice)
    {
        var normalized = NormalizeUrl(notice.Url);
        return configuration.AcknowledgedRepositoryRiskByUrl.TryGetValue(normalized, out var acknowledged) &&
               acknowledged.Equals(notice.NoticeFingerprint, StringComparison.OrdinalIgnoreCase);
    }

    private bool IsRepositoryRiskAcknowledged(string sourceUrl)
    {
        var normalized = NormalizeUrl(sourceUrl);
        var notice = repositoryRiskAllNotices.FirstOrDefault(x =>
            NormalizeUrl(x.Url).Equals(normalized, StringComparison.OrdinalIgnoreCase));
        return notice is not null && IsRepositoryRiskAcknowledged(notice);
    }

    private void AcknowledgeRepositoryRisk(RepositoryRiskNotice notice)
    {
        configuration.AcknowledgedRepositoryRiskByUrl[NormalizeUrl(notice.Url)] = notice.NoticeFingerprint;
        configuration.Save();
    }

    private static string UntrustedRepositoryFingerprint(MarketplacePlugin plugin)
    {
        var normalized = NormalizeUrl(plugin.SourceUrl);
        var material = $"omega-untrusted-source-v1|{normalized}|{RepositoryProviderRules.TrustLabel(plugin.SourceName, plugin.SourceUrl, plugin.SourceIsOfficial)}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    private static bool RequiresUntrustedRepositoryAcknowledgement(MarketplacePlugin plugin)
        => RepositoryProviderRules.RequiresExplicitInstallAcknowledgement(
            plugin.SourceName, plugin.SourceUrl, plugin.SourceIsOfficial);

    private bool IsUntrustedRepositoryAcknowledged(MarketplacePlugin plugin)
    {
        if (!RequiresUntrustedRepositoryAcknowledgement(plugin))
            return true;
        var normalized = NormalizeUrl(plugin.SourceUrl);
        return configuration.AcknowledgedUntrustedRepositoryByUrl.TryGetValue(normalized, out var acknowledged) &&
               acknowledged.Equals(UntrustedRepositoryFingerprint(plugin), StringComparison.OrdinalIgnoreCase);
    }

    private void AcknowledgeUntrustedRepository(MarketplacePlugin plugin)
    {
        configuration.AcknowledgedUntrustedRepositoryByUrl[NormalizeUrl(plugin.SourceUrl)] =
            UntrustedRepositoryFingerprint(plugin);
        configuration.Save();
    }

    private void AcknowledgeVisibleRepositoryRisks()
    {
        foreach (var notice in repositoryRiskNotices)
            configuration.AcknowledgedRepositoryRiskByUrl[NormalizeUrl(notice.Url)] = notice.NoticeFingerprint;
        configuration.AcknowledgedRepositoryRiskFingerprint = repositoryRiskFingerprint;
        configuration.Save();
    }

    private void DrawRepositoryRiskModal()
    {
        if (!repositoryRiskPopupOpen)
            return;

        var keepOpen = repositoryRiskPopupOpen;
        ImGui.SetNextWindowSize(UiModalSize(720f, 0f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal(RepositoryRiskPopupId, ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoCollapse |
                ImGuiWindowFlags.AlwaysAutoResize | ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse))
        {
            repositoryRiskPopupOpen = keepOpen;
            return;
        }

        if (DrawOmegaModalHeader("Repository warning", "repository-risk"))
        {
            repositoryRiskDismissedFingerprint = repositoryRiskFingerprint;
            repositoryRiskPopupOpen = false;
            ImGui.CloseCurrentPopup();
            ImGui.EndPopup();
            return;
        }

        ImGui.TextColored(new Vector4(0.96f, 0.36f, 0.28f, 1f), "Omega found repository package divergence in sources currently used by this Dalamud installation.");
        ImGui.TextWrapped("Same-version packages differ between repositories. Review the source before installing or updating.");
        ImGui.Spacing();

        if (ImGui.BeginTable("repository-risk-table", 3, ImGuiTableFlags.BordersInnerH | ImGuiTableFlags.RowBg, new Vector2(0f, 0f)))
        {
            ImGui.TableSetupColumn("Repository", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Use", ImGuiTableColumnFlags.WidthFixed, 150f);
            ImGui.TableSetupColumn("Differences", ImGuiTableColumnFlags.WidthFixed, 110f);
            ImGui.TableHeadersRow();
            foreach (var notice in repositoryRiskNotices)
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0);
                ImGui.TextColored(new Vector4(0.96f, 0.34f, 0.28f, 1f), notice.Name);
                if (ImGui.IsItemHovered())
                    SetReadableTooltip($"{notice.Url}\nExample divergent package: {notice.ExamplePlugin}");
                ImGui.TableSetColumnIndex(1);
                var use = notice.EnabledInDalamud && notice.UsedByInstalledPlugin
                    ? "Enabled + installed"
                    : notice.UsedByInstalledPlugin ? "Installed plugin" : "Enabled in Dalamud";
                ImGui.TextUnformatted(use);
                ImGui.TableSetColumnIndex(2);
                ImGui.TextUnformatted(notice.DivergentArtifactCount.ToString());
            }
            ImGui.EndTable();
        }

        ImGui.Spacing();
        if (ImGui.Button("Review Sources", Ui(150f, 34f)))
        {
            repositoryRiskDismissedFingerprint = repositoryRiskFingerprint;
            repositoryRiskPopupOpen = false;
            ImGui.CloseCurrentPopup();
            settingsSection = SettingsSection.Repositories;
            sourceSection = SourceManagerSection.DalamudConfigured;
            sourceSearch = string.Empty;
            requestSettingsPopup = true;
            settingsOpen = true;
        }
        ImGui.SameLine();
        if (ImGui.Button("Acknowledge", Ui(140f, 34f)))
        {
            AcknowledgeVisibleRepositoryRisks();
            repositoryRiskPopupOpen = false;
            ImGui.CloseCurrentPopup();
        }

        repositoryRiskPopupOpen = keepOpen && repositoryRiskPopupOpen;
        ImGui.EndPopup();
    }

    private bool IsRepositoryArtifactDivergent(string sourceUrl)
    {
        var normalized = NormalizeUrl(sourceUrl);
        return catalog.Variants.Any(variant =>
            NormalizeUrl(variant.SourceUrl).Equals(normalized, StringComparison.OrdinalIgnoreCase) &&
            variant.SecurityFindings.Any(finding =>
                finding.RuleId.Equals("artifact.cross-source-hash-mismatch", StringComparison.OrdinalIgnoreCase)));
    }
}
