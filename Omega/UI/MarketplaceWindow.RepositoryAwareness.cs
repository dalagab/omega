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

    private sealed record RepositoryRiskNotice(
        string Name,
        string Url,
        bool EnabledInDalamud,
        bool UsedByInstalledPlugin,
        int DivergentArtifactCount,
        string ExamplePlugin);

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

        var registrations = repositoryBridge.GetConfiguredRepositories();
        var enabledUrls = registrations
            .Where(x => x.Enabled)
            .Select(x => NormalizeUrl(x.Url))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var installedUrls = installed.Values
            .Select(x => NormalizeUrl(x.Manifest.InstalledFromUrl))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (enabledUrls.Count == 0 && installedUrls.Count == 0)
            return;

        var risky = catalog.Variants
            .Where(variant =>
            {
                var url = NormalizeUrl(variant.SourceUrl);
                return enabledUrls.Contains(url) || installedUrls.Contains(url);
            })
            .Where(variant => variant.SecurityFindings.Any(finding =>
                finding.RuleId.Equals("artifact.cross-source-hash-mismatch", StringComparison.OrdinalIgnoreCase)))
            .GroupBy(variant => NormalizeUrl(variant.SourceUrl), StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var first = group.First();
                var example = group.FirstOrDefault(x => x.SecurityFindings.Any(f =>
                    f.RuleId.Equals("artifact.cross-source-hash-mismatch", StringComparison.OrdinalIgnoreCase))) ?? first;
                return new RepositoryRiskNotice(
                    SourceLabel(first),
                    group.Key,
                    enabledUrls.Contains(group.Key),
                    installedUrls.Contains(group.Key),
                    group.Select(x => x.InternalName).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                    example.Name);
            })
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (risky.Length == 0)
            return;

        var fingerprintMaterial = string.Join("\n", risky.Select(x =>
            $"{x.Url}|{x.EnabledInDalamud}|{x.UsedByInstalledPlugin}|{x.DivergentArtifactCount}"));
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintMaterial))).ToLowerInvariant();
        if (fingerprint.Equals(configuration.AcknowledgedRepositoryRiskFingerprint, StringComparison.OrdinalIgnoreCase) ||
            fingerprint.Equals(repositoryRiskDismissedFingerprint, StringComparison.OrdinalIgnoreCase))
            return;

        repositoryRiskNotices = risky;
        repositoryRiskFingerprint = fingerprint;
        repositoryRiskPopupOpen = true;
        requestRepositoryRiskPopup = true;
    }

    private void DrawRepositoryRiskModal()
    {
        if (!repositoryRiskPopupOpen)
            return;

        var keepOpen = repositoryRiskPopupOpen;
        ImGui.SetNextWindowSize(new Vector2(720f, 430f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal(RepositoryRiskPopupId, ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoCollapse))
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
        ImGui.TextWrapped("This does not prove a repository is malicious. It means at least one package with the same plugin version differs from Omega's stable-provider artifact baseline, so the source deserves review before further installs or updates.");
        ImGui.Spacing();

        if (ImGui.BeginTable("repository-risk-table", 3, ImGuiTableFlags.BordersInnerH | ImGuiTableFlags.RowBg, new Vector2(0f, 235f)))
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
        if (ImGui.Button("Review Sources", new Vector2(150f, 34f)))
        {
            repositoryRiskDismissedFingerprint = repositoryRiskFingerprint;
            repositoryRiskPopupOpen = false;
            ImGui.CloseCurrentPopup();
            requestSettingsPopup = true;
            settingsOpen = true;
        }
        ImGui.SameLine();
        if (ImGui.Button("Acknowledge", new Vector2(140f, 34f)))
        {
            configuration.AcknowledgedRepositoryRiskFingerprint = repositoryRiskFingerprint;
            configuration.Save();
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
