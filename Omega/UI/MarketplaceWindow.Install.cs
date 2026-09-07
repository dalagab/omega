using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private const string InstallRiskPopupId = "Install plugin###DalagabOmegaInstallConfirm";

    private void DrawDetailsPrimaryAction(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (installedPlugin is not null)
        {
            ImGui.TextDisabled($"Installed {installedPlugin.Version?.ToString() ?? "version pending"}  •  {(installedPlugin.IsLoaded ? "loaded" : "not loaded")}");
            return;
        }

        var candidates = GetInstallCandidates(plugin.InternalName, currentApi, currentDalamudVersion);
        if (candidates.Count == 0)
        {
            ImGui.TextDisabled(DescribeInstallUnavailability(plugin.InternalName, currentApi, currentDalamudVersion));
            return;
        }

        if (installTask is not null && installingInternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase))
        {
            ImGui.TextDisabled("Installing…");
            return;
        }

        var label = candidates.Count > 1 ? $"Install  •  {candidates.Count} repositories" : "Install";
        var width = Math.Min(Ui(260f), Math.Max(Ui(130f), ImGui.CalcTextSize(label).X + Ui(36f)));
        if (DrawPillButton(label, $"details-install-{plugin.InternalName}", new Vector2(width, Ui(36f)), true))
            OpenInstallChooser(plugin);
    }

    /// <summary>
    /// Repository chooser shown for every install. Repository priority is already encoded in the
    /// candidate ordering, so the chooser stays focused on one task: select a source and install.
    /// Clicking a source only changes selection; the explicit Install action performs the lifecycle.
    /// </summary>
    private void DrawInstallModal(int currentApi, Version currentDalamudVersion)
    {
        if (!installPopupOpen || pendingInstall is null)
            return;

        var keepOpen = installPopupOpen;
        ImGui.SetNextWindowSize(UiModalSize(720f, 520f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal("Choose repository###DalagabOmegaInstall", ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoCollapse | ImGuiWindowFlags.NoResize))
        {
            installPopupOpen = keepOpen;
            return;
        }

        if (DrawOmegaModalHeader("Choose repository", "install"))
        {
            CloseInstallChooser();
            ImGui.EndPopup();
            return;
        }

        var plugin = pendingInstall;
        var candidates = GetInstallCandidates(plugin.InternalName, currentApi, currentDalamudVersion);
        EnsurePendingInstallSource(candidates);
        var selected = candidates.FirstOrDefault(x =>
            NormalizeUrl(x.SourceUrl).Equals(NormalizeUrl(pendingInstallSourceUrl), StringComparison.OrdinalIgnoreCase));

        ImGui.TextUnformatted(plugin.Name);
        ImGui.SameLine(0f, Ui(10f));
        ImGui.TextDisabled("Choose the package source. Omega's preferred source stays at the top.");
        ImGui.Spacing();

        if (candidates.Count == 0)
        {
            ImGui.TextWrapped(DescribeInstallUnavailability(plugin.InternalName, currentApi, currentDalamudVersion));
        }
        else
        {
            var footerHeight = Ui(72f);
            ImGui.BeginChild("install-source-list", new Vector2(0f, -footerHeight), true,
                ImGuiWindowFlags.AlwaysVerticalScrollbar);
            for (var index = 0; index < candidates.Count; index++)
                DrawInstallSourceChoice(candidates[index], currentApi, currentDalamudVersion, preferred: index == 0);
            ImGui.EndChild();
        }

        ImGui.Spacing();
        if (selected is not null)
        {
            ImGui.TextDisabled($"Selected: {selected.SourceName}");
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(selected.SourceUrl);
        }
        else
        {
            ImGui.TextDisabled("Select a repository to continue.");
        }

        var continueWidth = Ui(116f);
        var continueY = ImGui.GetCursorPosY() - ImGui.GetTextLineHeight() - Ui(5f);
        var continueX = ImGui.GetCursorPosX() + Math.Max(0f, ImGui.GetContentRegionAvail().X - continueWidth);
        ImGui.SetCursorPos(new Vector2(continueX, continueY));
        var canContinue = selected is not null && installTask is null;
        if (!canContinue)
            ImGui.BeginDisabled();
        if (ImGui.Button("Continue", new Vector2(continueWidth, Ui(34f))) && selected is not null)
            ContinueInstallSelection(selected, currentApi, currentDalamudVersion);
        if (!canContinue)
            ImGui.EndDisabled();

        installPopupOpen = keepOpen && installPopupOpen;
        ImGui.EndPopup();
    }

    // Package-manager dependencies come only from the normalized catalog graph.
    // SecurityDependencies (including IPC observations) remain presentation-only and never block
    // or trigger installation from the repository chooser.

    private void DrawInstallSourceChoice(
        MarketplacePlugin candidate,
        int currentApi,
        Version currentDalamudVersion,
        bool preferred)
    {
        var selected = NormalizeUrl(candidate.SourceUrl)
            .Equals(NormalizeUrl(pendingInstallSourceUrl), StringComparison.OrdinalIgnoreCase);
        var version = candidate.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out var testing)
            ? testing ? candidate.TestingAssemblyVersionText ?? candidate.AssemblyVersionText : candidate.AssemblyVersionText
            : candidate.AssemblyVersionText;
        var api = testing ? candidate.TestingDalamudApiLevel ?? candidate.DalamudApiLevel : candidate.DalamudApiLevel;
        var alreadyPresent = IsInstallRepositoryPresent(candidate);
        var candidates = GetInstallCandidates(candidate.InternalName, currentApi, currentDalamudVersion);
        var baseline = candidates.FirstOrDefault(x =>
                           x.AssemblyVersion.Equals(candidate.AssemblyVersion) &&
                           x.DalamudApiLevel == candidate.DalamudApiLevel &&
                           !IsPluginPackageArtifactDivergent(x))
                       ?? candidates.FirstOrDefault(x =>
                           x.AssemblyVersion.Equals(candidate.AssemblyVersion) &&
                           x.DalamudApiLevel == candidate.DalamudApiLevel)
                       ?? candidate;
        var sourceComparison = CompareRepositorySecurity(candidate, baseline);
        var packageDivergent = IsPluginPackageArtifactDivergent(candidate);
        var repositoryDivergent = IsRepositoryArtifactDivergent(candidate.SourceUrl);
        var unrecognized = RequiresUntrustedRepositoryAcknowledgement(candidate);
        var unrecognizedAcknowledged = unrecognized && IsUntrustedRepositoryAcknowledged(candidate);

        var statusLabel = "Available";
        var statusColor = new Vector4(0.62f, 0.66f, 0.70f, 1f);
        if (packageDivergent || repositoryDivergent)
        {
            statusLabel = "Package divergence";
            statusColor = new Vector4(0.96f, 0.30f, 0.24f, 1f);
        }
        else if (sourceComparison.Worse)
        {
            statusLabel = "More findings";
            statusColor = new Vector4(0.96f, 0.30f, 0.24f, 1f);
        }
        else if (unrecognized && !unrecognizedAcknowledged)
        {
            statusLabel = "Ack required";
            statusColor = new Vector4(0.95f, 0.64f, 0.20f, 1f);
        }
        else if (preferred)
        {
            statusLabel = "Preferred";
            statusColor = new Vector4(0.34f, 0.82f, 0.56f, 1f);
        }
        else if (unrecognizedAcknowledged)
        {
            statusLabel = "Acknowledged";
            statusColor = new Vector4(0.95f, 0.64f, 0.20f, 1f);
        }
        else if (alreadyPresent)
        {
            statusLabel = "Ready";
            statusColor = new Vector4(0.34f, 0.82f, 0.56f, 1f);
        }

        ImGui.PushID($"install-source-{StableId(candidate.SourceUrl)}");
        var rowStart = ImGui.GetCursorPos();
        var rowWidth = ImGui.GetContentRegionAvail().X;
        var rowHeight = Ui(MarketplaceLayoutRules.InstallSourceRowHeight);
        if (ImGui.Selectable(
                "##choice",
                selected,
                ImGuiSelectableFlags.DontClosePopups,
                new Vector2(rowWidth, rowHeight)))
        {
            pendingInstallSourceUrl = candidate.SourceUrl;
        }
        var rowHovered = ImGui.IsItemHovered();
        var rowEnd = ImGui.GetCursorPos();

        ImGui.SetCursorPos(rowStart + Ui(10f, 8f));
        DrawRepositoryName(Shorten(candidate.SourceName, 52), candidate.SourceUrl, candidate.SourceIsOfficial, currentApi);

        var statusWidth = ImGui.CalcTextSize(statusLabel).X + Ui(24f);
        ImGui.SetCursorPos(new Vector2(
            rowStart.X + Math.Max(Ui(180f), rowWidth - statusWidth - Ui(10f)),
            rowStart.Y + Ui(8f)));
        ImGui.TextColored(statusColor, "●");
        ImGui.SameLine(0f, Ui(5f));
        ImGui.TextColored(statusColor, statusLabel);

        ImGui.SetCursorPos(rowStart + Ui(10f, 33f));
        ImGui.TextDisabled($"Version {version}  •  API {api}  •  {RepositoryStateLabel(candidate.SourceName, candidate.SourceUrl, candidate.SourceIsOfficial)}");

        if (rowHovered)
        {
            var reason = DescribeInstallSourceState(candidate);
            ImGui.SetTooltip($"{reason}\n{candidate.SourceUrl}");
        }

        ImGui.SetCursorPos(rowEnd);
        ImGui.PopID();
    }

    private static void DrawInstallRepositoryPresentMarker(Vector2 rowStart, float rowWidth, bool official)
    {
        ImGui.SetCursorPos(rowStart + new Vector2(Math.Max(Ui(10f), rowWidth - Ui(30f)), Ui(10f)));
        ImGui.PushFont(UiBuilder.IconFontFixedWidth);
        ImGui.TextColored(new Vector4(0.28f, 0.80f, 0.48f, 1f), FontAwesomeIcon.Check.ToIconString());
        ImGui.PopFont();
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(official ? "Built into Dalamud" : "Repository already added to Dalamud");
    }

    private bool IsInstallRepositoryPresent(MarketplacePlugin candidate)
    {
        if (candidate.SourceIsOfficial)
            return true;

        var source = FindConfiguredSource(candidate.SourceUrl);
        if (source is null)
            return false;

        var state = repositoryBridge.GetState(source.Url);
        return state.Available && state.Present;
    }

    private bool NeedsInstallRepositoryReview(MarketplacePlugin candidate)
        => (IsRepositoryArtifactDivergent(candidate.SourceUrl) && !IsRepositoryRiskAcknowledged(candidate.SourceUrl)) ||
           (RequiresUntrustedRepositoryAcknowledgement(candidate) && !IsUntrustedRepositoryAcknowledged(candidate));

    private string BuildInstallRepositoryReviewReason(MarketplacePlugin candidate)
    {
        var divergence = IsRepositoryArtifactDivergent(candidate.SourceUrl) && !IsRepositoryRiskAcknowledged(candidate.SourceUrl);
        var untrusted = RequiresUntrustedRepositoryAcknowledgement(candidate) && !IsUntrustedRepositoryAcknowledged(candidate);
        if (divergence && untrusted)
            return "The selected repository is outside Omega's recognized provider set and also has unacknowledged package-divergence findings. Review this source before installing from it.";
        if (divergence)
            return "The selected repository has unacknowledged package-divergence findings. Review this source before installing from it.";
        return "The selected repository is outside Omega's recognized provider set. Review and explicitly acknowledge this source before installing from it.";
    }

    private static string BuildInstallRepositoryReviewExplanation(
        MarketplacePlugin selected,
        bool divergence,
        bool untrusted)
    {
        if (divergence && untrusted)
            return "Omega does not recognize this repository as one of its established provider identities, and Sigmascope has also recorded package-divergence findings for the source. Neither fact proves malicious intent, but both are reasons to review the repository before allowing Dalamud to install or service its plugins.";
        if (divergence)
            return "Sigmascope recorded package-divergence findings for this repository. That does not prove malicious intent, but the source should be reviewed before allowing Dalamud to install or service its plugins.";
        if (untrusted)
            return "This community repository is not one of Omega's recognized provider identities. Omega can still install from it, but only after you explicitly acknowledge the source. This source classification is separate from Sigmascope findings.";
        return $"{selected.SourceName} is already acknowledged for its current source-review state.";
    }

    private string DescribeInstallSourceState(MarketplacePlugin candidate)
    {
        if (IsPluginPackageArtifactDivergent(candidate))
            return "Plugin package differs from the preferred baseline — review required";

        if (IsRepositoryArtifactDivergent(candidate.SourceUrl))
            return IsRepositoryRiskAcknowledged(candidate.SourceUrl)
                ? "Package-divergence risk acknowledged — available for explicit installation"
                : "Repository has known package divergence — acknowledgement required";

        if (RequiresUntrustedRepositoryAcknowledgement(candidate))
            return IsUntrustedRepositoryAcknowledged(candidate)
                ? "Unrecognized community acknowledged — available for explicit installation"
                : "Unrecognized community — acknowledgement required";

        return DescribeInstallRepositoryRegistration(candidate);
    }

    private string DescribeInstallRepositoryRegistration(MarketplacePlugin candidate)
    {
        if (candidate.SourceIsOfficial)
            return "Built into Dalamud";

        var source = FindConfiguredSource(candidate.SourceUrl);
        if (source is null)
            return "Known in Omega Definitions — will be added to Dalamud for this installation";

        var state = repositoryBridge.GetState(source.Url);
        if (!state.Available)
            return "Repository service unavailable";
        if (!state.Present)
            return "Will be added automatically for installation";
        if (!state.Enabled && source.DalamudManagedByOmega)
            return "Will be enabled automatically for installation";
        if (!state.Enabled)
            return "Currently disabled; Install will enable it";
        return "Ready";
    }

    private void OpenInstallRepositoryRiskReview(MarketplacePlugin selected)
    {
        // Keep the install context intact. The old flow discarded the selected plugin/source and
        // jumped to Settings > Dalamud, which could be empty when the repository had not yet been
        // registered. Risk review now belongs to the installation that triggered it.
        pendingInstallRiskSourceUrl = selected.SourceUrl;
        pendingInstallRiskAcknowledgementChecked = false;
        installPopupOpen = false;
        installRiskPopupOpen = true;
        requestInstallRiskPopup = true;
        ImGui.CloseCurrentPopup();
    }

    private void DrawInstallRiskReviewModal(int currentApi, Version currentDalamudVersion)
    {
        if (!installRiskPopupOpen || pendingInstall is null)
            return;

        var keepOpen = installRiskPopupOpen;
        ImGui.SetNextWindowSize(UiModalSize(540f, 0f), ImGuiCond.Appearing);
        if (!ImGui.BeginPopupModal(InstallRiskPopupId, ref keepOpen,
                ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoCollapse | ImGuiWindowFlags.AlwaysAutoResize))
        {
            installRiskPopupOpen = keepOpen;
            return;
        }

        if (DrawOmegaModalHeader("Install plugin", "install-confirm"))
        {
            ReturnFromInstallRiskReview();
            ImGui.EndPopup();
            return;
        }

        var plugin = pendingInstall;
        var selected = GetInstallCandidates(plugin.InternalName, currentApi, currentDalamudVersion)
            .FirstOrDefault(x => NormalizeUrl(x.SourceUrl)
                .Equals(NormalizeUrl(pendingInstallRiskSourceUrl), StringComparison.OrdinalIgnoreCase));

        if (selected is null)
        {
            ImGui.TextWrapped("This package is no longer available in the current Omega Definitions.");
            ImGui.Spacing();
            if (ImGui.Button("Back to repositories", Ui(180f, 34f)))
                ReturnFromInstallRiskReview();
            installRiskPopupOpen = keepOpen && installRiskPopupOpen;
            ImGui.EndPopup();
            return;
        }

        selected = catalog.HydrateVariant(selected);
        var version = selected.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out var testing)
            ? testing ? selected.TestingAssemblyVersionText ?? selected.AssemblyVersionText : selected.AssemblyVersionText
            : selected.AssemblyVersionText;
        var api = testing ? selected.TestingDalamudApiLevel ?? selected.DalamudApiLevel : selected.DalamudApiLevel;
        var notice = FindRepositoryRiskNotice(selected.SourceUrl);
        var repositoryDivergent = IsRepositoryArtifactDivergent(selected.SourceUrl) || IsPluginPackageArtifactDivergent(selected);
        var needsDivergenceAcknowledgement = repositoryDivergent && !IsRepositoryRiskAcknowledged(selected.SourceUrl);
        var untrusted = RequiresUntrustedRepositoryAcknowledgement(selected);
        var needsUntrustedAcknowledgement = untrusted && !IsUntrustedRepositoryAcknowledged(selected);
        var needsAcknowledgement = needsDivergenceAcknowledgement || needsUntrustedAcknowledgement;

        ImGui.BeginGroup();
        DrawPluginArtwork(
            selected,
            null,
            Ui(72f),
            Ui(72f),
            currentApi,
            currentDalamudVersion,
            showOverlays: false);
        ImGui.SameLine(0f, Ui(16f));
        ImGui.BeginGroup();
        ImGui.TextUnformatted(selected.Name);
        if (!string.IsNullOrWhiteSpace(selected.Author))
            ImGui.TextDisabled(selected.Author);
        ImGui.TextDisabled($"{selected.SourceName}  •  Version {version}  •  API {api}");
        ImGui.EndGroup();
        ImGui.EndGroup();

        ImGui.Dummy(Ui(1f, 8f));
        ImGui.Separator();
        ImGui.Dummy(Ui(1f, 8f));

        Vector4 statusColor;
        string statusLabel;
        string statusExplanation;
        if (repositoryDivergent)
        {
            statusColor = new Vector4(0.96f, 0.30f, 0.24f, 1f);
            statusLabel = "Package divergence";
            statusExplanation = BuildInstallRepositoryReviewExplanation(selected, true, untrusted);
        }
        else if (needsUntrustedAcknowledgement)
        {
            statusColor = new Vector4(0.95f, 0.64f, 0.20f, 1f);
            statusLabel = "Acknowledgement required";
            statusExplanation = BuildInstallRepositoryReviewExplanation(selected, false, true);
        }
        else if (untrusted)
        {
            statusColor = new Vector4(0.95f, 0.64f, 0.20f, 1f);
            statusLabel = "Source acknowledged";
            statusExplanation = "You previously acknowledged this unrecognized community source for its current identity.";
        }
        else
        {
            statusColor = new Vector4(0.34f, 0.82f, 0.56f, 1f);
            statusLabel = "Ready to install";
            statusExplanation = DescribeInstallRepositoryRegistration(selected);
        }

        ImGui.TextColored(statusColor, "●");
        ImGui.SameLine(0f, Ui(7f));
        ImGui.TextColored(statusColor, statusLabel);
        ImGui.PushTextWrapPos(ImGui.GetCursorPosX() + Math.Max(Ui(320f), ImGui.GetContentRegionAvail().X));
        ImGui.TextWrapped(statusExplanation);
        ImGui.PopTextWrapPos();

        if (needsAcknowledgement)
        {
            ImGui.Spacing();
            ImGui.Checkbox("I understand this source and want to continue", ref pendingInstallRiskAcknowledgementChecked);
        }
        else if (repositoryDivergent)
        {
            ImGui.Spacing();
            ImGui.TextDisabled("Package divergence was already acknowledged for the current findings.");
        }

        ImGui.Dummy(Ui(1f, 8f));
        ImGui.Separator();
        ImGui.Dummy(Ui(1f, 8f));

        var discord = BuildProductProjectLinks(selected)
            .FirstOrDefault(link => link.Kind.Equals("discord", StringComparison.OrdinalIgnoreCase));
        var footerY = ImGui.GetCursorPosY();
        if (discord is not null)
        {
            if (DrawPillButton("Join community Discord", "install-confirm-discord", Ui(176f, 34f), true))
                OpenProductWebsite(selected, discord.Url);
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(discord.Url);
        }
        else
        {
            ImGui.TextDisabled("Community link unavailable");
        }

        var installWidth = Ui(104f);
        var installX = ImGui.GetCursorPosX() + Math.Max(0f, ImGui.GetContentRegionAvail().X - installWidth);
        ImGui.SetCursorPos(new Vector2(installX, footerY));
        var canInstall = installTask is null && (!needsAcknowledgement || pendingInstallRiskAcknowledgementChecked);
        if (!canInstall)
            ImGui.BeginDisabled();
        if (ImGui.Button("Install", new Vector2(installWidth, Ui(34f))) && canInstall)
        {
            if (needsDivergenceAcknowledgement && notice is not null)
                AcknowledgeRepositoryRisk(notice);
            if (needsUntrustedAcknowledgement)
                AcknowledgeUntrustedRepository(selected);

            installRiskPopupOpen = false;
            pendingInstallRiskAcknowledgementChecked = false;
            ImGui.CloseCurrentPopup();
            TryStartSelectedInstall(selected);
            ImGui.EndPopup();
            return;
        }
        if (!canInstall)
            ImGui.EndDisabled();

        installRiskPopupOpen = keepOpen && installRiskPopupOpen;
        ImGui.EndPopup();
    }

    private static void DrawInstallRiskDetailRow(string label, string value)
    {
        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        ImGui.TextDisabled(label);
        ImGui.TableSetColumnIndex(1);
        ImGui.TextWrapped(string.IsNullOrWhiteSpace(value) ? "—" : value);
    }

    private void ReturnFromInstallRiskReview()
    {
        installRiskPopupOpen = false;
        pendingInstallRiskAcknowledgementChecked = false;
        ImGui.CloseCurrentPopup();
        if (pendingInstall is null)
            return;
        if (pendingInstallPlan is not null)
        {
            installPlanPopupOpen = true;
            requestInstallPlanPopup = true;
            return;
        }
        installPopupOpen = true;
        requestInstallPopup = true;
    }

    private void EnsurePendingInstallSource(IReadOnlyList<MarketplacePlugin> candidates)
    {
        if (candidates.Any(x => NormalizeUrl(x.SourceUrl)
                .Equals(NormalizeUrl(pendingInstallSourceUrl), StringComparison.OrdinalIgnoreCase)))
            return;
        pendingInstallSourceUrl = candidates.FirstOrDefault()?.SourceUrl ?? string.Empty;
    }

    private void StartSelectedInstall(MarketplacePlugin plugin)
    {
        if (!PendingDependencyPlanAllowsSinglePluginExecution(plugin))
        {
            operationMessage = "The dependency plan changed or requires a multi-plugin transaction. Review the plan again before installing.";
            installRiskPopupOpen = false;
            installPermissionPopupOpen = false;
            installPlanPopupOpen = true;
            requestInstallPlanPopup = true;
            ImGui.CloseCurrentPopup();
            return;
        }

        var source = ResolveOrCreateInstallSource(plugin);
        installingInternalName = plugin.InternalName;
        operationMessage = $"Installing {plugin.Name} from {plugin.SourceName}...";
        installTask = installer.InstallAsync(
            plugin,
            source,
            configuration.PreferTestingBuilds);
        pendingInstall = null;
        pendingInstallSourceUrl = string.Empty;
        pendingInstallRiskSourceUrl = string.Empty;
        pendingInstallPlan = null;
        pendingInstallPlanRootSourceUrl = string.Empty;
        pendingInstallPlanFromUpdate = false;
        pendingInstallExplicitDependencies.Clear();
        pendingInstallTransactionReviewSources.Clear();
        installPlanPopupOpen = false;
        installPopupOpen = false;
        ImGui.CloseCurrentPopup();
    }

    private RepositorySource? ResolveOrCreateInstallSource(MarketplacePlugin plugin)
    {
        if (plugin.SourceIsOfficial)
            return null;

        var existing = FindConfiguredSource(plugin.SourceUrl);
        if (existing is not null)
            return existing;

        if (!Uri.TryCreate(plugin.SourceUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            return null;

        // The repository identity already belongs to online Definitions. Installation only needs
        // an ephemeral source descriptor so Dalamud can register/service the selected feed; Omega
        // does not create a second local repository entry.
        return new RepositorySource
        {
            Name = string.IsNullOrWhiteSpace(plugin.SourceName) ? uri.Host : plugin.SourceName,
            Url = uri.ToString(),
            Enabled = true,
            IsCurated = true,
            IsExperimental = true,
            IntegrateWithDalamud = true,
        };
    }

    private void CloseInstallChooser()
    {
        pendingInstall = null;
        pendingInstallSourceUrl = string.Empty;
        pendingInstallRiskSourceUrl = string.Empty;
        pendingInstallRiskAcknowledgementChecked = false;
        pendingInstallPermissionSourceUrl = string.Empty;
        pendingInstallPermissionAcknowledgementChecked = false;
        pendingInstallPlan = null;
        pendingInstallPlanRootSourceUrl = string.Empty;
        pendingInstallPlanFromUpdate = false;
        pendingInstallExplicitDependencies.Clear();
        pendingInstallTransactionReviewSources.Clear();
        installPopupOpen = false;
        installPlanPopupOpen = false;
        installRiskPopupOpen = false;
        installPermissionPopupOpen = false;
        ImGui.CloseCurrentPopup();
    }
}
