using System.Diagnostics;
using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Interface;
using Dalamud.Interface.Textures;
using Dalamud.Interface.Windowing;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private static void CenterText(string text, bool disabled = false)
    {
        var textWidth = ImGui.CalcTextSize(text).X;
        var available = ImGui.GetContentRegionAvail().X;
        var startX = ImGui.GetCursorPosX();
        if (textWidth < available)
            ImGui.SetCursorPosX(startX + ((available - textWidth) * 0.5f));

        if (disabled)
            ImGui.TextDisabled(text);
        else
            ImGui.TextUnformatted(text);

        ImGui.SetCursorPosX(startX);
    }

    private IEnumerable<MarketplacePlugin> ApplyFilters(
        IEnumerable<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        var query = plugins;

        query = activeView switch
        {
            MarketplaceView.Library => ApplyLibraryRuntimeFilter(
                query.Where(x => installed.ContainsKey(x.InternalName)), installed),
            MarketplaceView.Updates => query.Where(x =>
                installed.TryGetValue(x.InternalName, out var installedPlugin) &&
                HasAvailableUpdate(x.InternalName, installedPlugin, currentApi, currentDalamudVersion)),
            _ => ApplyStatusFilter(query, installed, currentApi, currentDalamudVersion),
        };

        query = ApplySecurityFilter(query);
        query = ApplyContentRatingFilter(query);

        if (!string.IsNullOrWhiteSpace(search))
        {
            var needle = search.Trim();
            query = query.Where(x =>
                Contains(x.Name, needle) ||
                Contains(x.InternalName, needle) ||
                Contains(x.Punchline, needle) ||
                Contains(x.Description, needle) ||
                Contains(x.OmegaWebsiteDescription, needle) ||
                Contains(x.OmegaWebsiteReadmeExcerpt, needle) ||
                Contains(x.Author, needle) ||
                x.Tags.Any(tag => Contains(tag, needle)) ||
                x.EffectiveCategories.Any(category => Contains(category, needle)));
        }

        if (selectedAuthors.Count > 0)
        {
            var requiredAuthors = selectedAuthors.ToArray();
            query = query.Where(x => requiredAuthors.All(required =>
                x.EffectiveAuthors.Any(value => value.Equals(required, StringComparison.OrdinalIgnoreCase))));
        }


        if (selectedCategory != "All categories")
            query = query.Where(x => x.EffectiveCategories.Contains(selectedCategory, StringComparer.OrdinalIgnoreCase));

        if (selectedTags.Count > 0)
        {
            var tagIndex = catalog.GetTagIndex(currentApi, selectedSource);
            var requiredTags = selectedTags.ToArray();
            query = query.Where(x => tagIndex.MatchesAll(x.InternalName, requiredTags));
        }

        if (selectedApi != 0)
        {
            query = query.Where(x => catalog.GetVariants(x.InternalName).Any(v =>
                v.DalamudApiLevel == selectedApi ||
                v.TestingDalamudApiLevel == selectedApi ||
                (v.OmegaMinimumApiLevel.HasValue &&
                 v.OmegaMaximumApiLevel.HasValue &&
                 v.OmegaMinimumApiLevel.Value <= selectedApi &&
                 v.OmegaMaximumApiLevel.Value >= selectedApi)));
        }

        return sort switch
        {
            MarketplaceSort.LastUpdated => query.OrderByDescending(x => x.LastUpdate).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase),
            MarketplaceSort.Downloads => query.OrderByDescending(x => x.DownloadCount).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase),
            MarketplaceSort.HighestApi => query.OrderByDescending(x => x.HighestKnownApiLevel).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase),
            MarketplaceSort.Version => query.OrderByDescending(x => x.AssemblyVersion).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase),
            _ => query.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase),
        };
    }

    private IEnumerable<MarketplacePlugin> ApplyLibraryRuntimeFilter(
        IEnumerable<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed)
        => libraryRuntimeFilter switch
        {
            LibraryRuntimeFilter.Loaded => plugins.Where(x =>
                installed.TryGetValue(x.InternalName, out var installedPlugin) && installedPlugin.IsLoaded),
            LibraryRuntimeFilter.NotLoaded => plugins.Where(x =>
                installed.TryGetValue(x.InternalName, out var installedPlugin) && !installedPlugin.IsLoaded),
            _ => plugins,
        };

    private IEnumerable<MarketplacePlugin> ApplyStatusFilter(
        IEnumerable<MarketplacePlugin> plugins,
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
        => statusFilter switch
        {
            MarketplaceStatusFilter.Installed => plugins.Where(x => installed.ContainsKey(x.InternalName)),
            MarketplaceStatusFilter.Installable => plugins.Where(x =>
                !installed.ContainsKey(x.InternalName) &&
                HasInstallableVariant(x.InternalName, currentApi, currentDalamudVersion)),
            MarketplaceStatusFilter.OutdatedApi => plugins.Where(x =>
            {
                var highest = HighestKnownApiFor(x.InternalName, currentApi);
                return highest > 0 && highest < currentApi;
            }),
            _ => plugins,
        };

    private bool HasAvailableUpdate(
        string internalName,
        IExposedPlugin installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
        => GetAvailableUpdateVersion(internalName, installedPlugin, currentApi, currentDalamudVersion) is not null;

    private Version? GetAvailableUpdateVersion(
        string internalName,
        IExposedPlugin installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        var candidate = GetAvailableUpdateCandidate(internalName, installedPlugin, currentApi, currentDalamudVersion);
        if (candidate is null ||
            !candidate.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out var useTesting))
        {
            return null;
        }

        return useTesting
            ? candidate.TestingAssemblyVersion ?? candidate.AssemblyVersion
            : candidate.AssemblyVersion;
    }

    private MarketplacePlugin? GetAvailableUpdateCandidate(
        string internalName,
        IExposedPlugin installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        var installedVersion = installedPlugin.Version;
        if (installedVersion is null)
            return null;

        var candidates = GetInstallCandidates(internalName, currentApi, currentDalamudVersion);
        if (candidates.Count == 0)
            return null;

        var installedLastUpdate = ResolveInstalledLastUpdate(internalName, installedPlugin, installedVersion);
        var valid = candidates
            .Select(candidate =>
            {
                var compatible = candidate.HasCurrentApiBuild(
                    currentApi,
                    configuration.PreferTestingBuilds,
                    out var useTesting);
                var offered = useTesting
                    ? candidate.TestingAssemblyVersion ?? candidate.AssemblyVersion
                    : candidate.AssemblyVersion;
                var isUpdate = compatible && PluginUpdateRules.IsUpdateCandidate(
                    installedVersion,
                    installedPlugin.Manifest.InstalledFromUrl,
                    installedLastUpdate,
                    candidate,
                    useTesting);
                return new { Candidate = candidate, Offered = offered, IsUpdate = isUpdate };
            })
            .Where(x => x.IsUpdate)
            .ToArray();
        if (valid.Length == 0)
            return null;

        // Prefer an update from the currently installed publishing lineage. If that lineage stopped
        // publishing, permit a newer package from another known repository as a migration candidate.
        // Cross-repository version numbers alone are never enough: PluginUpdateRules also requires
        // manifest chronology, and the UI asks the user before moving repositories.
        var sameSource = valid
            .Where(x => PluginUpdateRules.IsSamePublishingSource(
                installedPlugin.Manifest.InstalledFromUrl,
                x.Candidate.SourceUrl,
                x.Candidate.SourceIsOfficial))
            .OrderByDescending(x => x.Offered)
            .FirstOrDefault();
        if (sameSource is not null)
            return sameSource.Candidate;

        return valid
            .OrderByDescending(x => PluginUpdateRules.NormalizeUnix(x.Candidate.LastUpdate))
            .ThenByDescending(x => x.Offered)
            .Select(x => x.Candidate)
            .FirstOrDefault();
    }

    private static bool IsRepositoryMigration(IExposedPlugin installedPlugin, MarketplacePlugin updateCandidate)
        => !PluginUpdateRules.IsSamePublishingSource(
            installedPlugin.Manifest.InstalledFromUrl,
            updateCandidate.SourceUrl,
            updateCandidate.SourceIsOfficial);

    private long ResolveInstalledLastUpdate(string internalName, IExposedPlugin installedPlugin, Version installedVersion)
    {
        var manifestDate = PluginUpdateRules.NormalizeUnix(installedPlugin.Manifest.LastUpdate);
        if (manifestDate > 0)
            return manifestDate;

        var installedSource = installedPlugin.Manifest.InstalledFromUrl;
        return catalog.GetPresentationVariants(internalName)
            .Where(variant =>
                variant.AssemblyVersion.Equals(installedVersion) &&
                PluginUpdateRules.IsSamePublishingSource(installedSource, variant.SourceUrl, variant.SourceIsOfficial))
            .Select(variant => PluginUpdateRules.NormalizeUnix(variant.LastUpdate))
            .DefaultIfEmpty(0)
            .Max();
    }

    /// <summary>
    /// Returns whether the marketplace knows any compatible package variant. Repository registration
    /// is deliberately not part of this decision; install-time source preparation is hidden behind
    /// the install coordinator.
    /// </summary>
    private bool HasInstallableVariant(string internalName, int currentApi, Version currentDalamudVersion)
        => GetInstallCandidates(internalName, currentApi, currentDalamudVersion).Count > 0;

    private IReadOnlyList<MarketplacePlugin> GetInstallCandidates(
        string internalName,
        int currentApi,
        Version currentDalamudVersion)
    {
        var statuses = catalog.GetRepositoryStatuses(currentApi)
            .ToDictionary(x => NormalizeUrl(x.SourceUrl), StringComparer.OrdinalIgnoreCase);
        var divergentSources = catalog.Variants
            .Where(v => v.SecurityFindings.Any(f =>
                f.RuleId.Equals("artifact.cross-source-hash-mismatch", StringComparison.OrdinalIgnoreCase)))
            .Select(v => NormalizeUrl(v.SourceUrl))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return catalog.GetMainVariants(internalName, currentApi)
            .Where(v =>
                v.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out _) &&
                (v.MinimumDalamudVersion is null || v.MinimumDalamudVersion <= currentDalamudVersion) &&
                IsInstallSourceSelectable(v))
            // Never auto-prefer a package that Sigmascope already identified as the divergent
            // same-version artifact. A repository with known divergence elsewhere is also demoted
            // behind clean alternatives, but remains available for explicit reviewed selection.
            .OrderBy(v => IsPluginPackageArtifactDivergent(v) ? 1 : 0)
            .ThenBy(v => divergentSources.Contains(NormalizeUrl(v.SourceUrl)) ? 1 : 0)
            .ThenByDescending(v => v.AssemblyVersion)
            .ThenBy(v => RepositoryProviderRules.SortPriority(
                v.SourceName,
                v.SourceUrl,
                v.SourceIsOfficial,
                statuses.TryGetValue(NormalizeUrl(v.SourceUrl), out var status) ? status.PluginCount : 0))
            .ThenBy(v => v.SourceName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool IsPluginPackageArtifactDivergent(MarketplacePlugin plugin)
        => plugin.SecurityFindings.Any(finding =>
            finding.RuleId.Equals("artifact.cross-source-hash-mismatch", StringComparison.OrdinalIgnoreCase));

    private MarketplacePlugin ResolveProductBaselineVariant(
        MarketplacePlugin plugin,
        int currentApi,
        Version currentDalamudVersion)
        => GetInstallCandidates(plugin.InternalName, currentApi, currentDalamudVersion).FirstOrDefault()
           ?? ResolveDefaultVariant(plugin);

    private static bool IsInstallSourceSelectable(MarketplacePlugin plugin)
    {
        if (plugin.SourceIsOfficial)
            return true;
        return Uri.TryCreate(plugin.SourceUrl, UriKind.Absolute, out var sourceUri) &&
               sourceUri.Scheme == Uri.UriSchemeHttps;
    }

    private string DescribeInstallUnavailability(
        string internalName,
        int currentApi,
        Version currentDalamudVersion)
    {
        var variants = catalog.GetMainVariants(internalName, currentApi);
        if (variants.Count == 0)
            return "Omega Definitions do not currently contain an install package for this plugin.";

        var currentBuilds = variants
            .Where(v => v.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out _))
            .ToArray();
        if (currentBuilds.Length > 0)
        {
            var minimum = currentBuilds
                .Where(v => v.MinimumDalamudVersion is not null && v.MinimumDalamudVersion > currentDalamudVersion)
                .Select(v => v.MinimumDalamudVersion!)
                .OrderBy(v => v)
                .FirstOrDefault();
            if (minimum is not null)
                return $"A downloadable API {currentApi} package exists, but it requires Dalamud {minimum}+ (current {currentDalamudVersion}).";

            if (currentBuilds.All(v => !IsInstallSourceSelectable(v)))
                return $"A downloadable API {currentApi} package exists, but its repository URL is missing or is not HTTPS.";
        }

        var testingOnly = variants.Any(v =>
            v.TestingDalamudApiLevel == currentApi &&
            v.TestingAssemblyVersion is not null &&
            !string.IsNullOrWhiteSpace(v.DownloadLinkTesting));
        if (!configuration.PreferTestingBuilds && testingOnly)
            return $"Only a testing API {currentApi} package is advertised. Enable testing builds in Filters to make it installable.";

        var apiMetadata = variants.Any(v =>
            v.DalamudApiLevel == currentApi ||
            v.TestingDalamudApiLevel == currentApi ||
            (v.OmegaMinimumApiLevel is not null && v.OmegaMaximumApiLevel is not null &&
             currentApi >= v.OmegaMinimumApiLevel && currentApi <= v.OmegaMaximumApiLevel));
        if (apiMetadata)
            return $"The plugin is marked compatible with API {currentApi}, but no downloadable package for that API is currently advertised by its known repositories.";

        var highest = variants.Select(v => v.HighestKnownApiLevel).DefaultIfEmpty(0).Max();
        return highest switch
        {
            0 => "The repository does not advertise an API level for an installable package.",
            var api when api < currentApi => $"The newest known package targets API {api}; Omega currently needs API {currentApi}.",
            var api when api > currentApi => $"The available package targets newer API {api}; Omega currently needs API {currentApi}.",
            _ => $"No downloadable API {currentApi} package is currently advertised by the known repositories.",
        };
    }

    private void OpenInstallChooser(MarketplacePlugin plugin)
    {
        pendingInstall = plugin;
        // Product presentation may currently be showing a repository variant that is not the
        // safest install candidate. The chooser owns source selection and starts from its ranked
        // clean candidate instead of inheriting the displayed variant implicitly.
        pendingInstallSourceUrl = string.Empty;
        installPopupOpen = true;
        requestInstallPopup = true;
    }

    private int HighestKnownApiFor(string internalName, int currentApi)
        => catalog.GetMainVariants(internalName, currentApi).Select(x => x.HighestKnownApiLevel).DefaultIfEmpty(0).Max();

    private void DrawPluginDetailsPanel(
        IReadOnlyDictionary<string, IExposedPlugin> installed,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (!detailsOpen || selectedPlugin is null)
            return;

        var plugin = ResolveSelectedVariant(selectedPlugin);
        selectedPlugin = plugin;
        installed.TryGetValue(plugin.InternalName, out var installedPlugin);

        if (!DrawDetailsHeading(plugin, installedPlugin, currentApi, currentDalamudVersion))
            return;

        plugin = DrawDetailsVariantSelector(plugin, currentApi);
        DrawDetailsDescription(plugin, currentApi, currentDalamudVersion);
        DrawDetailsPrimaryAction(plugin, installedPlugin, currentApi, currentDalamudVersion);
        DrawDetailsLinks(plugin);
    }

    private bool DrawDetailsHeading(
        MarketplacePlugin plugin,
        IExposedPlugin? installedPlugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        if (DrawPillButton("Back", "details-back", Ui(70f, 30f), false))
        {
            detailsOpen = false;
            selectedPlugin = null;
            return false;
        }

        ImGui.SameLine();
        ImGui.TextDisabled("Plugin information");
        ImGui.Spacing();
        var detailWidth = ImGui.GetContentRegionAvail().X;
        DrawPluginArtwork(
            plugin,
            installedPlugin,
            Math.Min(Ui(150f), Math.Max(Ui(112f), detailWidth - Ui(40f))),
            detailWidth,
            currentApi,
            currentDalamudVersion,
            showOverlays: false);
        CenterText(plugin.Name);
        CenterText(string.IsNullOrWhiteSpace(plugin.Author) ? "Unknown author" : plugin.Author, disabled: true);
        ImGui.Spacing();
        return true;
    }

    private MarketplacePlugin DrawDetailsVariantSelector(MarketplacePlugin plugin, int currentApi)
    {
        var variants = catalog.GetVariants(plugin.InternalName);
        if (variants.Count <= 1)
            return plugin;

        ImGui.TextDisabled($"Available from {variants.Count} sources");
        ImGui.Spacing();
        var rowStart = ImGui.GetCursorPosX();
        var used = 0f;
        var available = ImGui.GetContentRegionAvail().X;
        foreach (var variant in variants)
            plugin = DrawDetailsVariantButton(plugin, variant, currentApi, available, rowStart, ref used);
        ImGui.NewLine();
        return plugin;
    }

    private MarketplacePlugin DrawDetailsVariantButton(
        MarketplacePlugin current,
        MarketplacePlugin variant,
        int currentApi,
        float available,
        float rowStart,
        ref float used)
    {
        var apiText = $"API {(variant.HighestKnownApiLevel > 0 ? variant.HighestKnownApiLevel.ToString() : "?")}";
        var label = $"{variant.SourceName}  •  {apiText}";
        var provider = GetRepositoryProvider(variant.SourceName, variant.SourceUrl, variant.SourceIsOfficial, currentApi);
        var width = Math.Min(available, Math.Max(Ui(120f), ImGui.CalcTextSize(label).X + Ui(28f) + (!string.IsNullOrWhiteSpace(provider.IconUrl) ? Ui(23f) : 0f)));
        if (used > 0f && used + width > available)
        {
            ImGui.NewLine();
            ImGui.SetCursorPosX(rowStart);
            used = 0f;
        }
        else if (used > 0f)
        {
            ImGui.SameLine(0f, 7f);
            used += 7f;
        }

        var active = NormalizeUrl(variant.SourceUrl).Equals(NormalizeUrl(current.SourceUrl), StringComparison.OrdinalIgnoreCase);
        if (DrawRepositoryActionButton(
                variant.SourceName,
                variant.SourceUrl,
                variant.SourceIsOfficial,
                currentApi,
                apiText,
                $"variant-{current.InternalName}-{StableId(variant.SourceUrl)}",
                new Vector2(width, Ui(30f)),
                active))
        {
            selectedVariantSource[current.InternalName] = variant.SourceUrl;
            selectedPlugin = variant;
            current = variant;
            operationMessage = $"Showing {current.Name} metadata from {current.SourceName}.";
        }
        used += width;
        return current;
    }

    private void DrawDetailsDescription(
        MarketplacePlugin plugin,
        int currentApi,
        Version currentDalamudVersion)
    {
        ImGui.Separator();
        if (!string.IsNullOrWhiteSpace(plugin.Punchline))
            ImGui.TextWrapped(plugin.Punchline);
        if (!string.IsNullOrWhiteSpace(plugin.Description))
        {
            ImGui.Spacing();
            ImGui.TextWrapped(plugin.Description);
        }

        ImGui.Spacing();
        ImGui.Text($"Version: {plugin.AssemblyVersionText}");
        var stableApi = catalog.GetStableApiLevel(plugin.InternalName, currentApi);
        ImGui.Text($"Stable API: {(stableApi > 0 ? stableApi.ToString() : "?")}");
        ImGui.Text($"Highest known API: {plugin.HighestKnownApiLevel}");
        if (plugin.TestingDalamudApiLevel is not null || plugin.TestingAssemblyVersion is not null)
            ImGui.TextDisabled($"Testing: {plugin.TestingAssemblyVersionText ?? "?"} / API {plugin.TestingDalamudApiLevel?.ToString() ?? "?"}");
        ImGui.TextWrapped($"Compatibility: {plugin.GetCompatibilityText(currentApi, currentDalamudVersion, configuration.PreferTestingBuilds)}");
        if (plugin.IsUnmaintained(currentApi))
            ImGui.TextColored(new Vector4(0.95f, 0.48f, 0.18f, 1f), $"Unmaintained: highest advertised API is {plugin.HighestKnownApiLevel} ({currentApi - plugin.HighestKnownApiLevel} API levels behind)");
        ImGui.TextDisabled("Source");
        ImGui.SameLine(0f, 8f);
        DrawRepositoryName(plugin.SourceName, plugin.SourceUrl, plugin.SourceIsOfficial, currentApi);
        if (plugin.Tags.Count > 0)
            ImGui.TextWrapped("Tags: " + string.Join(", ", plugin.Tags));
        if (plugin.EffectiveCategories.Count > 0)
            ImGui.TextWrapped("Categories: " + string.Join(", ", plugin.EffectiveCategories));

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();
    }

    private void DrawDetailsLinks(MarketplacePlugin plugin)
    {
        ImGui.Spacing();
        var projectUrl = ResolveProjectUrl(plugin);
        if (string.IsNullOrWhiteSpace(projectUrl) ||
            !DrawPillButton("Project", $"open-project-{plugin.InternalName}", Ui(92f, 30f), false))
            return;

        try
        {
            Process.Start(new ProcessStartInfo(projectUrl) { UseShellExecute = true });
            operationMessage = $"Opened {plugin.Name} project page in your browser.";
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega could not open project URL for {Plugin}", plugin.InternalName);
            operationMessage = $"Could not open the project page for {plugin.Name}.";
        }
    }

    private static string ResolveProjectUrl(MarketplacePlugin plugin)
    {
        foreach (var candidate in new[] { plugin.RepoUrl, plugin.OmegaWebsiteUrl })
        {
            if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri) &&
                (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                 uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)))
            {
                return uri.ToString();
            }
        }

        return string.Empty;
    }

    /// <summary>
    /// Shows one user-facing install action. Source registration/preparation is deliberately
    /// deferred to the repository chooser and install coordinator.
    /// </summary>
}
