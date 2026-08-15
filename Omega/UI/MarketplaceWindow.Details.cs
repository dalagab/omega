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

        if (!string.IsNullOrWhiteSpace(search))
        {
            var needle = search.Trim();
            query = query.Where(x =>
                Contains(x.Name, needle) ||
                Contains(x.InternalName, needle) ||
                Contains(x.Punchline, needle) ||
                Contains(x.Description, needle) ||
                Contains(x.Author, needle) ||
                x.Tags.Any(tag => Contains(tag, needle)) ||
                x.EffectiveCategories.Any(category => Contains(category, needle)));
        }

        if (!string.IsNullOrWhiteSpace(author))
            query = query.Where(x => Contains(x.Author, author.Trim()));


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
        var installedVersion = installedPlugin.Version;
        if (installedVersion is null)
            return null;

        Version? best = null;
        foreach (var variant in catalog.GetMainVariants(internalName, currentApi))
        {
            if (!IsSourceEnabledInOmega(variant) ||
                (variant.MinimumDalamudVersion is not null && variant.MinimumDalamudVersion > currentDalamudVersion) ||
                !variant.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out var useTesting))
            {
                continue;
            }

            var offered = useTesting
                ? variant.TestingAssemblyVersion ?? variant.AssemblyVersion
                : variant.AssemblyVersion;
            if (offered.CompareTo(installedVersion) <= 0)
                continue;
            if (best is null || offered.CompareTo(best) > 0)
                best = offered;
        }

        return best;
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
        return catalog.GetMainVariants(internalName, currentApi)
            .Where(v =>
                v.HasCurrentApiBuild(currentApi, configuration.PreferTestingBuilds, out _) &&
                (v.MinimumDalamudVersion is null || v.MinimumDalamudVersion <= currentDalamudVersion) &&
                IsSourceEnabledInOmega(v))
            .OrderBy(v => RepositoryProviderRules.SortPriority(
                v.SourceName,
                v.SourceUrl,
                v.SourceIsOfficial,
                statuses.TryGetValue(NormalizeUrl(v.SourceUrl), out var status) ? status.PluginCount : 0))
            .ThenByDescending(v => v.AssemblyVersion)
            .ThenBy(v => v.SourceName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private bool IsSourceEnabledInOmega(MarketplacePlugin plugin)
    {
        if (plugin.SourceIsOfficial)
            return true;
        var source = FindConfiguredSource(plugin.SourceUrl);
        return source?.Enabled == true;
    }

    private void OpenInstallChooser(MarketplacePlugin plugin)
    {
        pendingInstall = plugin;
        pendingInstallSourceUrl = plugin.SourceUrl;
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
        if (DrawPillButton("Back", "details-back", new Vector2(70f, 30f), false))
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
            Math.Min(150f, Math.Max(112f, detailWidth - 40f)),
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
        var width = Math.Min(available, Math.Max(120f, ImGui.CalcTextSize(label).X + 28f + (!string.IsNullOrWhiteSpace(provider.IconUrl) ? 23f : 0f)));
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
                new Vector2(width, 30f),
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
            !DrawPillButton("Project", $"open-project-{plugin.InternalName}", new Vector2(92f, 30f), false))
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
