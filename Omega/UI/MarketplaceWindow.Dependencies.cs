using System.Numerics;
using Dalamud.Bindings.ImGui;
using Dalamud.Plugin;

namespace Dalagab.Omega;

internal sealed partial class MarketplaceWindow
{
    private void DrawProductDependencies(
        MarketplacePlugin plugin,
        IReadOnlyDictionary<string, IExposedPlugin> installed)
    {
        DrawProductSectionHeading("Dependencies");
        ImGui.Indent(14f);

        var packageEdges = ReadNormalizedPackageDependencies(plugin);
        var required = packageEdges
            .Where(x => x.Relationship == PluginDependencyRelationship.Required)
            .ToArray();
        var recommended = packageEdges
            .Where(x => x.Relationship == PluginDependencyRelationship.Recommended)
            .ToArray();
        var optional = packageEdges
            .Where(x => x.Relationship == PluginDependencyRelationship.Optional)
            .ToArray();
        var observed = packageEdges
            .Where(x => x.Relationship == PluginDependencyRelationship.Observed)
            .ToArray();

        if (packageEdges.Count > 0)
        {
            DrawPackageDependencyGroup("Required plugins", required, installed);
            DrawPackageDependencyGroup("Recommended plugins", recommended, installed);
            DrawPackageDependencyGroup("Optional plugins", optional, installed);
            DrawPackageDependencyGroup("Observed package relationships", observed, installed);
        }
        else
        {
            DrawPackageDependencyEmptyState(plugin);
        }

        DrawReverseDependencies(plugin);
        DrawSecurityIntegrationDependencies(plugin, installed);
        DrawSecurityPackageObservations(plugin, installed);

        ImGui.Unindent(14f);
    }

    private IReadOnlyList<PluginDependencyEdge> ReadNormalizedPackageDependencies(MarketplacePlugin plugin)
    {
        if (plugin.CatalogVariantId > 0)
            return catalog.GetDependenciesForVariant(plugin.CatalogVariantId);

        // Official/live Dalamud overlays can intentionally own runtime package metadata while their
        // matching database row still owns catalog identity. Recover that exact database variant
        // before falling back to plugin-level authority.
        var databaseVariant = catalog.GetPresentationVariants(plugin.InternalName)
            .Where(x => x.CatalogVariantId > 0)
            .OrderByDescending(x =>
                NormalizeUrl(x.SourceUrl).Equals(NormalizeUrl(plugin.SourceUrl), StringComparison.OrdinalIgnoreCase) &&
                x.AssemblyVersionText.Equals(plugin.AssemblyVersionText, StringComparison.OrdinalIgnoreCase))
            .ThenByDescending(x => x.AssemblyVersionText.Equals(plugin.AssemblyVersionText, StringComparison.OrdinalIgnoreCase))
            .FirstOrDefault();
        if (databaseVariant is not null &&
            databaseVariant.AssemblyVersionText.Equals(plugin.AssemblyVersionText, StringComparison.OrdinalIgnoreCase))
        {
            return catalog.GetDependenciesForVariant(databaseVariant.CatalogVariantId);
        }

        // Legacy/live overlays may carry only stable plugin identity. Use the plugin-level graph as
        // a conservative presentation fallback and keep entries matching the selected version when
        // the catalog provides that information.
        var pluginId = plugin.CatalogPluginId > 0
            ? plugin.CatalogPluginId
            : databaseVariant?.CatalogPluginId ?? 0;
        if (pluginId <= 0)
            return [];

        var edges = catalog.GetDependenciesForPlugin(pluginId);
        var exact = edges
            .Where(x => string.IsNullOrWhiteSpace(x.ConsumerVersion) ||
                        x.ConsumerVersion.Equals(plugin.AssemblyVersionText, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        return exact.Length > 0 ? exact : edges;
    }

    private void DrawPackageDependencyEmptyState(MarketplacePlugin plugin)
    {
        if (!string.IsNullOrWhiteSpace(catalog.DependencyGraphRevision))
        {
            ImGui.TextDisabled("No normalized package dependencies.");
            return;
        }

        var observedPackageHints = plugin.SecurityDependencies
            .Where(x => IsSecurityPluginRelationship(plugin, x) && !IsIpcDependency(x))
            .ToArray();
        if (observedPackageHints.Length == 0)
        {
            ImGui.TextDisabled("Package dependency data is not available in this Definitions revision.");
            return;
        }

        ImGui.TextDisabled("Package dependency authority is not available in this Definitions revision.");
        ImGui.TextDisabled("The relationships below come from security observations only and are not used for automatic installation.");
        DrawSecurityObservationGroup("Observed plugin relationships", observedPackageHints, installed: null);
    }

    private void DrawPackageDependencyGroup(
        string title,
        IReadOnlyList<PluginDependencyEdge> dependencies,
        IReadOnlyDictionary<string, IExposedPlugin> installed)
    {
        if (dependencies.Count == 0)
            return;

        ImGui.Spacing();
        ImGui.TextUnformatted(title);
        ImGui.Spacing();
        ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, Ui(8f, 6f));
        if (ImGui.BeginTable(
                $"package-dependencies-{StableId(title)}",
                6,
                ImGuiTableFlags.SizingStretchProp | ImGuiTableFlags.BordersInnerH | ImGuiTableFlags.RowBg))
        {
            ImGui.TableSetupColumn("", ImGuiTableColumnFlags.WidthFixed, Ui(24f));
            ImGui.TableSetupColumn("Plugin", ImGuiTableColumnFlags.WidthStretch, 2.4f);
            ImGui.TableSetupColumn("Relationship", ImGuiTableColumnFlags.WidthStretch, 1.2f);
            ImGui.TableSetupColumn("Version", ImGuiTableColumnFlags.WidthStretch, 1.5f);
            ImGui.TableSetupColumn("Status", ImGuiTableColumnFlags.WidthStretch, 1.8f);
            ImGui.TableSetupColumn("Action", ImGuiTableColumnFlags.WidthFixed, Ui(82f));

            foreach (var dependency in dependencies)
                DrawPackageDependencyRow(dependency, installed);

            ImGui.EndTable();
        }
        ImGui.PopStyleVar();
    }

    private void DrawPackageDependencyRow(
        PluginDependencyEdge dependency,
        IReadOnlyDictionary<string, IExposedPlugin> installed)
    {
        var targetVariants = catalog.GetVariants(dependency.ProviderInternalName).ToArray();
        var availableInOmega = targetVariants.Length > 0;
        var targetInstalled = installed.TryGetValue(dependency.ProviderInternalName, out var installedPlugin);
        var status = PackageDependencyStatus(dependency, availableInOmega, targetInstalled, installedPlugin);
        var marker = targetInstalled ? "✓" :
            dependency.Relationship == PluginDependencyRelationship.Required
                ? availableInOmega && dependency.InstallEligible ? "↓" : "!"
                : availableInOmega ? "•" : "—";
        var markerColor = targetInstalled
            ? new Vector4(0.26f, 0.76f, 0.48f, 1f)
            : dependency.Relationship == PluginDependencyRelationship.Required && !dependency.InstallEligible
                ? new Vector4(0.92f, 0.30f, 0.24f, 1f)
                : availableInOmega
                    ? new Vector4(0.16f, 0.72f, 0.75f, 1f)
                    : new Vector4(0.62f, 0.64f, 0.68f, 1f);

        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        ImGui.TextColored(markerColor, marker);
        if (ImGui.IsItemHovered())
            SetReadableTooltip(PackageDependencyTooltip(dependency));

        ImGui.TableSetColumnIndex(1);
        var displayName = targetVariants.FirstOrDefault()?.Name;
        if (string.IsNullOrWhiteSpace(displayName))
            displayName = dependency.ProviderInternalName;
        if (availableInOmega)
        {
            ImGui.TextColored(new Vector4(0.16f, 0.72f, 0.75f, 1f), displayName);
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip($"Open {displayName} in Omega");
            if (ImGui.IsItemClicked())
                OpenPluginDetails(targetVariants[0]);
        }
        else
        {
            ImGui.TextWrapped(displayName);
        }

        ImGui.TableSetColumnIndex(2);
        ImGui.TextDisabled(PackageRelationshipLabel(dependency.Relationship));

        ImGui.TableSetColumnIndex(3);
        ImGui.TextWrapped(PackageDependencyVersionText(dependency));

        ImGui.TableSetColumnIndex(4);
        if (targetInstalled)
            ImGui.TextColored(new Vector4(0.26f, 0.76f, 0.48f, 1f), status);
        else if (dependency.Relationship == PluginDependencyRelationship.Required && !dependency.InstallEligible)
            ImGui.TextColored(new Vector4(0.92f, 0.30f, 0.24f, 1f), status);
        else
            ImGui.TextDisabled(status);

        ImGui.TableSetColumnIndex(5);
        if (!availableInOmega)
        {
            ImGui.TextDisabled("—");
            return;
        }

        var target = ResolveDefaultVariant(targetVariants[0]);
        var mayInstall = !targetInstalled &&
                         dependency.Relationship == PluginDependencyRelationship.Required &&
                         dependency.InstallEligible;
        var label = mayInstall ? "Install…" : "Open";
        if (ImGui.SmallButton($"{label}##package-dependency-{StableId(dependency.ProviderInternalName)}-{dependency.ConsumerVariantId}"))
        {
            // OMEGA-1 deliberately keeps this a normal single-plugin action. Recursive closure and
            // transaction execution arrive in the resolver/transaction passes; no mutation occurs
            // merely because the normalized graph is displayed.
            if (mayInstall)
                OpenInstallChooser(target);
            else
                OpenPluginDetails(target);
        }
    }

    private void DrawReverseDependencies(MarketplacePlugin plugin)
    {
        PluginDependencyProvider? provider = plugin.CatalogPluginId > 0
            ? catalog.GetDependencyProvider(plugin.CatalogPluginId)
            : catalog.GetDependencyProvider(plugin.InternalName);
        if (provider is null || provider.TotalDependentPlugins <= 0)
            return;

        var dependents = plugin.CatalogPluginId > 0
            ? catalog.GetDependentsForProvider(plugin.CatalogPluginId)
            : catalog.GetDependentsForProvider(plugin.InternalName);
        var requiredBy = dependents
            .Where(x => x.Relationship == PluginDependencyRelationship.Required)
            .GroupBy(x => x.ConsumerPluginId > 0 ? $"id:{x.ConsumerPluginId}" : $"name:{x.ConsumerInternalName}", StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .OrderBy(x => x.ConsumerInternalName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        ImGui.Spacing();
        ImGui.TextUnformatted("Dependency provider");
        ImGui.SameLine(0f, Ui(10f));
        ImGui.TextDisabled(
            $"Required by {provider.RequiredByCount} · Recommended by {provider.RecommendedByCount} · Optional for {provider.OptionalByCount}");

        if (requiredBy.Length == 0)
            return;

        ImGui.Spacing();
        ImGui.TextUnformatted("Required by");
        ImGui.Spacing();
        ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, Ui(8f, 6f));
        if (ImGui.BeginTable(
                $"package-required-by-{StableId(plugin.InternalName)}",
                4,
                ImGuiTableFlags.SizingStretchProp | ImGuiTableFlags.BordersInnerH | ImGuiTableFlags.RowBg))
        {
            ImGui.TableSetupColumn("Plugin", ImGuiTableColumnFlags.WidthStretch, 2.6f);
            ImGui.TableSetupColumn("Consumer version", ImGuiTableColumnFlags.WidthStretch, 1.2f);
            ImGui.TableSetupColumn("Requirement", ImGuiTableColumnFlags.WidthStretch, 1.5f);
            ImGui.TableSetupColumn("Action", ImGuiTableColumnFlags.WidthFixed, Ui(70f));

            foreach (var dependency in requiredBy)
                DrawReverseDependencyRow(dependency);

            ImGui.EndTable();
        }
        ImGui.PopStyleVar();
    }

    private void DrawReverseDependencyRow(PluginDependencyEdge dependency)
    {
        var consumerVariants = catalog.GetVariants(dependency.ConsumerInternalName).ToArray();
        var displayName = consumerVariants.FirstOrDefault()?.Name;
        if (string.IsNullOrWhiteSpace(displayName))
            displayName = dependency.ConsumerInternalName;

        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        if (consumerVariants.Length > 0)
        {
            ImGui.TextColored(new Vector4(0.16f, 0.72f, 0.75f, 1f), displayName);
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip($"Open {displayName} in Omega");
            if (ImGui.IsItemClicked())
                OpenPluginDetails(consumerVariants[0]);
        }
        else
        {
            ImGui.TextWrapped(displayName);
        }

        ImGui.TableSetColumnIndex(1);
        ImGui.TextDisabled(string.IsNullOrWhiteSpace(dependency.ConsumerVersion) ? "—" : dependency.ConsumerVersion);

        ImGui.TableSetColumnIndex(2);
        ImGui.TextWrapped(string.IsNullOrWhiteSpace(dependency.VersionConstraint)
            ? "Required"
            : dependency.VersionConstraint);

        ImGui.TableSetColumnIndex(3);
        if (consumerVariants.Length == 0)
        {
            ImGui.TextDisabled("—");
            return;
        }
        if (ImGui.SmallButton($"Open##required-by-{StableId(dependency.ConsumerInternalName)}-{dependency.ConsumerVariantId}"))
            OpenPluginDetails(consumerVariants[0]);
    }

    private void DrawSecurityIntegrationDependencies(
        MarketplacePlugin plugin,
        IReadOnlyDictionary<string, IExposedPlugin> installed)
    {
        var integrations = plugin.SecurityDependencies
            .Where(x => IsSecurityPluginRelationship(plugin, x) && IsIpcDependency(x))
            .ToArray();
        if (integrations.Length == 0)
            return;

        ImGui.Spacing();
        ImGui.TextUnformatted("Integrations");
        ImGui.TextDisabled("IPC relationships are security/integration observations, not package-install dependencies.");
        DrawSecurityObservationGroup("IPC integrations", integrations, installed);
    }

    private void DrawSecurityPackageObservations(
        MarketplacePlugin plugin,
        IReadOnlyDictionary<string, IExposedPlugin> installed)
    {
        // Preserve useful advisory/warning evidence without allowing the bounded security JSON to
        // become package authority. When the normalized graph is absent, DrawPackageDependencyEmptyState
        // already presents the broader observation fallback.
        if (string.IsNullOrWhiteSpace(catalog.DependencyGraphRevision))
            return;

        var observations = plugin.SecurityDependencies
            .Where(x => IsSecurityPluginRelationship(plugin, x) && !IsIpcDependency(x))
            .Where(x => x.HasWarning)
            .ToArray();
        if (observations.Length == 0)
            return;

        ImGui.Spacing();
        ImGui.TextUnformatted("Security observations");
        ImGui.TextDisabled("These findings annotate observed dependencies; install authority comes from the normalized package graph above.");
        DrawSecurityObservationGroup("Dependency security observations", observations, installed);
    }

    private void DrawSecurityObservationGroup(
        string title,
        IReadOnlyList<MarketplaceDependency> dependencies,
        IReadOnlyDictionary<string, IExposedPlugin>? installed)
    {
        if (dependencies.Count == 0)
            return;

        ImGui.Spacing();
        ImGui.TextUnformatted(title);
        ImGui.Spacing();
        ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, Ui(8f, 6f));
        if (ImGui.BeginTable(
                $"security-observed-dependencies-{StableId(title)}",
                5,
                ImGuiTableFlags.SizingStretchProp | ImGuiTableFlags.BordersInnerH | ImGuiTableFlags.RowBg))
        {
            ImGui.TableSetupColumn("", ImGuiTableColumnFlags.WidthFixed, Ui(24f));
            ImGui.TableSetupColumn("Integration", ImGuiTableColumnFlags.WidthStretch, 2.4f);
            ImGui.TableSetupColumn("Type", ImGuiTableColumnFlags.WidthStretch, 1.3f);
            ImGui.TableSetupColumn("Status", ImGuiTableColumnFlags.WidthStretch, 2f);
            ImGui.TableSetupColumn("Action", ImGuiTableColumnFlags.WidthFixed, Ui(70f));

            foreach (var dependency in dependencies)
                DrawSecurityObservationRow(dependency, installed);

            ImGui.EndTable();
        }
        ImGui.PopStyleVar();
    }

    private void DrawSecurityObservationRow(
        MarketplaceDependency dependency,
        IReadOnlyDictionary<string, IExposedPlugin>? installed)
    {
        var targetVariants = string.IsNullOrWhiteSpace(dependency.TargetInternalName)
            ? Array.Empty<MarketplacePlugin>()
            : catalog.GetVariants(dependency.TargetInternalName).ToArray();
        var available = targetVariants.Length > 0;
        var isInstalled = installed is not null &&
                          !string.IsNullOrWhiteSpace(dependency.TargetInternalName) &&
                          installed.ContainsKey(dependency.TargetInternalName);
        var displayName = available
            ? targetVariants[0].Name
            : !string.IsNullOrWhiteSpace(dependency.TargetInternalName)
                ? dependency.TargetInternalName
                : dependency.Name;

        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        ImGui.TextColored(
            isInstalled ? new Vector4(0.26f, 0.76f, 0.48f, 1f) : new Vector4(0.62f, 0.64f, 0.68f, 1f),
            isInstalled ? "✓" : "•");

        ImGui.TableSetColumnIndex(1);
        if (available)
        {
            ImGui.TextColored(new Vector4(0.16f, 0.72f, 0.75f, 1f), displayName);
            if (ImGui.IsItemClicked())
                OpenPluginDetails(targetVariants[0]);
        }
        else
        {
            ImGui.TextWrapped(displayName);
        }

        ImGui.TableSetColumnIndex(2);
        ImGui.TextDisabled(IsIpcDependency(dependency)
            ? $"IPC · {IpcRelationship(dependency)}"
            : "Observed plugin link");

        ImGui.TableSetColumnIndex(3);
        var ipc = IsIpcDependency(dependency);
        var status = ipc
            ? isInstalled
                ? "Integration provider installed"
                : !string.IsNullOrWhiteSpace(dependency.TargetInternalName)
                    ? "Integration provider not installed"
                    : dependency.ResolutionStatus.Equals("ambiguous-ipc-provider", StringComparison.OrdinalIgnoreCase)
                        ? "Multiple integration providers observed"
                        : "Integration provider not identified"
            : dependency.HasWarning
                ? $"{dependency.WarningCount} warning{(dependency.WarningCount == 1 ? string.Empty : "s")} · {dependency.AdvisoryCount} advisor{(dependency.AdvisoryCount == 1 ? "y" : "ies")}"
                : "Observed by SigmaScope";
        if (!ipc && dependency.HasWarning)
            ImGui.TextColored(DependencyObservationWarningColor(dependency.WarningSeverity), status);
        else
            ImGui.TextDisabled(status);
        if (ImGui.IsItemHovered() && !string.IsNullOrWhiteSpace(dependency.RelationshipReason))
        {
            var confidence = string.IsNullOrWhiteSpace(dependency.RelationshipConfidence)
                ? "unknown"
                : dependency.RelationshipConfidence;
            SetReadableTooltip($"{confidence} confidence\n{dependency.RelationshipReason}");
        }

        ImGui.TableSetColumnIndex(4);
        if (!available)
        {
            ImGui.TextDisabled("—");
            return;
        }
        if (ImGui.SmallButton($"Open##integration-{StableId(dependency.TargetInternalName)}-{StableId(dependency.Name)}"))
            OpenPluginDetails(targetVariants[0]);
    }

    private static bool IsSecurityPluginRelationship(MarketplacePlugin plugin, MarketplaceDependency dependency)
    {
        if (dependency.IsFramework)
            return false;

        var type = (dependency.Type ?? string.Empty).Trim().ToLowerInvariant();
        var kind = (dependency.Kind ?? string.Empty).Trim().ToLowerInvariant();
        var isIpc = type == "ipc" || kind == "ipc";
        var isPlugin = type is "hard" or "soft" or "optional" or "plugin" ||
                       kind == "external-plugin" ||
                       !string.IsNullOrWhiteSpace(dependency.TargetInternalName);
        if (!isIpc && !isPlugin)
            return false;

        if (!string.IsNullOrWhiteSpace(dependency.TargetInternalName) &&
            dependency.TargetInternalName.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase))
            return false;
        if (string.IsNullOrWhiteSpace(dependency.TargetInternalName) &&
            dependency.Name.Equals(plugin.InternalName, StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }

    private static bool IsIpcDependency(MarketplaceDependency dependency)
        => dependency.Type.Equals("ipc", StringComparison.OrdinalIgnoreCase) ||
           dependency.Kind.Equals("ipc", StringComparison.OrdinalIgnoreCase);

    private static string IpcRelationship(MarketplaceDependency dependency)
    {
        var relationship = (dependency.Relationship ?? string.Empty).Trim().ToLowerInvariant();
        return relationship is "required" or "feature" or "optional" or "unknown"
            ? relationship
            : "unknown";
    }

    private static Vector4 DependencyObservationWarningColor(string severity)
        => (severity ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "critical" or "high" => new Vector4(0.92f, 0.30f, 0.24f, 1f),
            "medium" or "caution" => new Vector4(0.94f, 0.56f, 0.16f, 1f),
            _ => new Vector4(0.92f, 0.78f, 0.22f, 1f),
        };

    private static string PackageRelationshipLabel(PluginDependencyRelationship relationship)
        => relationship switch
        {
            PluginDependencyRelationship.Required => "Required",
            PluginDependencyRelationship.Recommended => "Recommended",
            PluginDependencyRelationship.Optional => "Optional",
            _ => "Observed",
        };

    private static string PackageDependencyVersionText(PluginDependencyEdge dependency)
    {
        if (!string.IsNullOrWhiteSpace(dependency.VersionConstraint) &&
            !string.IsNullOrWhiteSpace(dependency.ResolvedVersion))
            return $"{dependency.ResolvedVersion} · {dependency.VersionConstraint}";
        if (!string.IsNullOrWhiteSpace(dependency.VersionConstraint))
            return dependency.VersionConstraint;
        if (!string.IsNullOrWhiteSpace(dependency.ResolvedVersion))
            return dependency.ResolvedVersion;
        return "—";
    }

    private static string PackageDependencyStatus(
        PluginDependencyEdge dependency,
        bool availableInOmega,
        bool installed,
        IExposedPlugin? installedPlugin)
    {
        if (installed)
        {
            var version = installedPlugin?.Version?.ToString();
            return string.IsNullOrWhiteSpace(version) ? "Already installed" : $"Already installed · {version}";
        }

        if (!dependency.InstallEligible)
        {
            if (dependency.VersionStatus.Equals("incompatible", StringComparison.OrdinalIgnoreCase))
                return "Version constraint unresolved";
            if (!string.IsNullOrWhiteSpace(dependency.ResolutionStatus))
                return $"Not installable · {dependency.ResolutionStatus}";
            return "Not installable from current graph";
        }

        if (availableInOmega)
            return dependency.Relationship == PluginDependencyRelationship.Required
                ? "Available in Omega · required"
                : "Available in Omega";

        return dependency.Relationship == PluginDependencyRelationship.Required
            ? "Required provider not in Definitions"
            : "Provider not in Definitions";
    }

    private static string PackageDependencyTooltip(PluginDependencyEdge dependency)
    {
        var parts = new List<string>
        {
            $"Catalog package relationship: {PackageRelationshipLabel(dependency.Relationship)}",
        };
        if (!string.IsNullOrWhiteSpace(dependency.VersionConstraint))
            parts.Add($"Constraint: {dependency.VersionConstraint}");
        if (!string.IsNullOrWhiteSpace(dependency.ResolvedVersion))
            parts.Add($"Resolved: {dependency.ResolvedVersion}");
        if (!string.IsNullOrWhiteSpace(dependency.ResolutionStatus))
            parts.Add($"Resolution: {dependency.ResolutionStatus}");
        if (!string.IsNullOrWhiteSpace(dependency.VersionStatus))
            parts.Add($"Version status: {dependency.VersionStatus}");
        if (!string.IsNullOrWhiteSpace(dependency.Confidence))
            parts.Add($"Confidence: {dependency.Confidence}");
        if (dependency.Origins.Count > 0)
            parts.Add($"Observed from: {string.Join(", ", dependency.Origins)}");
        parts.Add(dependency.InstallEligible
            ? "This normalized edge may participate in package resolution."
            : "This edge is informational for package resolution.");
        return string.Join("\n", parts);
    }
}
