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

        var dependencies = plugin.SecurityDependencies
            .Where(x => IsDisplayablePluginDependency(plugin, x))
            .ToArray();
        if (dependencies.Length == 0)
        {
            DrawDependencyEmptyState(plugin);
            ImGui.Unindent(14f);
            return;
        }

        var required = dependencies.Where(IsRequiredDependency).ToArray();
        var feature = dependencies.Where(x => !IsRequiredDependency(x) && IsFeatureDependency(x)).ToArray();
        var optional = dependencies.Where(x => !IsRequiredDependency(x) && !IsFeatureDependency(x) && IsOptionalDependency(x)).ToArray();
        var linked = dependencies.Where(x => !IsRequiredDependency(x) && !IsFeatureDependency(x) && !IsOptionalDependency(x)).ToArray();

        DrawDependencyGroup("Required plugins / providers", required, installed);
        DrawDependencyGroup("Feature integrations", feature, installed);
        DrawDependencyGroup("Optional integrations", optional, installed);
        DrawDependencyGroup("Plugin links / unknown IPC", linked, installed);

        ImGui.Unindent(14f);
    }

    private static void DrawDependencyEmptyState(MarketplacePlugin plugin)
    {
        if (plugin.HasCompletedSecurityScan)
        {
            ImGui.TextDisabled("No external plugin or IPC dependencies were detected for this package.");
            return;
        }

        if (string.IsNullOrWhiteSpace(plugin.SecurityStatus))
        {
            ImGui.TextDisabled("Dependency information is not present in the current Definitions snapshot for this package.");
            return;
        }

        var status = plugin.SecurityStatus.Trim();
        ImGui.TextDisabled($"Dependency analysis is {status} for this package. Published dependency data will appear here when available.");
        if (!string.IsNullOrWhiteSpace(plugin.SecurityError) && ImGui.IsItemHovered())
            ImGui.SetTooltip(plugin.SecurityError);
    }

    private void DrawDependencyGroup(
        string title,
        IReadOnlyList<MarketplaceDependency> dependencies,
        IReadOnlyDictionary<string, IExposedPlugin> installed)
    {
        if (dependencies.Count == 0)
            return;

        ImGui.Spacing();
        ImGui.TextUnformatted(title);
        ImGui.Spacing();
        ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(8f, 6f));
        if (ImGui.BeginTable(
                $"product-dependencies-{StableId(title)}",
                5,
                ImGuiTableFlags.SizingStretchProp | ImGuiTableFlags.BordersInnerH | ImGuiTableFlags.RowBg))
        {
            ImGui.TableSetupColumn("", ImGuiTableColumnFlags.WidthFixed, 24f);
            ImGui.TableSetupColumn("Dependency", ImGuiTableColumnFlags.WidthStretch, 2.3f);
            ImGui.TableSetupColumn("Type", ImGuiTableColumnFlags.WidthStretch, 1.1f);
            ImGui.TableSetupColumn("Version", ImGuiTableColumnFlags.WidthStretch, 1.25f);
            ImGui.TableSetupColumn("Status", ImGuiTableColumnFlags.WidthStretch, 1.7f);

            foreach (var dependency in dependencies)
                DrawDependencyRow(dependency, installed);

            ImGui.EndTable();
        }
        ImGui.PopStyleVar();
    }

    private void DrawDependencyRow(
        MarketplaceDependency dependency,
        IReadOnlyDictionary<string, IExposedPlugin> installed)
    {
        var targetVariants = string.IsNullOrWhiteSpace(dependency.TargetInternalName)
            ? Array.Empty<MarketplacePlugin>()
            : catalog.GetVariants(dependency.TargetInternalName).ToArray();
        var availableInOmega = targetVariants.Length > 0;
        var targetInstalled = availableInOmega && installed.ContainsKey(dependency.TargetInternalName);
        var marker = DependencyMarker(dependency, availableInOmega, targetInstalled);
        var markerColor = DependencyMarkerColor(dependency, availableInOmega, targetInstalled);

        ImGui.TableNextRow();
        ImGui.TableSetColumnIndex(0);
        ImGui.TextColored(markerColor, marker);
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(DependencyStatusText(dependency, availableInOmega, targetInstalled));

        ImGui.TableSetColumnIndex(1);
        if (availableInOmega)
        {
            ImGui.TextColored(new Vector4(0.16f, 0.72f, 0.75f, 1f), dependency.Name);
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip($"Open {targetVariants[0].Name} in Omega");
            if (ImGui.IsItemClicked())
                OpenPluginDetails(targetVariants[0]);
        }
        else
        {
            ImGui.TextWrapped(dependency.Name);
        }

        ImGui.TableSetColumnIndex(2);
        ImGui.TextDisabled(DependencyTypeLabel(dependency));
        if (ImGui.IsItemHovered() && IsIpcDependency(dependency) && !string.IsNullOrWhiteSpace(dependency.RelationshipReason))
        {
            var confidence = string.IsNullOrWhiteSpace(dependency.RelationshipConfidence) ? "unknown" : dependency.RelationshipConfidence;
            ImGui.SetTooltip($"Static IPC relationship inference: {IpcRelationship(dependency)} ({confidence} confidence)\n{dependency.RelationshipReason}");
        }

        ImGui.TableSetColumnIndex(3);
        ImGui.TextWrapped(DependencyVersionText(dependency));

        ImGui.TableSetColumnIndex(4);
        var status = DependencyStatusText(dependency, availableInOmega, targetInstalled);
        if (dependency.HasWarning)
            ImGui.TextColored(DependencyWarningColor(dependency.WarningSeverity), status);
        else if (IsHighConfidenceRequiredProvider(dependency) && !targetInstalled)
            ImGui.TextColored(new Vector4(0.92f, 0.30f, 0.24f, 1f), status);
        else if (targetInstalled)
            ImGui.TextColored(new Vector4(0.26f, 0.76f, 0.48f, 1f), status);
        else
            ImGui.TextDisabled(status);
    }

    private static bool IsDisplayablePluginDependency(MarketplacePlugin plugin, MarketplaceDependency dependency)
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
        return relationship is "required" or "feature" or "optional" or "unknown" ? relationship : "unknown";
    }

    private static bool HasHighRelationshipConfidence(MarketplaceDependency dependency)
        => dependency.RelationshipConfidence.Equals("High", StringComparison.OrdinalIgnoreCase) ||
           dependency.RelationshipConfidence.Equals("VeryHigh", StringComparison.OrdinalIgnoreCase);

    private static bool IsHighConfidenceRequiredProvider(MarketplaceDependency dependency)
        => IsIpcDependency(dependency) && IpcRelationship(dependency) == "required" && HasHighRelationshipConfidence(dependency);

    private static bool IsRequiredDependency(MarketplaceDependency dependency)
        => (IsIpcDependency(dependency) && IpcRelationship(dependency) == "required") ||
           dependency.Requirement.Equals("required", StringComparison.OrdinalIgnoreCase) ||
           dependency.Type.Equals("hard", StringComparison.OrdinalIgnoreCase);

    private static bool IsFeatureDependency(MarketplaceDependency dependency)
        => IsIpcDependency(dependency) && IpcRelationship(dependency) == "feature";

    private static bool IsOptionalDependency(MarketplaceDependency dependency)
        => (IsIpcDependency(dependency) && IpcRelationship(dependency) == "optional") ||
           (!IsIpcDependency(dependency) && (dependency.Requirement is "soft" or "optional" || dependency.Type is "soft" or "optional"));

    private static string DependencyMarker(MarketplaceDependency dependency, bool availableInOmega, bool installed)
    {
        if (dependency.HasWarning || (IsHighConfidenceRequiredProvider(dependency) && !installed))
            return "!";
        if (installed)
            return "✓";
        if (availableInOmega)
            return "↓";
        return IsRequiredDependency(dependency) ? "!" : "•";
    }

    private static Vector4 DependencyMarkerColor(MarketplaceDependency dependency, bool availableInOmega, bool installed)
    {
        if (dependency.HasWarning)
            return DependencyWarningColor(dependency.WarningSeverity);
        if (IsHighConfidenceRequiredProvider(dependency) && !installed)
            return new Vector4(0.92f, 0.30f, 0.24f, 1f);
        if (installed)
            return new Vector4(0.26f, 0.76f, 0.48f, 1f);
        if (availableInOmega)
            return new Vector4(0.16f, 0.72f, 0.75f, 1f);
        if (IsRequiredDependency(dependency))
            return new Vector4(0.88f, 0.28f, 0.24f, 1f);
        return new Vector4(0.62f, 0.64f, 0.68f, 1f);
    }

    private static Vector4 DependencyWarningColor(string severity)
        => (severity ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "critical" or "high" => new Vector4(0.92f, 0.30f, 0.24f, 1f),
            "medium" or "caution" => new Vector4(0.94f, 0.56f, 0.16f, 1f),
            _ => new Vector4(0.92f, 0.78f, 0.22f, 1f),
        };

    private static string DependencyTypeLabel(MarketplaceDependency dependency)
    {
        if (IsIpcDependency(dependency))
            return $"IPC · {IpcRelationship(dependency)}";

        return (dependency.Type ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "hard" => "Plugin · required",
            "soft" => "Plugin · soft",
            "optional" => "Plugin · optional",
            "plugin" => "Plugin",
            var value when !string.IsNullOrWhiteSpace(value) => value,
            _ => "Component",
        };
    }

    private static string DependencyVersionText(MarketplaceDependency dependency)
    {
        var observed = !string.IsNullOrWhiteSpace(dependency.TargetVersion)
            ? dependency.TargetVersion
            : !string.IsNullOrWhiteSpace(dependency.ResolvedVersion)
                ? dependency.ResolvedVersion
                : dependency.Version;
        var requirement = dependency.VersionRequirement;
        if (!string.IsNullOrWhiteSpace(requirement) && !string.IsNullOrWhiteSpace(observed) &&
            !requirement.Equals(observed, StringComparison.OrdinalIgnoreCase))
            return $"{observed} · requires {requirement}";
        if (!string.IsNullOrWhiteSpace(requirement))
            return $"requires {requirement}";
        return string.IsNullOrWhiteSpace(observed) ? "—" : observed;
    }

    private static string DependencyStatusText(MarketplaceDependency dependency, bool availableInOmega, bool installed)
    {
        var parts = new List<string>();
        var isIpc = IsIpcDependency(dependency);
        var relationship = isIpc ? IpcRelationship(dependency) : string.Empty;
        if (isIpc && !string.IsNullOrWhiteSpace(dependency.TargetInternalName))
        {
            parts.Add($"Provided by {dependency.TargetInternalName}");
            if (relationship == "required" && HasHighRelationshipConfidence(dependency) && !installed)
                parts.Add(availableInOmega ? "Required provider not installed; available in Omega" : "Required provider not installed");
            else
                parts.Add(installed ? "Installed" : availableInOmega ? "Available in Omega" : "Provider resolved");
        }
        else if (installed)
            parts.Add("Installed");
        else if (availableInOmega)
            parts.Add("Available in Omega");
        else if (dependency.Requirement.Equals("required", StringComparison.OrdinalIgnoreCase) && dependency.IsPluginDependency)
            parts.Add("Required plugin not in Definitions");
        else if (isIpc)
        {
            if (relationship == "required" && HasHighRelationshipConfidence(dependency))
                parts.Add(dependency.ResolutionStatus.Equals("ambiguous-ipc-provider", StringComparison.OrdinalIgnoreCase)
                    ? "Required IPC provider is ambiguous"
                    : "Required IPC provider not yet identified");
            else
                parts.Add(dependency.ResolutionStatus.Equals("ambiguous-ipc-provider", StringComparison.OrdinalIgnoreCase)
                    ? "Multiple IPC providers observed"
                    : "IPC provider not yet identified");
        }
        else
            parts.Add("Plugin relationship observed");

        if (isIpc && !string.IsNullOrWhiteSpace(dependency.RelationshipConfidence))
            parts.Add($"{relationship} · {dependency.RelationshipConfidence} confidence");

        if (dependency.WarningCount > 0)
            parts.Add($"{dependency.WarningCount} warning{(dependency.WarningCount == 1 ? "" : "s")}");
        if (dependency.AdvisoryCount > 0)
            parts.Add($"{dependency.AdvisoryCount} advisor{(dependency.AdvisoryCount == 1 ? "y" : "ies")}");
        if (!string.IsNullOrWhiteSpace(dependency.VersionStatus) &&
            dependency.VersionStatus.Equals("incompatible", StringComparison.OrdinalIgnoreCase))
            parts.Add("version mismatch");
        return string.Join(" · ", parts);
    }
}
