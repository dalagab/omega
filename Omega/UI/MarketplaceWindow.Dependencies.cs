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
        if (!plugin.HasCompletedSecurityScan || plugin.SecurityDependencyTotalCount <= 0 || plugin.SecurityDependencies.Count == 0)
            return;

        DrawProductSectionHeading(
            "Dependencies",
            "Required components, plugin links, packages and optional integrations");

        ImGui.Indent(14f);
        DrawDependencyGroup("Required", plugin.SecurityDependencies.Where(IsRequiredDependency).ToArray(), installed);
        DrawDependencyGroup(
            "Optional / integrations",
            plugin.SecurityDependencies.Where(x => !IsRequiredDependency(x) && IsOptionalDependency(x)).ToArray(),
            installed);
        DrawDependencyGroup(
            "Bundled / observed",
            plugin.SecurityDependencies.Where(x => !IsRequiredDependency(x) && !IsOptionalDependency(x)).ToArray(),
            installed);

        if (plugin.SecurityDependencyTotalCount > plugin.SecurityDependencies.Count)
        {
            ImGui.Spacing();
            ImGui.TextDisabled(
                $"Showing {plugin.SecurityDependencies.Count} of {plugin.SecurityDependencyTotalCount} dependency components. " +
                "Definitions keeps this summary bounded; detailed evidence remains server-side.");
        }

        ImGui.Unindent(14f);
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

        ImGui.TableSetColumnIndex(3);
        ImGui.TextWrapped(DependencyVersionText(dependency));

        ImGui.TableSetColumnIndex(4);
        var status = DependencyStatusText(dependency, availableInOmega, targetInstalled);
        if (dependency.HasWarning)
            ImGui.TextColored(DependencyWarningColor(dependency.WarningSeverity), status);
        else if (targetInstalled || dependency.IsFramework)
            ImGui.TextColored(new Vector4(0.26f, 0.76f, 0.48f, 1f), status);
        else
            ImGui.TextDisabled(status);
    }

    private static bool IsRequiredDependency(MarketplaceDependency dependency)
        => dependency.IsFramework || dependency.Requirement.Equals("required", StringComparison.OrdinalIgnoreCase) ||
           dependency.Type.Equals("hard", StringComparison.OrdinalIgnoreCase);

    private static bool IsOptionalDependency(MarketplaceDependency dependency)
        => dependency.Requirement is "soft" or "optional" || dependency.Type is "soft" or "optional" or "ipc";

    private static string DependencyMarker(MarketplaceDependency dependency, bool availableInOmega, bool installed)
    {
        if (dependency.HasWarning)
            return "!";
        if (dependency.IsFramework || installed)
            return "✓";
        if (availableInOmega)
            return "↓";
        return dependency.Requirement.Equals("required", StringComparison.OrdinalIgnoreCase) ? "!" : "•";
    }

    private static Vector4 DependencyMarkerColor(MarketplaceDependency dependency, bool availableInOmega, bool installed)
    {
        if (dependency.HasWarning)
            return DependencyWarningColor(dependency.WarningSeverity);
        if (dependency.IsFramework || installed)
            return new Vector4(0.26f, 0.76f, 0.48f, 1f);
        if (availableInOmega)
            return new Vector4(0.16f, 0.72f, 0.75f, 1f);
        if (dependency.Requirement.Equals("required", StringComparison.OrdinalIgnoreCase))
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
        => (dependency.Type ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "framework" => "Framework",
            "hard" => "Plugin · required",
            "soft" => "Plugin · soft",
            "optional" => "Plugin · optional",
            "plugin" => "Plugin",
            "ipc" => "IPC integration",
            "package" => "Package",
            "bundled-assembly" => "Bundled assembly",
            "assembly" => "Assembly",
            "native" => "Native library",
            "project" => "Project reference",
            "bundled" => "Bundled component",
            var value when !string.IsNullOrWhiteSpace(value) => value,
            _ => "Component",
        };

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
        if (dependency.IsFramework)
            parts.Add("Provided by framework");
        else if (installed)
            parts.Add("Installed");
        else if (availableInOmega)
            parts.Add("Available in Omega");
        else if (dependency.Requirement.Equals("required", StringComparison.OrdinalIgnoreCase) && dependency.IsPluginDependency)
            parts.Add("Required plugin not in Definitions");
        else if (dependency.Type.Equals("ipc", StringComparison.OrdinalIgnoreCase))
            parts.Add("Integration observed");
        else if (dependency.Requirement.Equals("bundled", StringComparison.OrdinalIgnoreCase) || dependency.Type.Equals("bundled-assembly", StringComparison.OrdinalIgnoreCase))
            parts.Add("Bundled");
        else
            parts.Add("Observed");

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
